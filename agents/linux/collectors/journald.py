"""
LiveSOC Linux Agent — Journald Collector

Uses `journalctl -f -o json` to follow journald entries.
Falls back gracefully if journalctl is not available.
"""

import subprocess
import threading
import json
import socket


class JournaldCollector:
    """Follows journald via journalctl -f -o json."""

    def __init__(self, client, config: dict, state_manager):
        self.client = client
        self.config = config
        self.agent_id = config["agent"]["agent_id"]
        self.collector_config = config["collectors"].get("journald", {})
        self.enabled = self.collector_config.get("enabled", False)
        self.units = self.collector_config.get("units", [])
        self._thread = None
        self._running = False
        self._stop_event = threading.Event()
        self._process = None
        self.session_id = None

    def set_session_id(self, session_id: str):
        self.session_id = session_id

    def start(self):
        if not self.enabled:
            _log("INFO", "Journald collector disabled")
            return

        # Check if journalctl is available
        try:
            subprocess.run(["journalctl", "--version"], capture_output=True, timeout=3)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            _log("WARNING", "journalctl not available, journald collector disabled")
            return

        _log("INFO", "Journald collector started")
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        self._stop_event.set()
        if self._process:
            try:
                self._process.terminate()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self):
        while self._running:
            try:
                self._follow_journald()
            except Exception as e:
                _log("ERROR", f"Journald collector error: {e}")
                self._stop_event.wait(10)  # wait before retry

    def _follow_journald(self):
        args = ["journalctl", "-f", "-o", "json", "--no-pager"]
        for unit in self.units:
            args.extend(["-u", unit])

        self._process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        _log("INFO", f"Following journald (PID {self._process.pid})")

        for line in self._process.stdout:
            if not self._running:
                break
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                self._process_entry(entry)
            except json.JSONDecodeError:
                continue
            except Exception as e:
                _log("WARNING", f"Failed to process journald entry: {e}")

    def _process_entry(self, entry: dict):
        """Convert a journald JSON entry to an ingestion payload."""
        message = entry.get("MESSAGE", "")
        if not message:
            return

        priority = entry.get("PRIORITY", "6")
        severity = self._priority_to_severity(priority)

        unit = entry.get("_SYSTEMD_UNIT", entry.get("SYSLOG_IDENTIFIER", "unknown"))
        event_type = "log_entry"

        # Detect auth-related
        msg_lower = message.lower()
        if "failed password" in msg_lower:
            event_type = "authentication_failure"
            severity = "high"
        elif "accepted password" in msg_lower:
            event_type = "authentication_success"
            severity = "info"
        elif "invalid user" in msg_lower:
            event_type = "invalid_user"
            severity = "high"
        elif "error" in msg_lower or "failed" in msg_lower:
            event_type = "system_error"
            severity = "medium" if severity == "info" else severity

        event = {
            "agentId": self.agent_id,
            "hostname": socket.gethostname(),
            "os": "Linux",
            "sourceType": "journald",
            "eventCategory": "authentication" if "auth" in event_type else "system",
            "timestamp": _iso_from_usec(entry.get("__REALTIME_TIMESTAMP")),
            "username": entry.get("_AUDIT_USER", None),
            "eventType": event_type,
            "action": "failure" if "failure" in event_type else "info",
            "severity": severity,
            "message": f"[{unit}] {message[:200]}",
            "rawEvent": message,
            "metadata": {
                "unit": unit,
                "priority": priority,
                "pid": entry.get("_PID"),
            },
        }

        if self.session_id:
            result = self.client.send_event(event, self.session_id)
            if result and result.get("ok"):
                _log("DEBUG", f"Sent journald: {event_type}")
        else:
            _log("DEBUG", f"No session — dropping journald: {event_type}")

    def _priority_to_severity(self, priority: str) -> str:
        try:
            p = int(priority)
        except (ValueError, TypeError):
            return "info"
        if p <= 2:
            return "critical"
        if p <= 4:
            return "high"
        if p <= 6:
            return "medium"
        return "info"


def _iso_from_usec(usec_str: str) -> str:
    """Convert journald __REALTIME_TIMESTAMP (microseconds) to ISO string."""
    import datetime
    if not usec_str:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        us = int(usec_str)
        return datetime.datetime.fromtimestamp(us / 1_000_000, tz=datetime.timezone.utc).isoformat()
    except (ValueError, TypeError):
        return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _iso_now() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _log(level: str, msg: str):
    import datetime
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)
