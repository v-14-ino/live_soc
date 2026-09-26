"""
LiveSOC Linux Agent — Syslog Collector

Tails /var/log/syslog (or /var/log/messages) and sends
notable system events to POST /api/ingest.
"""

import os
import re
import time
import threading
import socket


class SyslogCollector:
    """Tails syslog and sends parsed events."""

    def __init__(self, client, config: dict, state_manager):
        self.client = client
        self.config = config
        self.state = state_manager
        self.agent_id = config["agent"]["agent_id"]
        self.collector_config = config["collectors"].get("syslog", {})
        self.enabled = self.collector_config.get("enabled", True)
        self.paths = self.collector_config.get("paths", ["/var/log/syslog", "/var/log/messages"])
        self.log_file = None
        self._thread = None
        self._running = False
        self._stop_event = threading.Event()
        self.session_id = None

    def set_session_id(self, session_id: str):
        self.session_id = session_id

    def start(self):
        if not self.enabled:
            _log("INFO", "Syslog collector disabled")
            return

        self.log_file = self._find_readable_log()
        if not self.log_file:
            _log("WARNING", "No readable syslog found")
            return

        _log("INFO", f"Syslog collector started: {self.log_file}")
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _find_readable_log(self) -> str:
        for path in self.paths:
            if os.path.isfile(path) and os.access(path, os.R_OK):
                return path
        return None

    def _loop(self):
        while self._running:
            try:
                self._tail_and_parse()
            except Exception as e:
                _log("ERROR", f"Syslog collector error: {e}")
            self._stop_event.wait(1)

    def _tail_and_parse(self):
        if not self.log_file or not os.path.isfile(self.log_file):
            time.sleep(5)
            return

        try:
            stat = os.stat(self.log_file)
        except OSError:
            return

        current_inode = stat.st_ino
        current_size = stat.st_size

        state_key = f"syslog:{self.log_file}"
        saved = self.state.get(state_key, {})
        saved_inode = saved.get("inode")
        saved_offset = saved.get("offset", 0)

        if saved_inode is not None and saved_inode != current_inode:
            _log("INFO", f"Syslog rotation detected (inode changed)")
            offset = 0
        elif current_size < saved_offset:
            offset = 0
        else:
            offset = saved_offset

        if offset >= current_size:
            return

        try:
            with open(self.log_file, "r") as f:
                f.seek(offset)
                for line in f:
                    line = line.rstrip("\n")
                    if line:
                        self._process_line(line)
                new_offset = f.tell()
        except OSError as e:
            _log("WARNING", f"Failed to read {self.log_file}: {e}")
            return

        self.state.set(state_key, {"inode": current_inode, "offset": new_offset})

    def _process_line(self, line: str):
        event = self._parse_syslog_line(line)
        if event and self.session_id:
            result = self.client.send_event(event, self.session_id)
            if result and result.get("ok"):
                _log("DEBUG", f"Sent syslog: {event['eventType']}")
            else:
                _log("WARNING", f"Failed to send syslog event: {event['eventType']}")

    def _parse_syslog_line(self, line: str) -> dict:
        """Parse notable syslog lines into events."""
        # Only send notable events, not every syslog line
        lower = line.lower()

        # Service errors
        if "error" in lower or "failed" in lower:
            return self._make_event(
                line, "system_error", "error",
                severity="medium",
                message=f"System error: {line[:150]}",
            )

        # Service started
        if "started" in lower and "service" in lower:
            return self._make_event(
                line, "service_started", "info",
                severity="info",
                message=f"Service started: {line[:120]}",
            )

        # Service stopped
        if "stopped" in lower and "service" in lower:
            return self._make_event(
                line, "service_stopped", "info",
                severity="info",
                message=f"Service stopped: {line[:120]}",
            )

        return None

    def _make_event(self, raw_line: str, event_type: str, action: str, severity: str, message: str) -> dict:
        return {
            "agentId": self.agent_id,
            "hostname": socket.gethostname(),
            "os": "Linux",
            "sourceType": "syslog",
            "eventCategory": "system",
            "timestamp": _iso_now(),
            "eventType": event_type,
            "action": action,
            "severity": severity,
            "message": message,
            "rawEvent": raw_line,
            "metadata": {},
        }


def _iso_now() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _log(level: str, msg: str):
    import datetime
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)
