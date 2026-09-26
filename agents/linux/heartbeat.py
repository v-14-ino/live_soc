"""
LiveSOC Linux Agent — Heartbeat Sender

Periodically sends agent status to POST /api/agents/heartbeat.
"""

import socket
import time
import threading
import platform


class HeartbeatSender:
    """Sends periodic heartbeats to LiveSOC."""

    def __init__(self, client, config: dict):
        self.client = client
        self.interval = config["heartbeat"].get("interval_sec", 30)
        self.agent_id = config["agent"]["agent_id"]
        self.agent_name = config["agent"].get("name", "Linux Agent")
        self.version = config["agent"].get("version", "1.0.0")
        self._thread = None
        self._running = False
        self._stop_event = threading.Event()

    def start(self):
        """Start the heartbeat sender in a background thread."""
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        _log("INFO", f"Heartbeat sender started (interval={self.interval}s)")

    def stop(self):
        """Stop the heartbeat sender."""
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self):
        while self._running:
            try:
                self._send_once()
            except Exception as e:
                _log("WARNING", f"Heartbeat failed: {e}")
            self._stop_event.wait(self.interval)

    def _send_once(self):
        """Send a single heartbeat."""
        hostname = socket.gethostname()
        try:
            ip = socket.gethostbyname(hostname)
        except Exception:
            ip = None

        payload = {
            "agentId": self.agent_id,
            "hostname": hostname,
            "os": platform.platform(),
            "version": self.version,
            "ip": ip,
            "status": "ONLINE",
            "timestamp": _iso_now(),
        }

        result = self.client.send_heartbeat(payload)
        if result and result.get("ok"):
            _log("DEBUG", f"Heartbeat sent: {hostname} ONLINE")
        else:
            _log("WARNING", "Heartbeat send failed")


def _iso_now() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _log(level: str, msg: str):
    import datetime
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)
