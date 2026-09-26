"""
LiveSOC Linux Agent — Authentication Log Collector

Tails /var/log/auth.log (or /var/log/secure) and parses
authentication events: SSH failures, SSH successes, sudo, etc.

Handles file rotation by tracking inode + offset.
Sends normalized events to POST /api/ingest.
"""

import os
import re
import time
import threading
import json
from pathlib import Path


class AuthLogCollector:
    """Tails auth log files and sends parsed events."""

    def __init__(self, client, config: dict, state_manager):
        self.client = client
        self.config = config
        self.state = state_manager
        self.agent_id = config["agent"]["agent_id"]
        self.collector_config = config["collectors"].get("auth_log", {})
        self.enabled = self.collector_config.get("enabled", True)
        self.paths = self.collector_config.get("paths", ["/var/log/auth.log", "/var/log/secure"])
        self.log_file = None
        self._thread = None
        self._running = False
        self._stop_event = threading.Event()
        self.session_id = None

    def set_session_id(self, session_id: str):
        self.session_id = session_id

    def start(self):
        if not self.enabled:
            _log("INFO", "Auth log collector disabled")
            return

        self.log_file = self._find_readable_log()
        if not self.log_file:
            _log("WARNING", "No readable auth log found")
            return

        _log("INFO", f"Auth log collector started: {self.log_file}")
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
                _log("ERROR", f"Auth log collector error: {e}")
            self._stop_event.wait(1)

    def _tail_and_parse(self):
        """Tail the log file, handling rotation via inode tracking."""
        if not self.log_file or not os.path.isfile(self.log_file):
            time.sleep(5)
            return

        # Get current inode + size
        try:
            stat = os.stat(self.log_file)
        except OSError:
            return

        current_inode = stat.st_ino
        current_size = stat.st_size

        # Load saved state
        state_key = f"auth_log:{self.log_file}"
        saved = self.state.get(state_key, {})
        saved_inode = saved.get("inode")
        saved_offset = saved.get("offset", 0)

        # Detect rotation: if inode changed or file shrank, start from beginning
        if saved_inode is not None and saved_inode != current_inode:
            _log("INFO", f"Log rotation detected (inode {saved_inode} → {current_inode})")
            offset = 0
        elif current_size < saved_offset:
            _log("INFO", f"Log truncation detected (size {current_size} < offset {saved_offset})")
            offset = 0
        else:
            offset = saved_offset

        # Read new content
        if offset >= current_size:
            return  # nothing new

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

        # Save state
        self.state.set(state_key, {"inode": current_inode, "offset": new_offset})

    def _process_line(self, line: str):
        """Parse a single auth log line and send matching events."""
        event = self._parse_auth_line(line)
        if event:
            if self.session_id:
                result = self.client.send_event(event, self.session_id)
                if result and result.get("ok"):
                    _log("DEBUG", f"Sent: {event['eventType']} ({result.get('eventId', '?')})")
                else:
                    _log("WARNING", f"Failed to send event: {event['eventType']}")
            else:
                _log("DEBUG", f"No session — dropping: {event['eventType']}")

    def _parse_auth_line(self, line: str) -> dict:
        """Parse an auth log line into an ingestion payload."""
        # SSH failed password: "Jan  1 10:42:15 host sshd[123]: Failed password for 'root' from 192.168.1.50 port 49152 ssh2"
        m = re.search(
            r"Failed password for (?:invalid user )?'?(\S+)'? from (\d+\.\d+\.\d+\.\d+) port (\d+)",
            line,
        )
        if m:
            return self._make_event(
                line, "authentication_failure", "failure",
                username=m.group(1), source_ip=m.group(2), source_port=int(m.group(3)),
                dest_port=22, severity="high",
                message=f"SSH authentication failure for '{m.group(1)}' from {m.group(2)}",
            )

        # SSH accepted password: "Jan  1 10:42:15 host sshd[123]: Accepted password for 'root' from 192.168.1.50 port 49152 ssh2"
        m = re.search(
            r"Accepted (?:password|publickey) for '?(\S+)'? from (\d+\.\d+\.\d+\.\d+) port (\d+)",
            line,
        )
        if m:
            return self._make_event(
                line, "authentication_success", "success",
                username=m.group(1), source_ip=m.group(2), source_port=int(m.group(3)),
                dest_port=22, severity="info",
                message=f"SSH authentication success for '{m.group(1)}' from {m.group(2)}",
            )

        # SSH invalid user: "Jan  1 10:42:15 host sshd[123]: Invalid user admin from 192.168.1.50 port 49152"
        m = re.search(
            r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)",
            line,
        )
        if m:
            return self._make_event(
                line, "invalid_user", "failure",
                username=m.group(1), source_ip=m.group(2), source_port=int(m.group(3)),
                dest_port=22, severity="high",
                message=f"Invalid SSH user '{m.group(1)}' from {m.group(2)}",
            )

        # sudo: COMMAND=...
        m = re.search(r"sudo.*?:\s+(\S+)\s*:\s*TTY=.*?;\s*PWD=.*?;\s*USER=.*?;\s*COMMAND=(.*)", line)
        if m:
            return self._make_event(
                line, "sudo_activity", "success",
                username=m.group(1), severity="info",
                message=f"sudo command by {m.group(1)}: {m.group(2)[:100]}",
            )

        # User login (login session opened)
        if "session opened for user" in line:
            m = re.search(r"user\s+(\S+)", line)
            username = m.group(1) if m else "unknown"
            return self._make_event(
                line, "user_login", "success",
                username=username, severity="info",
                message=f"Login session opened for user '{username}'",
            )

        # User logout (session closed)
        if "session closed for user" in line:
            m = re.search(r"user\s+(\S+)", line)
            username = m.group(1) if m else "unknown"
            return self._make_event(
                line, "user_logout", "info",
                username=username, severity="info",
                message=f"Login session closed for user '{username}'",
            )

        # Authentication failure (generic PAM)
        if "authentication failure" in line.lower() or "FAILED" in line:
            return self._make_event(
                line, "authentication_failure", "failure",
                severity="medium",
                message=f"Authentication failure: {line[:120]}",
            )

        return None  # no match

    def _make_event(
        self,
        raw_line: str,
        event_type: str,
        action: str,
        username: str = None,
        source_ip: str = None,
        source_port: int = None,
        dest_port: int = None,
        severity: str = "info",
        message: str = "",
    ) -> dict:
        """Build an ingestion payload."""
        import socket
        return {
            "agentId": self.agent_id,
            "hostname": socket.gethostname(),
            "os": "Linux",
            "sourceType": "linux_auth",
            "eventCategory": "authentication",
            "timestamp": _iso_now(),
            "username": username,
            "sourceIp": source_ip,
            "sourcePort": source_port,
            "destinationIp": None,
            "destinationPort": dest_port,
            "protocol": "TCP" if dest_port else None,
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
