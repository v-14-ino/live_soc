"""
LiveSOC Linux Agent — HTTP Client

Sends events to POST /api/ingest and heartbeats to POST /api/agents/heartbeat.
Includes agent authentication via X-Agent-ID and X-Agent-Key headers.
Uses only stdlib (urllib).
"""

import json
import time
import urllib.request
import urllib.error
from typing import Optional


class LiveSOCClient:
    """HTTP client for sending telemetry + heartbeats to LiveSOC."""

    def __init__(self, config: dict):
        self.server_url = config["server"]["url"].rstrip("/")
        self.ingest_path = config["server"]["ingest_path"]
        self.heartbeat_path = config["server"]["heartbeat_path"]
        self.timeout = config["server"].get("timeout_sec", 10)
        self.retry_attempts = config["server"].get("retry_attempts", 3)
        self.retry_delay = config["server"].get("retry_delay_sec", 5)
        self.agent_id = config["agent"]["agent_id"]
        self.api_key = config["agent"]["api_key"]

    def _headers(self) -> dict:
        """Build auth headers for every request."""
        return {
            "Content-Type": "application/json",
            "X-Agent-ID": self.agent_id,
            "X-Agent-Key": self.api_key,
            "User-Agent": f"LiveSOC-Linux-Agent/1.0",
        }

    def _post(self, path: str, payload: dict, session_id: Optional[str] = None) -> Optional[dict]:
        """POST JSON to the server with retries. Returns response or None on failure."""
        url = f"{self.server_url}{path}"
        if session_id:
            payload = {**payload, "sessionId": session_id}

        body = json.dumps(payload).encode("utf-8")
        headers = self._headers()

        for attempt in range(self.retry_attempts):
            try:
                req = urllib.request.Request(url, data=body, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    resp_body = resp.read().decode("utf-8")
                    try:
                        return json.loads(resp_body)
                    except json.JSONDecodeError:
                        return {"ok": True, "raw": resp_body}
            except urllib.error.HTTPError as e:
                err_body = ""
                try:
                    err_body = e.read().decode("utf-8")[:200]
                except Exception:
                    pass
                if e.code in (401, 403):
                    # Auth failure — don't retry
                    _log("ERROR", f"Auth failed ({e.code}): {err_body}")
                    return None
                if attempt < self.retry_attempts - 1:
                    _log("WARNING", f"POST {path} failed ({e.code}), retrying in {self.retry_delay}s...")
                    time.sleep(self.retry_delay)
                else:
                    _log("ERROR", f"POST {path} failed ({e.code}): {err_body}")
                    return None
            except Exception as e:
                if attempt < self.retry_attempts - 1:
                    _log("WARNING", f"POST {path} error: {e}, retrying in {self.retry_delay}s...")
                    time.sleep(self.retry_delay)
                else:
                    _log("ERROR", f"POST {path} failed after {self.retry_attempts} attempts: {e}")
                    return None
        return None

    def send_event(self, event: dict, session_id: str) -> Optional[dict]:
        """Send a telemetry event to POST /api/ingest."""
        return self._post(self.ingest_path, event, session_id)

    def send_heartbeat(self, heartbeat: dict) -> Optional[dict]:
        """Send a heartbeat to POST /api/agents/heartbeat."""
        return self._post(self.heartbeat_path, heartbeat)


def _log(level: str, msg: str):
    import datetime
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)
