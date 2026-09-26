#!/usr/bin/env python3
"""
LiveSOC Linux Agent — Main Entry Point

Collects authentication/syslog/journald telemetry from a Linux
endpoint and sends it to the LiveSOC backend via POST /api/ingest.

Usage:
    python3 agent.py [--config agent.yml] [--session SESSION_ID]

The agent:
  1. Loads configuration
  2. Sends periodic heartbeats (ONLINE status)
  3. Tails configured log sources (auth.log, syslog, journald)
  4. Parses + normalizes events
  5. Sends events to POST /api/ingest with X-Agent-ID/X-Agent-Key auth

No external dependencies — uses only Python 3 stdlib.
"""

import sys
import os
import time
import json
import signal
import argparse
import threading

# Add parent dir to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import load_config
from client import LiveSOCClient
from heartbeat import HeartbeatSender
from collectors.auth import AuthLogCollector
from collectors.syslog import SyslogCollector
from collectors.journald import JournaldCollector


class StateManager:
    """Manages persistent state for file rotation tracking."""

    def __init__(self, state_file: str):
        self.state_file = state_file
        self._state = {}
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        try:
            with open(self.state_file, "r") as f:
                self._state = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self._state = {}

    def get(self, key: str, default=None):
        with self._lock:
            return self._state.get(key, default)

    def set(self, key: str, value):
        with self._lock:
            self._state[key] = value
            self._save()

    def _save(self):
        try:
            with open(self.state_file, "w") as f:
                json.dump(self._state, f)
        except OSError as e:
            _log("WARNING", f"Failed to save state: {e}")


class LinuxAgent:
    def __init__(self, config: dict):
        self.config = config
        self.client = LiveSOCClient(config)
        self.state = StateManager(config.get("state_file", "/tmp/livesoc-agent-state.json"))
        self.heartbeat = HeartbeatSender(self.client, config)
        self.collectors = []
        self.session_id = None
        self._running = False

    def set_session_id(self, session_id: str):
        self.session_id = session_id
        for c in self.collectors:
            c.set_session_id(session_id)
        _log("INFO", f"Session set: {session_id}")

    def start(self):
        _log("INFO", f"Starting LiveSOC Linux Agent (agent_id={self.config['agent']['agent_id']})")

        # Start heartbeat
        self.heartbeat.start()

        # Start collectors
        auth = AuthLogCollector(self.client, self.config, self.state)
        auth.set_session_id(self.session_id)
        auth.start()
        self.collectors.append(auth)

        syslog = SyslogCollector(self.client, self.config, self.state)
        syslog.set_session_id(self.session_id)
        syslog.start()
        self.collectors.append(syslog)

        journald = JournaldCollector(self.client, self.config, self.state)
        journald.set_session_id(self.session_id)
        journald.start()
        self.collectors.append(journald)

        self._running = True
        _log("INFO", "Agent started. Press Ctrl+C to stop.")

    def stop(self):
        _log("INFO", "Stopping agent...")
        self._running = False
        for c in self.collectors:
            c.stop()
        self.heartbeat.stop()
        _log("INFO", "Agent stopped.")


def main():
    parser = argparse.ArgumentParser(description="LiveSOC Linux Agent")
    parser.add_argument("--config", default=None, help="Path to agent.yml config file")
    parser.add_argument("--session", default=None, help="Monitoring session ID to ingest into")
    args = parser.parse_args()

    config = load_config(args.config)

    if not config["agent"]["api_key"] or config["agent"]["api_key"] == "CHANGE_ME_TO_YOUR_API_KEY":
        _log("ERROR", "No API key configured. Edit agent.yml and set agent.api_key.")
        sys.exit(1)

    agent = LinuxAgent(config)

    if args.session:
        agent.set_session_id(args.session)

    # Handle Ctrl+C
    def signal_handler(sig, frame):
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    agent.start()

    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()


if __name__ == "__main__":
    main()


def _log(level: str, msg: str):
    import datetime
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)
