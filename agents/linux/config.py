"""
LiveSOC Linux Agent — Configuration Loader

Loads agent.yml (or agent.yml.example as fallback).
No external dependencies — uses only stdlib.
"""

import os
import json
from pathlib import Path

DEFAULT_CONFIG = {
    "server": {
        "url": "http://localhost:3000",
        "ingest_path": "/api/ingest",
        "heartbeat_path": "/api/agents/heartbeat",
        "timeout_sec": 10,
        "retry_attempts": 3,
        "retry_delay_sec": 5,
    },
    "agent": {
        "agent_id": "agent-linux-001",
        "api_key": "",
        "name": "Lab Linux Agent",
        "version": "1.0.0",
    },
    "heartbeat": {
        "interval_sec": 30,
    },
    "collectors": {
        "auth_log": {
            "enabled": True,
            "paths": ["/var/log/auth.log", "/var/log/secure"],
        },
        "syslog": {
            "enabled": True,
            "paths": ["/var/log/syslog", "/var/log/messages"],
        },
        "journald": {
            "enabled": False,
            "units": [],
        },
    },
    "state_file": "/tmp/livesoc-agent-state.json",
    "log_level": "INFO",
}


def load_config(config_path: str = None) -> dict:
    """Load configuration from YAML file, falling back to defaults."""
    config = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy

    # Try to find a config file
    paths_to_try = []
    if config_path:
        paths_to_try.append(config_path)
    paths_to_try.extend([
        "agent.yml",
        "config/agent.yml",
        os.path.expanduser("~/.livesoc/agent.yml"),
        "/etc/livesoc/agent.yml",
    ])

    config_file = None
    for p in paths_to_try:
        if os.path.isfile(p):
            config_file = p
            break

    if config_file:
        try:
            # Simple YAML parser (no PyYAML dependency)
            loaded = _parse_simple_yaml(config_file)
            _deep_merge(config, loaded)
        except Exception as e:
            _log("WARNING", f"Failed to parse {config_file}: {e}, using defaults")
    else:
        _log("WARNING", "No agent.yml found, using defaults. Copy agent.yml.example to agent.yml.")

    return config


def _parse_simple_yaml(path: str) -> dict:
    """Parse a simple YAML file (key: value, nested via indentation)."""
    result = {}
    stack = [(0, result)]

    with open(path, "r") as f:
        for line in f:
            line = line.rstrip()
            if not line or line.strip().startswith("#"):
                continue

            indent = len(line) - len(line.lstrip())
            stripped = line.strip()

            # Pop stack to current indent level
            while stack and stack[-1][0] > indent:
                stack.pop()

            if ":" not in stripped:
                continue

            key, _, value = stripped.partition(":")
            key = key.strip()
            value = value.strip()

            # Remove quotes from value
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            elif value.startswith("'") and value.endswith("'"):
                value = value[1:-1]

            current = stack[-1][1]

            if value == "":
                # Nested dict
                new_dict = {}
                current[key] = new_dict
                stack.append((indent + 2, new_dict))
            elif value.startswith("[") and value.endswith("]"):
                # List
                items = []
                inner = value[1:-1].strip()
                if inner:
                    for item in inner.split(","):
                        item = item.strip().strip('"').strip("'")
                        if item:
                            items.append(item)
                current[key] = items
            elif value.lower() in ("true", "false"):
                current[key] = value.lower() == "true"
            elif value.isdigit():
                current[key] = int(value)
            elif _is_float(value):
                current[key] = float(value)
            else:
                current[key] = value

    return result


def _is_float(s: str) -> bool:
    try:
        float(s)
        return True
    except ValueError:
        return False


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def _log(level: str, msg: str):
    import datetime
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)
