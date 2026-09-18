"""Configuration loader for Agent Guard.

Loads API keys and settings from:
1. Explicit argument
2. Environment variables (TYPESAFE_API_KEY)
3. RC configuration files (.agentguardrc, ~/.agentguardrc)
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional


CANDIDATE_RC_FILES: List[Path] = [
    Path.cwd() / ".agentguardrc",
    Path.home() / ".agentguardrc",
    Path.home() / ".agent-guardrc",
    Path.home() / ".config" / "agent-guard" / "config",
]


def parse_rc_content(content: str) -> Dict[str, str]:
    """Parse key-value pairs from an RC file content.

    Supports:
    - INI/env style: KEY=VALUE or key = "value"
    - JSON style: {"typesafe_api_key": "..."}
    - Single raw key on a single line
    """
    content = content.strip()
    if not content:
        return {}

    # 1. Try JSON if it looks like a JSON object
    if content.startswith("{") and content.endswith("}"):
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                return {str(k).lower(): str(v).strip() for k, v in data.items()}
        except Exception:
            pass

    # 2. Key-value line parsing
    result = {}
    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue

        if "=" in line:
            key, val = line.split("=", 1)
            key = key.strip().lower()
            val = val.strip().strip("'\"")
            result[key] = val

    # 3. If no key-value found and it's a single clean line without spaces, treat as raw key
    if not result and len(lines) == 1 and " " not in content:
        raw_candidate = content.strip().strip("'\"")
        if len(raw_candidate) > 10:
            result["typesafe_api_key"] = raw_candidate

    return result


def find_rc_file() -> Optional[Path]:
    """Find the first existing RC configuration file."""
    for path in CANDIDATE_RC_FILES:
        try:
            if path.is_file():
                return path
        except Exception:
            continue
    return None


def load_config() -> Dict[str, str]:
    """Load merged configuration from the first matching RC file."""
    rc_path = find_rc_file()
    if not rc_path:
        return {}

    try:
        content = rc_path.read_text(encoding="utf-8")
        return parse_rc_content(content)
    except Exception:
        return {}


def get_api_key(explicit_key: Optional[str] = None) -> Optional[str]:
    """Resolve TypeSafe API Key by priority:

    1. Explicit key parameter
    2. TYPESAFE_API_KEY environment variable
    3. RC configuration file (~/.agentguardrc)
    """
    if explicit_key:
        return explicit_key

    # Check environment variable
    env_key = os.getenv("TYPESAFE_API_KEY")
    if env_key:
        return env_key.strip()

    # Check RC file
    config = load_config()
    for key in ("typesafe_api_key", "api_key", "typesafe_key"):
        if key in config and config[key]:
            return config[key]

    return None
