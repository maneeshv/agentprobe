"""
Config file support — load scan targets from YAML/JSON config files.
"""

import json
from pathlib import Path
from typing import Any


def load_config(path: str) -> dict[str, Any]:
    """Load a config file (JSON or YAML)."""
    p = Path(path)
    text = p.read_text()

    if p.suffix in (".yaml", ".yml"):
        try:
            import yaml
            return yaml.safe_load(text)
        except ImportError:
            raise ImportError(
                "PyYAML is required for YAML config files. "
                "Install it with: pip install pyyaml"
            )
    else:
        return json.loads(text)


def parse_cookie_string(raw: str) -> str:
    """
    Clean up a raw cookie string (from browser DevTools).
    Returns a properly formatted cookie header value.
    """
    # Strip leading -b or --cookie flags if present
    raw = raw.strip()
    if raw.startswith("-b ") or raw.startswith("-b\t"):
        raw = raw[3:].strip()
    if raw.startswith("--cookie "):
        raw = raw[9:].strip()
    # Remove surrounding quotes
    if (raw.startswith("'") and raw.endswith("'")) or \
       (raw.startswith('"') and raw.endswith('"')):
        raw = raw[1:-1]
    return raw
