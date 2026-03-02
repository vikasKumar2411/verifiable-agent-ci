from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, List

try:
    # Python 3.9
    from importlib import resources as importlib_resources
except Exception:  # pragma: no cover
    import importlib_resources  # type: ignore


PRESET_PACKAGE = "vaci.presets"

# Keep a stable tutorial-friendly alias. Canonical preset stays "pr-agent".
_PRESET_ALIASES: Dict[str, str] = {
    "demo": "pr-agent",
}

def _resolve_preset_name(name: str) -> str:
    return _PRESET_ALIASES.get(name, name)


def list_presets() -> List[str]:
    """
    Returns preset names (without .json extension) bundled with the package.
    """
    presets: List[str] = []
    root = importlib_resources.files(PRESET_PACKAGE)
    for entry in root.iterdir():
        if entry.is_file() and entry.name.endswith(".json"):
            presets.append(entry.name[:-5])
    return sorted(presets)


def load_preset(name: str) -> Dict:
    """
    Loads a preset JSON from vaci.presets/<name>.json and returns the parsed dict.
    """
    resolved = _resolve_preset_name(name)
    filename = f"{resolved}.json"
    root = importlib_resources.files(PRESET_PACKAGE)
    path = root / filename
    if not path.is_file():
        available = ", ".join(list_presets()) or "(none)"
        # show the original user-supplied name in the error
        raise FileNotFoundError(f"Unknown preset '{name}'. Available: {available}")
    raw = path.read_text(encoding="utf-8")
    return json.loads(raw)
