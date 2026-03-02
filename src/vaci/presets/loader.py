from __future__ import annotations

import json
from importlib import resources
from typing import Any, Dict, List


class PresetNotFoundError(FileNotFoundError):
    pass


def _preset_dir():
    # Use importlib.resources so presets work when installed via pip,
    # not only in editable installs.
    return resources.files("vaci.presets")


def list_presets() -> List[str]:
    """
    Return available preset names (without .json extension).
    """
    root = _preset_dir()
    out: List[str] = []
    for p in root.iterdir():
        if p.is_file() and p.name.endswith(".json"):
            out.append(p.name[:-5])
    return sorted(out)


def load_preset(name: str) -> Dict[str, Any]:
    """
    Load a preset policy JSON by name (e.g. "pr-agent").
    """
    root = _preset_dir()
    target = root / f"{name}.json"
    if not target.exists():
        avail = ", ".join(list_presets()) or "(none)"
        raise PresetNotFoundError(f"Preset '{name}' not found. Available: {avail}")
    data = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Preset '{name}' must be a JSON object.")
    return data