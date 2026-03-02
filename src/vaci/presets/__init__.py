"""
Built-in policy presets shipped with VACI.

These presets match the VACI core policy evaluator schema:
allow/deny/deny_shell/deny_arg_globs/(optional)cwd_allow.
"""

from .loader import PresetNotFoundError, list_presets, load_preset

__all__ = ["PresetNotFoundError", "list_presets", "load_preset"]