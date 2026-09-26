"""Centralized runtime state paths.

Every module that persists state (canary manifests, FIM baselines, honeyport
trips, burner traps) resolves it through here instead of hardcoding
``~/.sentinel``. That gives three things:

1. One place to change the location.
2. ``SENTINEL_HOME`` override so the test suite — and anyone running two
   isolated audits — never touches the real operator state directory.
3. Lazy resolution. Paths are computed on *call*, not at import time, so
   setting ``SENTINEL_HOME`` after import still takes effect.
"""
from __future__ import annotations

import os

ENV_VAR = "SENTINEL_HOME"
DEFAULT_DIR = "~/.sentinel"


def state_dir() -> str:
    """Return the active state directory, honouring ``SENTINEL_HOME``."""
    override = os.environ.get(ENV_VAR)
    if override:
        return os.path.abspath(os.path.expanduser(override))
    return os.path.abspath(os.path.expanduser(DEFAULT_DIR))


def state_path(name: str) -> str:
    """Return an absolute path *inside* the state directory."""
    return os.path.join(state_dir(), name)


def ensure_state_dir() -> str:
    """Create the state directory if needed and return it."""
    d = state_dir()
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d
