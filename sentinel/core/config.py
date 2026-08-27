"""Paths and engine locators."""
from __future__ import annotations
import os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIN_DIR = os.path.join(ROOT, "bin")


def bin_path(name: str) -> str:
    """Return an engine binary path if present in ./bin, else rely on PATH."""
    cand = os.path.join(BIN_DIR, name)
    if os.path.isfile(cand):
        return cand
    cand_exe = os.path.join(BIN_DIR, name + ".exe")
    if os.path.isfile(cand_exe):
        return cand_exe
    return name  # fall back to PATH
