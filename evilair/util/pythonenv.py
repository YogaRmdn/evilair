"""Locate the interpreter that has EvilAir's dependencies installed."""

from __future__ import annotations

import os
from pathlib import Path

ENV_VAR = "EVILAIR_PYTHON"


def preferred_python() -> str | None:
    """Return the best interpreter for EvilAir, or ``None`` for the current one.

    Resolution order: the ``EVILAIR_PYTHON`` override, a project-local
    ``.venv``, then the conventional ``~/Python-env`` described in the README.
    Hard-coding a single user path made ``run.py`` and ``update`` unusable on
    any other machine.
    """
    override = os.environ.get(ENV_VAR)
    if override and os.path.exists(override):
        return override

    project_root = Path(__file__).resolve().parents[2]
    candidates = (
        project_root / ".venv" / "bin" / "python",
        Path.home() / "Python-env" / "bin" / "python",
    )
    for candidate in candidates:
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None
