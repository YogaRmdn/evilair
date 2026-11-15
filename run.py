#!/usr/bin/env python3
"""Convenience entry point so you can run EvilAir from this folder with ./run.py."""
import os
import sys

from evilair.util.pythonenv import preferred_python


def reexec_in_venv() -> None:
    """Re-exec with the project virtualenv when it is not the current one.

    This keeps ``sudo ./run.py`` working (sudo drops the venv from PATH) without
    hard-coding a path that only exists on one machine.
    """
    target = preferred_python()
    if not target:
        return
    if os.path.abspath(sys.executable) == os.path.abspath(target):
        return
    os.execv(target, [target] + sys.argv)


if __name__ == "__main__":
    reexec_in_venv()
    from evilair.cli import main

    main()
