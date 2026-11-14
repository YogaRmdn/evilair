#!/home/whoami/Python-env/bin/python
"""Convenience entry point so you can run EvilAir from this folder with ./run.py."""
import os
import sys

VENV_PYTHON = "/home/whoami/Python-env/bin/python"
# Re-exec with the project virtualenv when launched via a different interpreter
# (e.g. `sudo python run.py`), so dependencies like prompt_toolkit resolve.
if os.path.exists(VENV_PYTHON) and os.path.abspath(sys.executable) != os.path.abspath(VENV_PYTHON):
    os.execv(VENV_PYTHON, [VENV_PYTHON] + sys.argv)

from evilair.cli import main

if __name__ == "__main__":
    main()
