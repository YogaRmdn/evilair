"""Thin, logged, injection safe wrapper around the system tools."""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass, field

LOGGER = logging.getLogger("evilair.shell")


class ToolMissingError(RuntimeError):
    """Raised when a required system binary is not installed."""


def which(name: str) -> str | None:
    return shutil.which(name)


@dataclass(frozen=True)
class Result:
    command: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def __str__(self) -> str:
        return " ".join(self.command)


@dataclass
class CommandRunner:
    """Executes privileged commands.

    ``dry_run`` records the commands instead of touching the system, which makes
    the whole tool testable and lets users preview its actions with ``--dry-run``.
    """

    dry_run: bool = False
    history: list[Result] = field(default_factory=list)

    def run(self, command: list[str] | tuple[str, ...], check: bool = False) -> Result:
        argv = tuple(str(part) for part in command)
        if self.dry_run:
            LOGGER.info("[dry-run] %s", " ".join(argv))
            result = Result(command=argv, returncode=0)
            self.history.append(result)
            return result

        LOGGER.debug("exec: %s", " ".join(argv))
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError as exc:
            raise ToolMissingError(argv[0]) from exc

        result = Result(
            command=argv,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
        self.history.append(result)

        if not result.ok:
            LOGGER.debug(
                "command failed (%s): %s | %s",
                result.returncode,
                " ".join(argv),
                result.stderr.strip(),
            )
            if check:
                raise subprocess.CalledProcessError(
                    result.returncode, argv, result.stdout, result.stderr
                )
        return result

    def output(self, command: list[str] | tuple[str, ...]) -> str:
        result = self.run(command)
        return result.stdout if result.ok else ""

    def require(self, *binaries: str) -> None:
        missing = [name for name in binaries if which(name) is None]
        if missing and not self.dry_run:
            raise ToolMissingError(
                "missing system tool(s): "
                + ", ".join(missing)
                + " (install iproute2 and iptables)"
            )
