"""Start-up banner and session header."""

from __future__ import annotations

from rich.align import Align
from rich.text import Text

from evilair import __description__, __version__


def banner_text() -> Text:
    text = Text(justify="center")
    text.append("█▓▒░  ", style="bold red")
    text.append("EVILAIR", style="bold white")
    text.append("  ░▒▓█", style="bold red")
    text.append("\n")
    text.append(f"v{__version__}  ·  {__description__}", style="dim")
    text.append("\n")
    text.append("github.com/YogaRmdn", style="dim cyan")
    return text


def banner() -> Align:
    return Align.center(banner_text())


def session_header(interface: str, gateway: str, hosts: int, dry_run: bool = False) -> Text:
    text = Text()
    text.append("interface ", style="dim")
    text.append(interface, style="bold cyan")
    text.append("   gateway ", style="dim")
    text.append(gateway, style="bold cyan")
    text.append("   hosts ", style="dim")
    text.append(str(hosts), style="bold cyan")
    if dry_run:
        text.append("   mode ", style="dim")
        text.append("DRY-RUN (no changes applied)", style="bold yellow")
    return text
