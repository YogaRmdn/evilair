"""All terminal output goes through this module (rich based)."""

from __future__ import annotations

import shutil
import sys

from rich import box
from rich.console import Console as RichConsole
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from evilair.core.host import Host
from evilair.util.rate import format_bitrate, format_bytes

STATUS_STYLES = {
    "free": "green",
    "limited": "yellow",
    "blocked": "red",
    "limited+blocked": "magenta",
}


class Console:
    """Small facade so the rest of the code never touches raw ANSI codes."""

    def __init__(self, colorless: bool = False, quiet: bool = False, width: int | None = None) -> None:
        if width is None:
            if sys.stdout.isatty():
                width = shutil.get_terminal_size((120, 24)).columns
            else:
                width = 120
        self.rich = RichConsole(
            no_color=colorless, highlight=False, soft_wrap=False, width=width
        )
        self.quiet = quiet

    # -- primitives -------------------------------------------------------
    def print(self, *renderables, **kwargs) -> None:
        if not self.quiet:
            self.rich.print(*renderables, **kwargs)

    def ok(self, message: str) -> None:
        self.print(f"[bold green] OK [/] {message}")

    def info(self, message: str) -> None:
        self.print(f"[bold cyan]INFO[/] {message}")

    def warn(self, message: str) -> None:
        self.print(f"[bold yellow]WARN[/] {message}")

    def error(self, message: str) -> None:
        self.print(f"[bold red]FAIL[/] {message}")

    def rule(self, title: str = "") -> None:
        self.rich.rule(title, style="dim")

    # -- domain renderables ----------------------------------------------
    def host_table(self, hosts: list[Host], title: str = "Hosts") -> Table:
        table = Table(
            title=title,
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            title_justify="left",
            pad_edge=False,
        )
        table.add_column("#", justify="right", style="bold yellow", width=3, no_wrap=True)
        table.add_column("IP address", style="white", no_wrap=True)
        table.add_column("MAC address", style="dim", no_wrap=True, min_width=17)
        table.add_column("Hostname", overflow="fold")
        table.add_column("Status", no_wrap=True)
        table.add_column("Limit", justify="right", overflow="fold")
        table.add_column("Up / Down", justify="right", no_wrap=True)

        for index, host in enumerate(hosts):
            status = host.status()
            # Show a clear placeholder instead of a bare "-" so an unset limit is
            # not mistaken for missing data; blocked hosts show "blocked".
            limit = host.limit_summary() or ("blocked" if host.blocked else "none")
            traffic = (
                f"{format_bitrate(host.traffic.upload_rate)} / "
                f"{format_bitrate(host.traffic.download_rate)}"
            )
            flags = []
            if host.spoofed:
                flags.append("[blue]mitm[/]")
            if host.watched:
                flags.append("[cyan]watch[/]")
            status_markup = status + (" " + " ".join(flags) if flags else "")
            table.add_row(
                str(index),
                host.ip,
                host.mac,
                host.name or "-",
                Text.from_markup(status_markup, style=STATUS_STYLES.get(status, "white")),
                limit,
                traffic,
            )
        return table

    def traffic_table(self, hosts: list[Host], title: str = "Live traffic") -> Table:
        table = Table(
            title=title,
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            title_justify="left",
            pad_edge=False,
        )
        table.add_column("#", justify="right", style="bold yellow", width=3)
        table.add_column("IP address")
        table.add_column("Hostname", overflow="fold")
        table.add_column("Upload", justify="right")
        table.add_column("Download", justify="right")
        table.add_column("Total up", justify="right")
        table.add_column("Total down", justify="right")
        table.add_column("Packets ↑/↓", justify="right")

        for index, host in enumerate(hosts):
            traffic = host.traffic
            table.add_row(
                str(index),
                host.ip,
                host.name or "-",
                format_bitrate(traffic.upload_rate),
                format_bitrate(traffic.download_rate),
                format_bytes(traffic.upload_total),
                format_bytes(traffic.download_total),
                f"{traffic.upload_packets}/{traffic.download_packets}",
            )
        return table

    def panel(self, body, title: str, style: str = "cyan") -> Panel:
        return Panel(body, title=title, border_style=style, box=box.ROUNDED, expand=False)
