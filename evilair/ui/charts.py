"""Text charts used by the ``analyze`` command."""

from __future__ import annotations

from rich.table import Table
from rich.text import Text

from evilair.util.rate import format_bytes

BAR = "▇"


def bar_rows(values: list[tuple[str, int]], width: int = 28) -> list[Text]:
    """Build proportional bars for ``(label, value)`` pairs."""
    if not values:
        return []

    largest = max(value for _, value in values) or 1
    label_width = max(len(label) for label, _ in values)
    rows: list[Text] = []

    for label, value in sorted(values, key=lambda item: item[1], reverse=True):
        length = max(int(round(value / largest * width)), 1 if value > 0 else 0)
        text = Text()
        text.append(label.ljust(label_width) + "  ", style="bold yellow")
        text.append(BAR * length, style="red" if value == largest else "yellow")
        text.append(f"  {format_bytes(value)}", style="dim")
        rows.append(text)
    return rows


def chart_table(title: str, values: list[tuple[str, int]], width: int = 28) -> Table:
    table = Table(title=title, show_header=False, box=None, title_justify="left")
    table.add_column()
    for row in bar_rows(values, width):
        table.add_row(row)
    if not values:
        table.add_row(Text("no traffic recorded", style="dim"))
    return table
