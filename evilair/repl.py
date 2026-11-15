"""Interactive command shell with history, completion and rich feedback."""

from __future__ import annotations

import argparse
import logging
import os
import time

try:  # prompt_toolkit gives us arrow-key completion and a polished prompt
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import WordCompleter
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.styles import Style
    from prompt_toolkit.formatted_text import HTML, FormattedText
    PROMPT_TOOLKIT = True
except Exception:  # pragma: no cover - fallback to plain input/readline
    PROMPT_TOOLKIT = False
    PromptSession = None
    WordCompleter = None
    FileHistory = None
    AutoSuggestFromHistory = None
    Style = None
    HTML = None
    FormattedText = None
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from rich.live import Live
from rich.table import Table

from evilair import __version__
from evilair.net.qos import Direction
from evilair.session import Session, SessionError
from evilair.ui.banner import banner, session_header
from evilair.ui.charts import chart_table
from evilair.util.rate import BitRate, format_bitrate

LOGGER = logging.getLogger("evilair.repl")

_EXIT = {"quit", "exit", "q"}


@dataclass
class Command:
    name: str
    summary: str
    parser: argparse.ArgumentParser
    handler: Callable[[argparse.Namespace], None]
    aliases: tuple[str, ...] = field(default=())


class Repl:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.console = session.console
        self.commands: dict[str, Command] = {}
        self._running = True
        self._parser = argparse.ArgumentParser(prog="", add_help=False)
        self._subparsers = self._parser.add_subparsers(dest="command")
        self._register_commands()

    # -- command registry -------------------------------------------------
    def _add(
        self,
        name: str,
        summary: str,
        aliases: tuple[str, ...] = (),
        help_text: str = "",
    ) -> argparse.ArgumentParser:
        parser = self._subparsers.add_parser(name, add_help=False, description=help_text or summary)
        command = Command(name=name, summary=summary, parser=parser, handler=lambda _: None, aliases=aliases)
        self.commands[name] = command
        for alias in aliases:
            self.commands[alias] = command
        return parser

    def _set_handler(self, name: str, handler: Callable[[argparse.Namespace], None]) -> None:
        self.commands[name].handler = handler

    def _register_commands(self) -> None:
        parser = self._add("scan", "Discover hosts on the LAN (ARP sweep).", ("s",))
        parser.add_argument("target", nargs="?", help="IP, CIDR or start-end range")
        parser.add_argument("--no-names", action="store_true", help="skip reverse DNS")
        self._set_handler("scan", self._cmd_scan)

        parser = self._add("hosts", "List discovered hosts.", ("ls", "list"))
        self._set_handler("hosts", self._cmd_hosts)

        parser = self._add("import", "Import hosts from the kernel ARP cache (no root).", ("neigh",))
        parser.add_argument("--probe", action="store_true", help="ping the LAN first to fill the cache")
        self._set_handler("import", self._cmd_import)

        parser = self._add("add", "Add a host manually.")
        parser.add_argument("ip")
        parser.add_argument("--mac")
        parser.add_argument("--name")
        self._set_handler("add", self._cmd_add)

        parser = self._add("limit", "Cap the bandwidth of one or more hosts.")
        parser.add_argument("target", help="id, range (1-3), IP, MAC or 'all'")
        parser.add_argument("rate", help="e.g. 512kbit, 2mbit")
        parser.add_argument("--dir", choices=["up", "down", "both"], default="both")
        parser.add_argument("--download", dest="download_rate", help="separate download rate")
        self._set_handler("limit", self._cmd_limit)

        parser = self._add("block", "Cut internet access for one or more hosts.")
        parser.add_argument("target")
        parser.add_argument("--dir", choices=["up", "down", "both"], default="both")
        self._set_handler("block", self._cmd_block)

        parser = self._add(
            "block-all",
            "Cut internet access for every discovered host (gateway skipped).",
            ("blockall", "block_all"),
        )
        parser.add_argument("--scan", action="store_true", help="scan the LAN first")
        parser.add_argument("--dir", choices=["up", "down", "both"], default="both")
        self._set_handler("block-all", self._cmd_block_all)

        parser = self._add(
            "free",
            "Remove every limit/block from hosts ('all' skips the gateway).",
            ("unlimit", "release"),
        )
        parser.add_argument("target", nargs="?", default="all")
        self._set_handler("free", self._cmd_free)

        parser = self._add(
            "free-all",
            "Remove every limit/block from all known hosts (gateway skipped).",
            ("freeall", "free_all"),
        )
        self._set_handler("free-all", self._cmd_free_all)

        parser = self._add("monitor", "Live bandwidth view.", ("mon", "top"))
        parser.add_argument("--interval", type=int, default=1000, help="refresh interval in ms")
        self._set_handler("monitor", self._cmd_monitor)

        parser = self._add("analyze", "Measure who uses the most bandwidth.")
        parser.add_argument("target", nargs="?", default="all")
        parser.add_argument("--duration", type=int, default=15, help="seconds to sample")
        self._set_handler("analyze", self._cmd_analyze)

        parser = self._add("watch", "Detect reconnections (same MAC, new IP).")
        parser.add_argument("action", nargs="?", choices=["add", "remove", "interval", "list"], default="list")
        parser.add_argument("value", nargs="?")
        self._set_handler("watch", self._cmd_watch)

        parser = self._add("export", "Save the host list as JSON or CSV.")
        parser.add_argument("path")
        parser.add_argument("--csv", action="store_true")
        self._set_handler("export", self._cmd_export)

        parser = self._add("flush", "Delete every evilair rule and the qdisc.")
        self._set_handler("flush", self._cmd_flush)

        parser = self._add("clear", "Clear the screen.")
        self._set_handler("clear", self._cmd_clear)

        parser = self._add("help", "Show this help.", ("?",))
        parser.add_argument("topic", nargs="?")
        self._set_handler("help", self._cmd_help)

        parser = self._add("menu", "Open the interactive command menu (arrow keys).", ("m",))
        self._set_handler("menu", self._cmd_menu)

        parser = self._add("update", "Pull the latest version from GitHub and reinstall.", ("upd",))
        self._set_handler("update", self._cmd_update)

        self._add("quit", "Leave evilair and restore the network.", ("exit", "q"))

    # -- loop -------------------------------------------------------------
    def run(self) -> None:
        self._print_intro()
        if PROMPT_TOOLKIT:
            self._pt_session = PromptSession(
                history=FileHistory(str(self._history_path())),
                auto_suggest=AutoSuggestFromHistory(),
                style=Style.from_dict(
                    {
                        "prompt": "bold #5fd7ff",
                        "bottom-toolbar": "bg:#1e1e2e #cdd6f4",
                    }
                ),
            )
        else:  # pragma: no cover - prompt_toolkit unavailable, fall back to readline
            self._pt_session = None
            self._install_readline()

        while self._running:
            try:
                if PROMPT_TOOLKIT:
                    words = self._completion_words()
                    self._pt_session.completer = WordCompleter(words, ignore_case=True)
                    line = self._pt_session.prompt(
                        self._prompt_message(),
                        bottom_toolbar=self._toolbar,
                    )
                else:
                    line = input(self.prompt())
            except (EOFError, KeyboardInterrupt):
                self.console.print()
                break
            if line.strip():
                self.handle(line)
        self._save_history()

    def prompt(self) -> str:
        managed = sum(1 for host in self.session.hosts if host.managed)
        context = f"{len(self.session.hosts)} hosts"
        if managed:
            context += f", {managed} managed"
        return f"evilair ({context}) › "

    def _prompt_message(self):
        managed = sum(1 for host in self.session.hosts if host.managed)
        context = f"{len(self.session.hosts)} hosts"
        if managed:
            context += f", {managed} managed"
        from prompt_toolkit.formatted_text import FormattedText

        return FormattedText([("class:prompt", f"evilair ({context}) › ")])

    def _toolbar(self) -> str:
        managed = sum(1 for host in self.session.hosts if host.managed)
        context = f"{len(self.session.hosts)} hosts"
        if managed:
            context += f", {managed} managed"
        return f" evilair v{__version__} · {context} · tab complete · ctrl+c cancel · 'menu' for guided mode "

    def _completion_words(self) -> list[str]:
        words = list(self.commands.keys())
        words += ["all", "up", "down", "both", "--dir", "--download", "--duration",
                  "--interval", "--csv", "--no-names", "--probe", "--scan"]
        words += [host.ip for host in self.session.hosts]
        words += [host.mac.lower() for host in self.session.hosts]
        return sorted(set(words))

    def handle(self, line: str) -> None:
        argv = line.split()
        if argv[0] in _EXIT:
            self._running = False
            return
        alias = self.commands.get(argv[0])
        if alias is not None:
            argv[0] = alias.name
        try:
            args = self._parser.parse_args(argv)
        except SystemExit:
            self.console.error(f"usage: {argv[0]} --help")
            return

        if args.command is None:
            self.console.error("unknown command, type 'help'")
            return

        command = self.commands.get(args.command)
        if command is None:
            return
        try:
            command.handler(args)
        except SessionError as exc:
            self.console.error(str(exc))
        except Exception as exc:  # pragma: no cover - safety net
            LOGGER.exception("command failed")
            self.console.error(f"{type(exc).__name__}: {exc}")

    # -- readline ---------------------------------------------------------
    def _history_path(self) -> Path:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        directory = base / "evilair"
        directory.mkdir(parents=True, exist_ok=True)
        return directory / "history"

    def _install_readline(self) -> None:
        try:
            import readline  # noqa: PLC0415 - platform specific
        except ImportError:
            return

        def completer(text: str, state: int) -> str | None:
            words = ["all"] + [host.ip for host in self.session.hosts]
            candidates = [name for name in self.commands if name.startswith(text)]
            if " " in readline.get_line_buffer():
                candidates = [word for word in words if word.startswith(text)]
            return candidates[state] if state < len(candidates) else None

        readline.set_completer(completer)
        readline.set_completer_delims(" \t\n")
        readline.parse_and_bind("tab: complete")
        try:
            readline.read_history_file(self._history_path())
        except OSError:
            pass

    def _save_history(self) -> None:
        try:
            import readline  # noqa: PLC0415

            readline.write_history_file(self._history_path())
        except (ImportError, OSError):
            pass

    # -- presentation -----------------------------------------------------
    def _print_intro(self) -> None:
        # Banner and session header are already printed by cli.main(); only
        # show the quick-start hint here to avoid duplicating the banner.
        self.console.print("[dim]type 'help' for commands · 'scan' to start · 'menu' for guided mode · ctrl+c to leave[/dim]\n")

    def refresh_header(self) -> None:
        self.console.print(
            session_header(
                self.session.config.interface,
                self.session.config.gateway_ip,
                len(self.session.hosts),
                self.session.config.dry_run,
            )
        )

    def print_hosts(self) -> None:
        if not self.session.hosts:
            self.console.warn("no hosts yet, run 'scan'")
            return
        self.session.snapshot()
        self.console.print(self.console.host_table(self.session.hosts))

    # -- commands ---------------------------------------------------------
    def _cmd_scan(self, args: argparse.Namespace) -> None:
        self.console.info("scanning…")
        with self.console.rich.status("[cyan]ARP sweep berjalan…[/]", spinner="dots"):
            hosts = self.session.scan(args.target, resolve_names=not args.no_names)
        self.console.ok(f"{len(hosts)} host(s) known")
        self.print_hosts()

    def _cmd_hosts(self, args: argparse.Namespace) -> None:
        self.print_hosts()

    def _cmd_import(self, args: argparse.Namespace) -> None:
        if args.probe:
            self.console.info("probing the LAN to populate the ARP cache…")
        with self.console.rich.status("[cyan]membaca ARP cache…[/]", spinner="dots"):
            hosts = self.session.import_from_cache(probe=args.probe)
        self.console.ok(f"imported from the ARP cache, {len(hosts)} host(s) known")
        self.print_hosts()

    def _cmd_add(self, args: argparse.Namespace) -> None:
        host = self.session.add(args.ip, args.mac, args.name)
        self.console.ok(f"host {host.ip} ({host.mac}) is tracked")

    def _cmd_limit(self, args: argparse.Namespace) -> None:
        hosts = self.session.limit(
            args.target, args.rate, Direction.parse(args.dir), args.download_rate
        )
        for host in hosts:
            detail = []
            if host.upload_limit is not None:
                detail.append(f"up {format_bitrate(host.upload_limit)}")
            if host.download_limit is not None:
                detail.append(f"down {format_bitrate(host.download_limit)}")
            self.console.ok(f"{host.ip} limited to {' / '.join(detail)}")

    def _cmd_block(self, args: argparse.Namespace) -> None:
        hosts = self.session.block(args.target, Direction.parse(args.dir))
        for host in hosts:
            self.console.ok(f"{host.ip} blocked ({Direction.parse(args.dir).label()})")

    def _cmd_block_all(self, args: argparse.Namespace) -> None:
        if args.scan or not self.session.hosts:
            self.console.info("scanning the LAN first…")
            self.session.scan()
        if not self.session.hosts:
            raise SessionError("no hosts detected; run 'scan' or 'import --probe' first")
        hosts = self.session.block("all", Direction.parse(args.dir))
        self.console.ok(f"{len(hosts)} host(s) blocked")

    def _cmd_free(self, args: argparse.Namespace) -> None:
        hosts = self.session.free(args.target)
        for host in hosts:
            self.console.ok(f"{host.ip} is free again")

    def _cmd_free_all(self, args: argparse.Namespace) -> None:
        if not self.session.hosts:
            raise SessionError("no hosts discovered yet, run 'scan' first")
        hosts = self.session.free("all")
        self.console.ok(f"{len(hosts)} host(s) freed")

    def _cmd_monitor(self, args: argparse.Namespace) -> None:
        hosts = self.session.hosts
        if not hosts:
            raise SessionError("no hosts to monitor, run 'scan' first")

        watched = [host for host in hosts if host.managed]
        for host in watched or hosts:
            self.session.monitor.watch(host)
        if not watched:
            self.console.warn("no limits set, showing traffic of all known hosts")

        interval = max(args.interval, 250) / 1000
        self.console.print("[dim]press ctrl+c to return to the prompt[/dim]")
        try:
            with Live(
                self.console.traffic_table(hosts),
                console=self.console.rich,
                refresh_per_second=max(int(1 / interval), 1),
                screen=False,
            ) as live:
                while True:
                    time.sleep(interval)
                    self.session.snapshot()
                    live.update(self.console.traffic_table(hosts))
        except KeyboardInterrupt:
            self.console.print()
        finally:
            for host in watched or hosts:
                self.session.monitor.unwatch(host)

    def _cmd_analyze(self, args: argparse.Namespace) -> None:
        hosts = self.session.select(args.target)
        duration = max(args.duration, 1)
        for host in hosts:
            self.session.monitor.watch(host)

        self.console.info(f"sampling {len(hosts)} host(s) for {duration}s…")
        self.session.snapshot()
        baseline = {host.ip: (host.traffic.upload_total, host.traffic.download_total) for host in hosts}
        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            self.console.warn("sampling interrupted, showing partial results")
        self.session.snapshot()

        upload: list[tuple[str, int]] = []
        download: list[tuple[str, int]] = []
        for host in hosts:
            start_up, start_down = baseline[host.ip]
            label = f"{host.ip} {host.name}".strip()
            upload.append((label, max(host.traffic.upload_total - start_up, 0)))
            download.append((label, max(host.traffic.download_total - start_down, 0)))
            self.session.monitor.unwatch(host)

        self.console.print()
        self.console.print(chart_table(f"Upload over {duration}s", upload))
        self.console.print(chart_table(f"Download over {duration}s", download))

    def _cmd_watch(self, args: argparse.Namespace) -> None:
        action = args.action
        if action == "add":
            if not args.value:
                raise SessionError("usage: watch add <target>")
            self.session.watch(args.value, True)
            self.console.ok(f"watching {args.value}")
        elif action == "remove":
            if not args.value:
                raise SessionError("usage: watch remove <target>")
            self.session.watch(args.value, False)
            self.console.ok(f"stopped watching {args.value}")
        elif action == "interval":
            if not args.value:
                raise SessionError("usage: watch interval <seconds>")
            try:
                seconds = float(args.value)
            except ValueError as exc:
                raise SessionError("interval must be a number of seconds") from exc
            self.session.watcher.interval = seconds
            self.console.ok(f"watch interval set to {self.session.watcher.interval:.0f}s")
        else:
            self._watch_overview()

    def _watch_overview(self) -> None:
        table = Table(box=None, show_header=True, header_style="bold cyan", title="Watchlist", title_justify="left")
        table.add_column("IP address")
        table.add_column("MAC address")
        table.add_column("Current ID")
        for host in self.session.watcher.watched:
            index = self.session.hosts.index(host) if host in self.session.hosts else "-"
            table.add_row(host.ip, host.mac, str(index))
        if not self.session.watcher.watched:
            table.add_row("-", "-", "-")
        self.console.print(table)
        self.console.print(f"[dim]interval {self.session.watcher.interval:.0f}s[/dim]")
        if self.session.watcher.history:
            self.console.print("[bold]recent reconnections[/bold]")
            for entry in self.session.watcher.history[-5:]:
                self.console.print(f"  {entry.old.ip} → {entry.new.ip} at {time.strftime('%H:%M:%S', time.localtime(entry.at))}")

    def _cmd_export(self, args: argparse.Namespace) -> None:
        path = self.session.export(args.path, "csv" if args.csv else "json")
        self.console.ok(f"written to {path}")

    def _cmd_flush(self, args: argparse.Namespace) -> None:
        self.session.controller.flush()
        for host in self.session.hosts:
            host.forget_control_state()
        self.console.ok("all shaping and blocking rules removed")

    def _cmd_menu(self, args: argparse.Namespace) -> None:
        """Guided, arrow-key driven command picker."""
        if not PROMPT_TOOLKIT:
            raise SessionError("interactive menu needs prompt_toolkit")
        from prompt_toolkit.shortcuts import radiolist_dialog, input_dialog, message_dialog

        seen: set[str] = set()
        choices: list[tuple[str, str]] = []
        for name, command in self.commands.items():
            if command.name in seen:
                continue
            seen.add(command.name)
            choices.append((command.name, f"{command.name:<8} {command.summary}"))
        if not choices:
            raise SessionError("no commands registered")

        selected = radiolist_dialog(
            title="EvilAir · Command Menu",
            text="Pilih perintah dengan panah ↑/↓, Enter untuk jalankan, Esc untuk batal.",
            values=choices,
        ).run()
        if not selected:
            return

        command = self.commands[selected]
        # Show the usage hint first so the user knows the expected arguments.
        help_text = command.parser.format_help()
        args_value = input_dialog(
            title=f"{selected} arguments",
            text=(
                f"{command.summary}\n\n"
                "Masukkan argumen (kosongkan jika tidak perlu).\n"
                "Contoh: 0 512kbit  /  all  /  192.168.1.5 2mbit --dir down"
            ),
        ).run()
        if args_value is None:
            return
        line = selected + (" " + args_value.strip() if args_value.strip() else "")
        self.console.print(f"[dim]› {line}[/dim]")
        self.handle(line)

    def _cmd_update(self, args: argparse.Namespace) -> None:
        """Pull the latest code from GitHub and reinstall the package."""
        import subprocess
        import sys
        from pathlib import Path

        project_root = Path(__file__).resolve().parents[1]
        if not (project_root / ".git").is_dir():
            raise SessionError(
                "this installation is not a git checkout; update manually with git pull"
            )

        self.console.info("fetching updates from GitHub…")
        pull = subprocess.run(
            ["git", "-C", str(project_root), "pull", "--ff-only"],
            capture_output=True,
            text=True,
        )
        output = (pull.stdout or "").strip()
        if pull.returncode != 0:
            detail = (pull.stderr or output or "unknown error").strip()
            raise SessionError(f"git pull failed: {detail}")
        if output:
            self.console.ok(output.splitlines()[-1])
        else:
            self.console.ok("already up to date")

        from evilair.util.pythonenv import preferred_python

        python = preferred_python() or sys.executable
        self.console.info("installing dependencies…")
        install = subprocess.run(
            [python, "-m", "pip", "install", "-e", str(project_root)],
            capture_output=True,
            text=True,
        )
        if install.returncode != 0:
            detail = (install.stderr or install.stdout or "unknown error").strip()
            raise SessionError(f"pip install failed: {detail[-400:]}")
        self.console.ok("update complete — restart EvilAir to use the new version")

    def _cmd_clear(self, args: argparse.Namespace) -> None:
        self.console.rich.clear()
        self.console.print(banner())
        self.refresh_header()

    def _cmd_help(self, args: argparse.Namespace) -> None:
        if args.topic:
            command = self.commands.get(args.topic)
            if command is None:
                raise SessionError(f"unknown command: {args.topic}")
            self.console.print(command.parser.format_help())
            return

        table = Table(box=None, show_header=False, pad_edge=False)
        table.add_column("command", style="bold yellow", no_wrap=True)
        table.add_column("description", style="white")
        seen: set[str] = set()
        for name, command in self.commands.items():
            if command.name in seen:
                continue
            seen.add(command.name)
            label = command.name
            if command.aliases:
                label += f" ({', '.join(command.aliases)})"
            table.add_row(label, command.summary)
        self.console.print(table)
        self.console.print(
            "[dim]examples: scan → limit 0 512kbit → monitor → free all → export hosts.json[/dim]"
        )
        self.console.print(f"[dim]evilair v{__version__} · ctrl+c restores the network and quits[/dim]")
