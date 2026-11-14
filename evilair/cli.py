"""Command line entry point."""

from __future__ import annotations

import argparse
import atexit
import ipaddress
import logging
import os
import signal
import sys

from evilair import __description__, __version__
from evilair.net.arp import ARPScanner
from evilair.net.iface import (
    get_default_gateway_ip,
    list_interfaces,
    neighbour_table,
)
from evilair.repl import Repl
from evilair.session import Session, SessionError, build_config, discover_interface
from evilair.ui.banner import banner, session_header
from evilair.ui.console import Console
from evilair.util.rate import format_mac
from evilair.util.shell import ToolMissingError

LOGGER = logging.getLogger("evilair")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evilair",
        description=__description__,
        epilog="example: sudo evilair -i wlan0   then: scan, limit 0 512kbit, monitor",
    )
    parser.add_argument("-i", "--interface", help="network interface (auto-detected)")
    parser.add_argument("-g", "--gateway-ip", dest="gateway_ip", help="gateway IPv4 address")
    parser.add_argument("-m", "--gateway-mac", dest="gateway_mac", help="gateway MAC address")
    parser.add_argument("-n", "--netmask", help="netmask or CIDR length for the LAN")
    parser.add_argument("-c", "--exec", dest="commands", help="run ';' separated commands and exit")
    parser.add_argument("-f", "--flush", action="store_true", help="remove leftover evilair rules at start")
    parser.add_argument("--dry-run", action="store_true", help="print commands instead of applying them")
    parser.add_argument("--colorless", action="store_true", help="disable colors")
    parser.add_argument("--debug", action="store_true", help="verbose logging")
    parser.add_argument("--list-interfaces", action="store_true", help="show interfaces and exit")
    parser.add_argument("-V", "--version", action="version", version=f"evilair {__version__}")
    return parser


def configure_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def resolve_network(netmask: str | None, address, default_network):
    if not netmask:
        return default_network
    try:
        if netmask.isdigit():
            return ipaddress.IPv4Network(f"{address}/{int(netmask)}", strict=False)
        return ipaddress.IPv4Network(f"{address}/{netmask}", strict=False)
    except ValueError as exc:
        raise SessionError(f"invalid netmask: {netmask}") from exc


def resolve_gateway_mac(interface: str, gateway_ip: str, provided: str | None) -> str:
    if provided:
        try:
            return format_mac(provided)
        except ValueError as exc:
            raise SessionError(str(exc)) from exc

    cached = neighbour_table().get(gateway_ip)
    if cached:
        return cached

    try:
        found = ARPScanner(interface, timeout=1.5, retries=1).scan([gateway_ip], resolve_names=False)
    except Exception as exc:  # pragma: no cover - needs root
        raise SessionError(
            "could not resolve the gateway MAC (needs root). Pass it with -m."
        ) from exc
    if not found:
        raise SessionError("gateway did not answer the ARP request. Pass its MAC with -m.")
    return found[0].mac


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.debug)
    console = Console(colorless=args.colorless)

    if args.list_interfaces:
        for name in list_interfaces():
            console.print(name)
        return 0

    if not args.dry_run and hasattr(os, "geteuid") and os.geteuid() != 0:
        console.print(banner())
        console.error("root is required to shape traffic and craft ARP packets")
        console.print("[dim]run: sudo evilair   (or preview with --dry-run)[/dim]")
        return 1

    try:
        interface = discover_interface(args.interface)
    except SessionError as exc:
        console.error(str(exc))
        return 1

    gateway_ip = args.gateway_ip or get_default_gateway_ip()
    if not gateway_ip:
        console.error("could not detect the gateway, pass it with -g")
        return 1

    try:
        network = resolve_network(args.netmask, interface.address, interface.network)
        gateway_mac = resolve_gateway_mac(interface.name, gateway_ip, args.gateway_mac)
    except SessionError as exc:
        console.error(str(exc))
        return 1

    config = build_config(interface, gateway_ip, gateway_mac, dry_run=args.dry_run)
    config.network = network
    session = Session(config, console)

    if args.flush:
        session.controller.flush()

    console.print(banner())
    console.print(session_header(interface.name, gateway_ip, len(session.hosts), args.dry_run))
    try:
        started = session.start()
    except ToolMissingError as exc:
        console.error(str(exc))
        return 1

    if not started:
        console.error("could not initialise traffic control (try 'sudo evilair --flush')")
        return 1

    atexit.register(session.shutdown)

    def handle_signal(signum, _frame):
        LOGGER.info("signal %s received", signum)
        raise KeyboardInterrupt

    for sig in (signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(sig, handle_signal)
        except (ValueError, OSError):  # pragma: no cover - not main thread
            pass

    try:
        if args.commands:
            repl = Repl(session)
            for command in args.commands.split(";"):
                command = command.strip()
                if not command:
                    continue
                console.print(f"[dim]› {command}[/dim]")
                repl.handle(command)
                if not repl._running:  # noqa: SLF001 - quit command
                    break
        else:
            Repl(session).run()
    except KeyboardInterrupt:
        console.print()
    finally:
        console.info("restoring network settings…")
        session.shutdown()
        console.ok("network restored, goodbye")

    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
