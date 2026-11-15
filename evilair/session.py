"""The session ties discovery, shaping, monitoring and watching together."""

from __future__ import annotations

import csv
import ipaddress
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from evilair.core.host import Host
from evilair.net.arp import ARPScanner, ARPSpoofer, resolve_names_for
from evilair.net.iface import Interface, neighbour_table, resolve_interface
from evilair.net.monitor import BandwidthMonitor
from evilair.net.qos import Direction, TrafficController
from evilair.net.watch import HostWatcher
from evilair.ui.console import Console
from evilair.util.rate import BitRate, format_mac
from evilair.util.shell import CommandRunner

LOGGER = logging.getLogger("evilair.session")

IPNetwork = ipaddress.IPv4Network


class SessionError(RuntimeError):
    """A user facing error that should be printed, not traced."""


@dataclass
class SessionConfig:
    interface: str
    gateway_ip: str
    gateway_mac: str
    network: IPNetwork
    dry_run: bool = False
    watch_interval: float = 45.0
    spoof_interval: float = 2.0


@dataclass
class Session:
    config: SessionConfig
    console: Console
    runner: CommandRunner = field(init=False)
    controller: TrafficController = field(init=False)
    scanner: ARPScanner = field(init=False)
    spoofer: ARPSpoofer = field(init=False)
    monitor: BandwidthMonitor = field(init=False)
    watcher: HostWatcher = field(init=False)

    hosts: list[Host] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    _running: bool = False
    _protected: set[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.runner = CommandRunner(dry_run=self.config.dry_run)
        self.controller = TrafficController(self.runner, self.config.interface)
        self.scanner = ARPScanner(self.config.interface)
        self.spoofer = ARPSpoofer(
            self.config.interface,
            self.config.gateway_ip,
            self.config.gateway_mac,
            interval=self.config.spoof_interval,
        )
        self.monitor = BandwidthMonitor(self.config.interface)
        self.watcher = HostWatcher(
            self.scanner,
            self._addresses(),
            self._on_reconnect,
            interval=self.config.watch_interval,
        )

        # Never shape or spoof the gateway or our own address during bulk
        # operations; doing so would cut the connection for everyone.
        self._protected = {self.config.gateway_ip}
        try:
            iface = resolve_interface(self.config.interface)
        except Exception:  # pragma: no cover - platform dependent
            iface = None
        if iface is not None:
            self._protected.add(str(iface.address))

    # -- helpers ----------------------------------------------------------
    def _addresses(self) -> list[str]:
        return [str(host) for host in self.config.network.hosts()]

    @property
    def interface(self) -> str:
        return self.config.interface

    def get(self, index: int) -> Host:
        try:
            return self.hosts[index]
        except IndexError as exc:
            raise SessionError(f"no host with id {index}") from exc

    def by_ip(self, ip: str) -> Host | None:
        return next((host for host in self.hosts if host.ip == ip), None)

    # -- lifecycle --------------------------------------------------------
    def start(self) -> bool:
        if self.config.dry_run:
            LOGGER.warning("dry-run: no traffic control, ARP or capture will be touched")
            self._running = True
            return True

        if not self.controller.setup():
            return False
        self.spoofer.start()
        self.monitor.start()
        self.watcher.start()
        self._running = True
        return True

    def shutdown(self) -> None:
        if not self._running:
            return
        self._running = False
        LOGGER.info("shutting down")

        self.watcher.stop()
        self.monitor.stop()
        self.spoofer.stop()
        if not self.config.dry_run:
            self.spoofer.restore_all()
            self.controller.teardown()
        for host in self.hosts:
            host.forget_control_state()
            host.spoofed = host.watched = False
        for thread in (self.monitor, self.watcher, self.spoofer):
            if thread.is_alive():
                thread.join(timeout=1.0)

    # -- discovery --------------------------------------------------------
    def scan(self, target: str | None = None, resolve_names: bool = True) -> list[Host]:
        addresses = self._resolve_targets(target) if target else self._addresses()
        if not addresses:
            raise SessionError("empty address range")

        try:
            found = self.scanner.scan(addresses, resolve_names=resolve_names)
        except Exception as exc:  # pragma: no cover - needs root/capabilities
            LOGGER.debug("ARP scan failed, falling back to the ARP cache: %s", exc)
            found = self.scanner.scan_from_cache(addresses)
            if not found:
                raise SessionError(
                    "scan needs root privileges (raw sockets). Run with sudo or use 'import'."
                ) from exc
            self.console.warn("raw scan unavailable, using the kernel ARP cache")
            resolve_names_for(found)

        # A successful but empty raw scan (e.g. AP client isolation or a
        # stale cache) should not silently leave us with zero hosts: probe the
        # LAN and re-read the kernel neighbour table before giving up.
        if not found:
            try:
                cached = self.scanner.scan_from_cache(addresses)
            except Exception:  # pragma: no cover - defensive
                cached = []
            if cached:
                found = cached
                self.console.warn("raw scan found nothing; using the kernel ARP cache")
                if resolve_names:
                    resolve_names_for(found)
            else:
                try:
                    from evilair.net.iface import ping_sweep  # noqa: PLC0415

                    self.console.info("warming up the ARP cache with a ping sweep…")
                    ping_sweep(self.config.network)
                    time.sleep(0.5)
                    found = self.scanner.scan_from_cache(addresses)
                    if found:
                        self.console.warn("raw scan found nothing; discovered via ping sweep")
                        if resolve_names:
                            resolve_names_for(found)
                except Exception as exc:  # pragma: no cover - network dependent
                    LOGGER.debug("ping sweep failed: %s", exc)

        if not found:
            self.console.warn(
                "no hosts detected; try 'import --probe' or check the interface/network"
            )

        self._merge(found)
        return self.hosts

    def import_from_cache(self, probe: bool = False) -> list[Host]:
        """Discover hosts without raw sockets.

        With ``probe`` the LAN is pinged first so the kernel ARP cache fills up,
        which makes root-free discovery genuinely useful.
        """
        if probe:
            from evilair.net.iface import ping_sweep  # noqa: PLC0415 - avoid cycle

            ping_sweep(self.config.network)
            time.sleep(0.5)

        found = self.scanner.scan_from_cache(self._addresses())
        resolve_names_for(found)
        self._merge(found)
        return self.hosts

    def add(self, ip: str, mac: str | None = None, name: str | None = None) -> Host:
        try:
            address = ipaddress.IPv4Address(ip)
        except ValueError as exc:
            raise SessionError(f"invalid IPv4 address: {ip}") from exc
        if address not in self.config.network and not self.config.dry_run:
            raise SessionError(f"{ip} is outside {self.config.network}")

        resolved_mac = mac
        if resolved_mac:
            try:
                resolved_mac = format_mac(resolved_mac)
            except ValueError as exc:
                raise SessionError(str(exc)) from exc
        else:
            found = self.scanner.scan([ip], resolve_names=False)
            if not found:
                cached = neighbour_table().get(ip)
                if cached is None:
                    raise SessionError(
                        f"could not resolve the MAC of {ip}; pass --mac"
                    )
                resolved_mac = cached
            else:
                resolved_mac = found[0].mac

        existing = self.by_ip(ip)
        if existing is not None:
            existing.mac = resolved_mac
            return existing

        host = Host(ip=ip, mac=resolved_mac, name=name or "")
        if not host.name:
            resolve_names_for([host])
        self.hosts.append(host)
        self._sort()
        return host

    def _merge(self, found: list[Host]) -> None:
        by_ip = {host.ip: host for host in self.hosts}
        for host in found:
            current = by_ip.get(host.ip)
            if current is None:
                self.hosts.append(host)
            else:
                current.mac = host.mac
                if host.name:
                    current.name = host.name
        self._sort()

    def _sort(self) -> None:
        self.hosts.sort(key=lambda host: tuple(int(part) for part in host.ip.split(".")))

    # -- target resolution ------------------------------------------------
    def _resolve_targets(self, target: str) -> list[str]:
        target = target.strip()
        if "/" in target or "-" in target:
            return self._expand_range(target)
        return [target]

    @staticmethod
    def _expand_range(target: str) -> list[str]:
        try:
            if "/" in target:
                return [str(host) for host in IPNetwork(target, strict=False).hosts()]
            start, _, end = target.partition("-")
            first = ipaddress.IPv4Address(start.strip())
            if not end.strip():
                raise SessionError(f"invalid range: {target}")
            second = ipaddress.IPv4Address(end.strip())
            return [str(ipaddress.IPv4Address(value)) for value in range(int(first), int(second) + 1)]
        except ValueError as exc:
            raise SessionError(f"invalid address range: {target}") from exc

    def select(self, reference: str) -> list[Host]:
        """Resolve ``all``, ids, ranges, IPs and MACs to hosts."""
        reference = (reference or "").strip()
        if not reference:
            raise SessionError("no host specified")
        if reference.lower() == "all":
            if not self.hosts:
                raise SessionError("no hosts discovered yet, run 'scan' first")
            return list(self.hosts)

        selected: list[Host] = []
        for token in reference.replace(" ", "").split(","):
            if not token:
                continue
            if token.isdigit():
                selected.append(self.get(int(token)))
                continue
            if "-" in token and all(part.isdigit() for part in token.split("-", 1)):
                start, end = (int(part) for part in token.split("-", 1))
                selected.extend(self.get(index) for index in range(start, end + 1))
                continue

            lowered = token.lower()
            match = next(
                (host for host in self.hosts if host.ip == token or host.mac == lowered),
                None,
            )
            if match is None:
                raise SessionError(f"no host matching '{token}' (run 'scan' first)")
            selected.append(match)

        unique: dict[str, Host] = {host.ip: host for host in selected}
        return list(unique.values())

    def bulk_targets(self, reference: str) -> list[Host]:
        """Resolve a target for a bulk action, protecting the gateway.

        ``all`` intentionally skips the gateway and this machine's own address
        for every bulk action (limit, block and free): shaping, spoofing or
        clearing either of them is never part of a structured bulk operation.
        An explicit id, IP or MAC still targets them when the user means it.
        """
        hosts = self.select(reference)
        if reference.strip().lower() != "all":
            return hosts

        skipped = sorted({host.ip for host in hosts if host.ip in self._protected})
        if skipped:
            self.console.warn("skipping gateway/local address: " + ", ".join(skipped))
        hosts = [host for host in hosts if host.ip not in self._protected]
        if not hosts:
            raise SessionError("nothing to control after skipping the gateway")
        return hosts

    # -- control ----------------------------------------------------------
    def limit(
        self,
        reference: str,
        rate: str | int | BitRate,
        direction: Direction,
        download_rate: str | int | BitRate | None = None,
    ) -> list[Host]:
        try:
            bitrate = BitRate.parse(rate)
        except ValueError as exc:
            raise SessionError(str(exc)) from exc
        if bitrate.bits_per_second < 1_000:
            raise SessionError("limit must be at least 1kbit")

        parsed_download = BitRate.parse(download_rate) if download_rate is not None else None
        hosts = self.bulk_targets(reference)
        for host in hosts:
            self._arm(host)
            self.controller.limit(host, direction, bitrate, parsed_download)
            self.monitor.watch(host)
        return hosts

    def block(self, reference: str, direction: Direction) -> list[Host]:
        hosts = self.bulk_targets(reference)
        for host in hosts:
            self._arm(host)
            self.controller.block(host, direction)
            self.monitor.watch(host)
        return hosts

    def _arm(self, host: Host) -> None:
        """Put ourselves between host and gateway (skipped in dry-run)."""
        if host.spoofed:
            return
        if self.config.dry_run:
            host.spoofed = True
            return
        self.spoofer.add(host)

    def free(self, reference: str) -> list[Host]:
        hosts = self.bulk_targets(reference)
        for host in hosts:
            self.controller.clear(host.ip)
            if host.spoofed:
                self.spoofer.remove(host, restore=not self.config.dry_run)
            self.monitor.unwatch(host)
            self.watcher.remove(host)
            host.forget_control_state()
        return hosts

    def watch(self, reference: str, enabled: bool = True) -> list[Host]:
        hosts = self.select(reference)
        for host in hosts:
            if enabled:
                self.watcher.add(host)
            else:
                self.watcher.remove(host)
        return hosts

    def _on_reconnect(self, old: Host, new: Host) -> None:
        """Migrate limits, monitoring and spoofing to the new address."""
        LOGGER.info("reconnect %s -> %s", old.ip, new.ip)
        self.controller.clear(old.ip)
        self.spoofer.remove(old, restore=False)
        self.monitor.rename(old.ip, new.ip)

        previous_up, previous_down = old.upload_limit, old.download_limit
        was_blocked = old.blocked
        replaced = False
        for index, host in enumerate(self.hosts):
            if host.ip == old.ip:
                self.hosts[index] = new
                replaced = True
                break
        if not replaced:
            self.hosts.append(new)

        if previous_up or previous_down:
            direction = Direction.NONE
            if previous_up:
                direction |= Direction.UPLOAD
            if previous_down:
                direction |= Direction.DOWNLOAD
            self.controller.limit(
                new,
                direction,
                BitRate(previous_up or previous_down or 0),
                BitRate(previous_down) if previous_down else None,
            )
        elif was_blocked:
            self.controller.block(new, Direction.BOTH)
        self.monitor.watch(new)
        self.spoofer.add(new)

    # -- reporting --------------------------------------------------------
    def snapshot(self) -> list[Host]:
        self.monitor.snapshot(self.hosts)
        return self.hosts

    def export(self, path: str, fmt: str = "json") -> Path:
        target = Path(path).expanduser()
        self.snapshot()
        rows = [
            {
                "ip": host.ip,
                "mac": host.mac,
                "hostname": host.name,
                "status": host.status(),
                "upload_limit_bps": host.upload_limit,
                "download_limit_bps": host.download_limit,
                "upload_total_bytes": host.traffic.upload_total,
                "download_total_bytes": host.traffic.download_total,
            }
            for host in self.hosts
        ]

        if fmt == "csv":
            with target.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else ["ip"])
                writer.writeheader()
                writer.writerows(rows)
        else:
            target.write_text(
                json.dumps(
                    {
                        "interface": self.config.interface,
                        "gateway": self.config.gateway_ip,
                        "network": str(self.config.network),
                        "hosts": rows,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
        return target


def build_config(
    interface: Interface,
    gateway_ip: str,
    gateway_mac: str,
    dry_run: bool = False,
) -> SessionConfig:
    return SessionConfig(
        interface=interface.name,
        gateway_ip=gateway_ip,
        gateway_mac=gateway_mac,
        network=interface.network,
        dry_run=dry_run,
    )


def discover_interface(name: str | None) -> Interface:
    iface = resolve_interface(name)
    if iface is None:
        raise SessionError(
            f"interface {name!r} is unknown or has no IPv4 address" if name else "no default IPv4 interface found"
        )
    return iface
