"""Watches managed devices for reconnections (same MAC, new IP)."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Callable

from evilair.core.host import Host
from evilair.net.arp import ARPScanner
from evilair.util.rate import format_mac

LOGGER = logging.getLogger("evilair.watch")


@dataclass
class Reconnect:
    old: Host
    new: Host
    at: float


class HostWatcher(threading.Thread):
    """Periodically rescans and reports hosts that changed address."""

    def __init__(
        self,
        scanner: ARPScanner,
        targets: list[str],
        on_reconnect: Callable[[Host, Host], None],
        interval: float = 45.0,
    ) -> None:
        super().__init__(name="evilair-watcher", daemon=True)
        self._scanner = scanner
        self._targets = list(targets)
        self._on_reconnect = on_reconnect
        self._interval = interval
        self._hosts: dict[str, Host] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.history: list[Reconnect] = []

    # -- config -----------------------------------------------------------
    @property
    def interval(self) -> float:
        return self._interval

    @interval.setter
    def interval(self, value: float) -> None:
        self._interval = max(float(value), 5.0)

    @property
    def targets(self) -> list[str]:
        return list(self._targets)

    @targets.setter
    def targets(self, values: list[str]) -> None:
        self._targets = list(values)

    @property
    def watched(self) -> list[Host]:
        with self._lock:
            return list(self._hosts.values())

    # -- registration -----------------------------------------------------
    def add(self, host: Host) -> None:
        with self._lock:
            self._hosts[host.ip] = host
        host.watched = True

    def remove(self, host: Host) -> None:
        with self._lock:
            self._hosts.pop(host.ip, None)
        host.watched = False

    def replace(self, old_ip: str, new_host: Host) -> None:
        """Swap a watched host for its new address without mutating either one."""
        with self._lock:
            self._hosts.pop(old_ip, None)
            self._hosts[new_host.ip] = new_host
        new_host.watched = True

    # -- thread -----------------------------------------------------------
    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.wait(self._interval):
            with self._lock:
                hosts = list(self._hosts.values())
            if not hosts or not self._targets:
                continue
            try:
                self._check(hosts)
            except Exception as exc:  # pragma: no cover - network dependent
                LOGGER.debug("watch cycle failed: %s", exc)

    def _check(self, hosts: list[Host]) -> None:
        scanned = self._scanner.scan(self._targets, resolve_names=False)
        by_mac = {host.mac: host for host in scanned}
        for host in hosts:
            match = by_mac.get(format_mac(host.mac))
            if match is None or match.ip == host.ip:
                continue
            LOGGER.info("host %s reconnected as %s", host.ip, match.ip)
            match.name = host.name or match.name
            self.replace(host.ip, match)
            self.history.append(Reconnect(old=host, new=match, at=time.time()))
            self._on_reconnect(host, match)
