"""Per-host bandwidth accounting by sniffing the managed interface."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

from evilair.core.host import Host, TrafficSnapshot

LOGGER = logging.getLogger("evilair.monitor")


@dataclass
class Counters:
    upload_bytes: int = 0
    download_bytes: int = 0
    upload_packets: int = 0
    download_packets: int = 0


class BandwidthMonitor(threading.Thread):
    """Sniffs traffic and turns byte counters into smoothed rates."""

    def __init__(self, interface: str, smoothing: float = 0.4) -> None:
        super().__init__(name="evilair-monitor", daemon=True)
        self.interface = interface
        self.smoothing = smoothing

        self._lock = threading.Lock()
        self._watched: set[str] = set()
        self._counters: dict[str, Counters] = {}
        self._rates: dict[str, tuple[float, float]] = {}
        self._last_bytes: dict[str, tuple[int, int]] = {}
        self._last_sample = time.monotonic()
        self._stop = threading.Event()
        self._available = True

    # -- registration -----------------------------------------------------
    def watch(self, host: Host) -> None:
        with self._lock:
            self._watched.add(host.ip)
            self._counters.setdefault(host.ip, Counters())

    def unwatch(self, host: Host) -> None:
        with self._lock:
            self._watched.discard(host.ip)
            self._counters.pop(host.ip, None)
            self._rates.pop(host.ip, None)
            self._last_bytes.pop(host.ip, None)

    def rename(self, old_ip: str, new_ip: str) -> None:
        """Keep counters when a watched device changes address."""
        with self._lock:
            if old_ip in self._watched:
                self._watched.discard(old_ip)
                self._watched.add(new_ip)
            counters = self._counters.pop(old_ip, None)
            if counters is not None:
                self._counters[new_ip] = counters
            rates = self._rates.pop(old_ip, None)
            if rates is not None:
                self._rates[new_ip] = rates
            seen = self._last_bytes.pop(old_ip, None)
            if seen is not None:
                self._last_bytes[new_ip] = seen

    @property
    def available(self) -> bool:
        return self._available

    # -- thread -----------------------------------------------------------
    def run(self) -> None:
        from scapy.all import IP, sniff  # noqa: PLC0415

        def handle(packet) -> None:
            if not packet.haslayer(IP):
                return
            layer = packet[IP]
            size = len(packet)
            with self._lock:
                if layer.src in self._watched:
                    counters = self._counters.setdefault(layer.src, Counters())
                    counters.upload_bytes += size
                    counters.upload_packets += 1
                if layer.dst in self._watched:
                    counters = self._counters.setdefault(layer.dst, Counters())
                    counters.download_bytes += size
                    counters.download_packets += 1

        try:
            sniff(
                iface=self.interface,
                filter="ip",
                prn=handle,
                store=False,
                stop_filter=lambda *_: self._stop.is_set(),
            )
        except Exception as exc:  # pragma: no cover - depends on privileges
            self._available = False
            LOGGER.warning("packet capture unavailable: %s", exc)

    def stop(self) -> None:
        self._stop.set()

    # -- sampling ---------------------------------------------------------
    def snapshot(self, hosts: list[Host] | None = None) -> dict[str, TrafficSnapshot]:
        now = time.monotonic()
        with self._lock:
            elapsed = max(now - self._last_sample, 0.001)
            self._last_sample = now
            result: dict[str, TrafficSnapshot] = {}
            for ip, counters in self._counters.items():
                previous_up, previous_down = self._rates.get(ip, (0.0, 0.0))
                last_up, last_down = self._last_bytes.get(ip, (counters.upload_bytes, counters.download_bytes))
                delta_up = max(counters.upload_bytes - last_up, 0)
                delta_down = max(counters.download_bytes - last_down, 0)
                self._last_bytes[ip] = (counters.upload_bytes, counters.download_bytes)

                raw_up = delta_up * 8 / elapsed
                raw_down = delta_down * 8 / elapsed
                up = previous_up + self.smoothing * (raw_up - previous_up)
                down = previous_down + self.smoothing * (raw_down - previous_down)
                self._rates[ip] = (up, down)
                result[ip] = TrafficSnapshot(
                    upload_rate=up,
                    download_rate=down,
                    upload_total=counters.upload_bytes,
                    download_total=counters.download_bytes,
                    upload_packets=counters.upload_packets,
                    download_packets=counters.download_packets,
                )
            for ip in list(self._rates):
                if ip not in self._counters:
                    del self._rates[ip]

        if hosts is not None:
            for host in hosts:
                host.traffic = result.get(host.ip, TrafficSnapshot())
        return result
