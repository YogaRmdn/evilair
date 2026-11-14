"""The host model shared by the scanner, controller and UI."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from evilair.util.rate import format_bitrate


@dataclass
class TrafficSnapshot:
    upload_rate: float = 0.0
    download_rate: float = 0.0
    upload_total: int = 0
    download_total: int = 0
    upload_packets: int = 0
    download_packets: int = 0


@dataclass
class Host:
    """A device discovered on the local network."""

    ip: str
    mac: str
    name: str = ""
    vendor: str = ""
    first_seen: float = field(default_factory=time.time)

    upload_limit: int | None = None
    download_limit: int | None = None
    blocked_upload: bool = False
    blocked_download: bool = False
    spoofed: bool = False
    watched: bool = False

    traffic: TrafficSnapshot = field(default_factory=TrafficSnapshot)

    # -- identity ---------------------------------------------------------
    @property
    def key(self) -> str:
        return self.ip

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Host):
            return NotImplemented
        return self.ip == other.ip

    def __hash__(self) -> int:
        return hash(self.ip)

    def __str__(self) -> str:
        return f"{self.ip} ({self.mac})"

    # -- state ------------------------------------------------------------
    @property
    def limited(self) -> bool:
        return self.upload_limit is not None or self.download_limit is not None

    @property
    def blocked(self) -> bool:
        return self.blocked_upload or self.blocked_download

    @property
    def managed(self) -> bool:
        return self.limited or self.blocked

    def status(self) -> str:
        if self.blocked and self.limited:
            return "limited+blocked"
        if self.blocked:
            return "blocked"
        if self.limited:
            return "limited"
        return "free"

    def limit_summary(self) -> str:
        parts: list[str] = []
        if self.upload_limit is not None:
            parts.append(f"up {format_bitrate(self.upload_limit)}")
        if self.download_limit is not None:
            parts.append(f"down {format_bitrate(self.download_limit)}")
        return ", ".join(parts)

    def forget_control_state(self) -> None:
        self.upload_limit = None
        self.download_limit = None
        self.blocked_upload = False
        self.blocked_download = False
