"""Human friendly parsing and formatting of bitrates and byte counters."""

from __future__ import annotations

import re
from dataclasses import dataclass

_BIT_UNITS = {
    "bit": 1,
    "bits": 1,
    "b": 1,
    "kbit": 1_000,
    "kbits": 1_000,
    "kbps": 1_000,
    "kb": 1_000,
    "mbit": 1_000_000,
    "mbits": 1_000_000,
    "mbps": 1_000_000,
    "mb": 1_000_000,
    "gbit": 1_000_000_000,
    "gbits": 1_000_000_000,
    "gbps": 1_000_000_000,
    "gb": 1_000_000_000,
}

_BYTE_UNITS = {
    "b": 1,
    "byte": 1,
    "bytes": 1,
    "kb": 1024,
    "kib": 1024,
    "mb": 1024**2,
    "mib": 1024**2,
    "gb": 1024**3,
    "gib": 1024**3,
    "tb": 1024**4,
    "tib": 1024**4,
}

_QUANTITY_RE = re.compile(r"^\s*(\d+(?:[.,]\d+)?)\s*([a-zA-Z]*)\s*$")


class RateFormatError(ValueError):
    """Raised when a human supplied value cannot be parsed."""


def _parse_quantity(value: str, units: dict[str, int], kind: str) -> int:
    match = _QUANTITY_RE.match(str(value))
    if match is None:
        raise RateFormatError(f"'{value}' is not a valid {kind} value")

    number, unit = match.group(1).replace(",", "."), match.group(2).lower()
    if unit == "":
        unit = "bit" if kind == "bitrate" else "b"
    if unit not in units:
        raise RateFormatError(
            f"unknown {kind} unit '{unit}', try one of: "
            + ", ".join(sorted(units))
        )
    return int(float(number) * units[unit])


@dataclass(frozen=True, order=True)
class BitRate:
    """A bandwidth value expressed in bits per second."""

    bits_per_second: int

    @classmethod
    def parse(cls, value: "str | int | BitRate") -> "BitRate":
        if isinstance(value, BitRate):
            return value
        if isinstance(value, (int, float)):
            return cls(int(value))
        return cls(_parse_quantity(value, _BIT_UNITS, "bitrate"))

    def __str__(self) -> str:
        return format_bitrate(self.bits_per_second)

    def tc_value(self) -> str:
        """Value understood by ``tc`` (always bits, SI prefixes)."""
        return f"{max(self.bits_per_second, 1)}bit"


@dataclass(frozen=True, order=True)
class ByteSize:
    """A data volume expressed in bytes."""

    bytes: int

    @classmethod
    def parse(cls, value: "str | int | ByteSize") -> "ByteSize":
        if isinstance(value, ByteSize):
            return value
        if isinstance(value, (int, float)):
            return cls(int(value))
        return cls(_parse_quantity(value, _BYTE_UNITS, "size"))

    def __str__(self) -> str:
        return format_bytes(self.bytes)

    def __add__(self, other: "ByteSize | int") -> "ByteSize":
        other = other if isinstance(other, ByteSize) else ByteSize(int(other))
        return ByteSize(self.bytes + other.bytes)

    def __sub__(self, other: "ByteSize | int") -> "ByteSize":
        other = other if isinstance(other, ByteSize) else ByteSize(int(other))
        return ByteSize(self.bytes - other.bytes)


def format_bitrate(bits_per_second: float) -> str:
    value = float(bits_per_second)
    for unit in ("bit", "kbit", "mbit", "gbit"):
        if abs(value) < 1000 or unit == "gbit":
            return f"{value:.0f}{unit}" if unit == "bit" else f"{value:.1f}{unit}"
        value /= 1000
    return f"{value:.1f}gbit"


def format_bytes(count: float) -> str:
    value = float(count)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1024 or unit == "TB":
            return f"{value:.0f}{unit}" if unit == "B" else f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}TB"


def format_mac(mac: str) -> str:
    """Normalise a MAC address to lower case colon notation."""
    digits = re.sub(r"[^0-9a-fA-F]", "", mac or "")
    if len(digits) != 12:
        raise ValueError(f"invalid MAC address: {mac!r}")
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2)).lower()
