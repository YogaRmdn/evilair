"""Network interface, gateway and neighbour discovery.

Uses ``netifaces`` for the fast path and falls back to ``ip`` from iproute2,
so the tool still works on minimal systems.
"""

from __future__ import annotations

import ipaddress
import shutil
import socket
import subprocess
from dataclasses import dataclass

from evilair.util.rate import format_mac

IPAddress = ipaddress.IPv4Address
IPNetwork = ipaddress.IPv4Network


@dataclass(frozen=True)
class Interface:
    name: str
    address: IPAddress
    network: IPNetwork
    mac: str

    @property
    def netmask(self) -> str:
        return str(self.network.netmask)

    @property
    def prefixlen(self) -> int:
        return self.network.prefixlen


@dataclass(frozen=True)
class Gateway:
    ip: IPAddress
    mac: str | None = None


def _run(*argv: str) -> str:
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, check=False)
    except (OSError, ValueError):
        return ""
    return completed.stdout if completed.returncode == 0 else ""


def list_interfaces() -> list[str]:
    """Return names of all IPv4 capable interfaces."""
    try:
        import netifaces  # noqa: PLC0415 - optional dependency
    except ImportError:
        netifaces = None

    if netifaces is not None:
        return [
            name
            for name in netifaces.interfaces()
            if netifaces.AF_INET in netifaces.ifaddresses(name)
        ]

    names: list[str] = []
    for line in _run("ip", "-o", "-4", "addr", "show").splitlines():
        parts = line.split()
        if len(parts) > 1 and parts[1] not in names:
            names.append(parts[1])
    return names


def get_default_interface_name() -> str | None:
    try:
        import netifaces  # noqa: PLC0415

        gateways = netifaces.gateways()
        default = gateways.get("default", {})
        if netifaces.AF_INET in default:
            return default[netifaces.AF_INET][1]
    except ImportError:
        pass

    route = _run("ip", "-4", "route", "show", "default")
    for line in route.splitlines():
        parts = line.split()
        if "dev" in parts:
            index = parts.index("dev")
            if index + 1 < len(parts):
                return parts[index + 1]
    return None


def get_default_gateway_ip() -> str | None:
    try:
        import netifaces  # noqa: PLC0415

        default = netifaces.gateways().get("default", {})
        if netifaces.AF_INET in default:
            return default[netifaces.AF_INET][0]
    except ImportError:
        pass

    route = _run("ip", "-4", "route", "show", "default")
    for line in route.splitlines():
        parts = line.split()
        if "via" in parts:
            index = parts.index("via")
            if index + 1 < len(parts):
                return parts[index + 1]
    return None


def describe_interface(name: str) -> Interface | None:
    """Build an :class:`Interface` for ``name`` (``None`` when unusable)."""
    try:
        import netifaces  # noqa: PLC0415
    except ImportError:
        netifaces = None

    if netifaces is not None:
        if name not in netifaces.interfaces():
            return None
        addresses = netifaces.ifaddresses(name)
        inet = addresses.get(netifaces.AF_INET)
        if not inet:
            return None
        link = addresses.get(netifaces.AF_LINK) or [{}]
        address = inet[0].get("addr")
        netmask = inet[0].get("netmask", "255.255.255.0")
        mac = (link[0].get("addr") or "00:00:00:00:00:00").lower()
    else:
        output = _run("ip", "-o", "-4", "addr", "show", "dev", name)
        if not output:
            return None
        parts = output.split()
        cidr = next((part for part in parts if "/" in part and part[0].isdigit()), None)
        if cidr is None:
            return None
        address, _, prefix = cidr.partition("/")
        netmask = str(IPNetwork(f"{address}/{prefix}").netmask)
        mac = (_run("cat", f"/sys/class/net/{name}/address") or "00:00:00:00:00:00").strip()

    try:
        iface_address = IPAddress(address)
        network = IPNetwork(f"{address}/{netmask}", strict=False)
    except ValueError:
        return None

    try:
        mac = format_mac(mac)
    except ValueError:
        mac = "00:00:00:00:00:00"

    return Interface(name=name, address=iface_address, network=network, mac=mac)


def resolve_interface(name: str | None = None) -> Interface | None:
    if name:
        return describe_interface(name)
    default = get_default_interface_name()
    return describe_interface(default) if default else None


def interface_mac(name: str) -> str | None:
    iface = describe_interface(name)
    if iface is not None and iface.mac != "00:00:00:00:00:00":
        return iface.mac
    try:
        from evilair.net.arp import get_if_hwaddr  # noqa: PLC0415

        return format_mac(get_if_hwaddr(name))
    except Exception:  # pragma: no cover - depends on driver support
        return None


def neighbour_table() -> dict[str, str]:
    """Read the kernel ARP cache (``ip neigh``) - works without root."""
    table: dict[str, str] = {}
    for line in _run("ip", "-4", "neigh", "show").splitlines():
        parts = line.split()
        if len(parts) < 5 or "lladdr" not in parts:
            continue
        ip, state = parts[0], parts[-1]
        if state.upper() in {"FAILED", "INCOMPLETE"}:
            continue
        mac = parts[parts.index("lladdr") + 1]
        try:
            table[ip] = format_mac(mac)
        except ValueError:
            continue
    return table


def reverse_dns(ip: str, timeout: float = 0.75) -> str:
    """Best effort reverse lookup that never blocks for long."""
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError, UnicodeError):
        return ""
    finally:
        socket.setdefaulttimeout(None)


def ping_sweep(network: IPNetwork, timeout: float = 0.2, workers: int = 64) -> list[str]:
    """Cheap reachability probe used to warm up the ARP cache without root."""
    from concurrent.futures import ThreadPoolExecutor

    if shutil.which("ping") is None:
        return []

    hosts = [str(host) for host in network.hosts()]
    if len(hosts) > 1024:
        hosts = hosts[:1024]

    def probe(host: str) -> str | None:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), host],
            capture_output=True,
            check=False,
        )
        return host if result.returncode == 0 else None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return [host for host in pool.map(probe, hosts) if host]
