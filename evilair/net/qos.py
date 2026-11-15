"""Traffic shaping (HTB) and filtering (iptables) per host.

Every rule this module creates carries a ``evilair`` comment or a private class
id, which makes removal deterministic - no matter how the process exited.
"""

from __future__ import annotations

import logging
import shlex
from dataclasses import dataclass
from enum import IntFlag

from evilair.core.host import Host
from evilair.util.rate import BitRate
from evilair.util.shell import CommandRunner

LOGGER = logging.getLogger("evilair.qos")

ROOT_HANDLE = "1:0"
DEFAULT_CLASS = 30
DEFAULT_CLASS_RATE = "10gbit"
COMMENT_PREFIX = "evilair"
IP_FORWARD = "/proc/sys/net/ipv4/ip_forward"


def rule_tokens(line: str) -> list[str]:
    """Split an ``iptables -S`` line, removing the quotes iptables adds."""
    return shlex.split(line)


def _token_matches(token: str, part: str) -> bool:
    # ``iptables -S`` renders single hosts with a /32 suffix, so compare the
    # address part as well as the literal token.
    return token == part or token.split("/", 1)[0] == part


def rule_matches(
    line: str, match: list[str], jump: str | None, chain: str | None = None
) -> bool:
    """Return True when an ``iptables -S`` line is one of this tool's rules."""
    tokens = rule_tokens(line)
    if len(tokens) < 2 or tokens[0] != "-A":
        return False
    if chain is not None and tokens[1] != chain:
        return False
    if not any(COMMENT_PREFIX in token for token in tokens):
        return False
    if jump is not None and jump not in tokens:
        return False
    return all(any(_token_matches(token, part) for token in tokens) for part in match)


def delete_arguments(line: str) -> list[str]:
    """Turn an ``iptables -S`` rule into an equivalent ``-D`` argument list.

    The comment value is re-tokenised with :func:`shlex.split`, otherwise the
    quotes printed by ``iptables -S`` would be passed literally and the delete
    request would not match the installed rule.
    """
    tokens = rule_tokens(line)
    if not tokens or tokens[0] != "-A":
        return []
    tokens[0] = "-D"
    return tokens


class Direction(IntFlag):
    NONE = 0
    UPLOAD = 1
    DOWNLOAD = 2
    BOTH = UPLOAD | DOWNLOAD

    @classmethod
    def parse(cls, value: str | None) -> "Direction":
        if value is None:
            return cls.BOTH
        value = value.strip().lower()
        if value in {"up", "upload", "out", "outgoing"}:
            return cls.UPLOAD
        if value in {"down", "download", "in", "incoming"}:
            return cls.DOWNLOAD
        if value in {"both", "all", "updown", "up/down"}:
            return cls.BOTH
        raise ValueError(f"unknown direction: {value!r}")

    def label(self) -> str:
        if self is Direction.UPLOAD:
            return "upload"
        if self is Direction.DOWNLOAD:
            return "download"
        return "upload/download"


@dataclass
class HostRules:
    upload_id: int | None = None
    download_id: int | None = None

    def used_ids(self) -> list[int]:
        return [i for i in (self.upload_id, self.download_id) if i is not None]


class TrafficController:
    """Applies and reverts bandwidth limits and blocks."""

    def __init__(self, runner: CommandRunner, interface: str) -> None:
        self.runner = runner
        self.interface = interface
        self._rules: dict[str, HostRules] = {}
        self._blocks: dict[str, set[Direction]] = {}

    # -- lifecycle --------------------------------------------------------
    def setup(self) -> bool:
        """Install the root qdisc with an unlimited default class."""
        self.runner.require("tc", "iptables")
        self._enable_ip_forwarding()

        if not self._tc("qdisc", "replace", "dev", self.interface, "root", "handle", "1:", "htb", "default", str(DEFAULT_CLASS)):
            LOGGER.error("could not install the root qdisc on %s", self.interface)
            return False

        self._tc(
            "class", "replace", "dev", self.interface, "parent", ROOT_HANDLE,
            "classid", f"1:{DEFAULT_CLASS}", "htb", "rate", DEFAULT_CLASS_RATE,
            "ceil", DEFAULT_CLASS_RATE,
        )
        # Unmanaged traffic keeps flowing through the default class.
        self._tc(
            "filter", "replace", "dev", self.interface, "parent", ROOT_HANDLE,
            "protocol", "ip", "prio", "10", "u32", "match", "u32", "0", "0",
            "flowid", f"1:{DEFAULT_CLASS}",
        )
        return True

    def teardown(self) -> None:
        """Remove every remnant of this tool and re-enable normal routing."""
        self.flush()
        self._tc("qdisc", "del", "dev", self.interface, "root")
        self._disable_ip_forwarding()

    def flush(self) -> None:
        for ip in list(self._rules):
            self.clear(ip)
        for ip in list(self._blocks):
            self.clear(ip)
        self._delete_tagged_iptables_rules()
        self._rules.clear()
        self._blocks.clear()

    # -- public operations ------------------------------------------------
    def limit(
        self,
        host: Host,
        direction: Direction,
        rate: BitRate,
        download_rate: BitRate | None = None,
    ) -> None:
        self.clear(host.ip)
        rules = HostRules()
        allocated = {i for entry in self._rules.values() for i in entry.used_ids()}

        def take_id() -> int:
            candidate = 1
            while candidate in allocated:
                candidate += 1
            allocated.add(candidate)
            return candidate

        if direction & Direction.UPLOAD:
            rules.upload_id = take_id()
            self._shape(host, rules.upload_id, rate, outgoing=True)
            host.upload_limit = rate.bits_per_second

        if direction & Direction.DOWNLOAD:
            rules.download_id = take_id()
            self._shape(host, rules.download_id, download_rate or rate, outgoing=False)
            host.download_limit = (download_rate or rate).bits_per_second

        self._rules[host.ip] = rules
        host.blocked_upload = host.blocked_download = False

    def block(self, host: Host, direction: Direction) -> None:
        self.clear(host.ip)
        blocked = Direction.NONE

        if direction & Direction.UPLOAD:
            self.runner.run(
                [
                    "iptables", "-t", "filter", "-A", "FORWARD",
                    "-s", host.ip, "-m", "comment",
                    "--comment", f"{COMMENT_PREFIX}:block:upload",
                    "-j", "DROP",
                ]
            )
            blocked |= Direction.UPLOAD
            host.blocked_upload = True

        if direction & Direction.DOWNLOAD:
            self.runner.run(
                [
                    "iptables", "-t", "filter", "-A", "FORWARD",
                    "-d", host.ip, "-m", "comment",
                    "--comment", f"{COMMENT_PREFIX}:block:download",
                    "-j", "DROP",
                ]
            )
            blocked |= Direction.DOWNLOAD
            host.blocked_download = True

        self._blocks[host.ip] = blocked
        host.upload_limit = host.download_limit = None

    def clear(self, ip: str) -> None:
        """Remove shaping and blocking rules for a single address."""
        rules = self._rules.pop(ip, None)
        if rules is not None:
            for class_id in rules.used_ids():
                self._tc("filter", "del", "dev", self.interface, "parent", ROOT_HANDLE, "prio", str(class_id))
                self._tc("class", "del", "dev", self.interface, "parent", ROOT_HANDLE, "classid", f"1:{class_id}")

        blocks = self._blocks.pop(ip, None)
        if blocks is not None:
            self._delete_iptables_rule(
                "mangle", "PREROUTING", ["-d", ip], jump="MARK"
            )
            self._delete_iptables_rule(
                "mangle", "POSTROUTING", ["-s", ip], jump="MARK"
            )
            for direction in (Direction.UPLOAD, Direction.DOWNLOAD):
                if blocks & direction:
                    chain_key = "-s" if direction is Direction.UPLOAD else "-d"
                    self._delete_iptables_rule(
                        "filter", "FORWARD", [chain_key, ip], jump="DROP"
                    )
        else:
            # Limits also leave marks behind.
            self._delete_iptables_rule("mangle", "PREROUTING", ["-d", ip], jump="MARK")
            self._delete_iptables_rule("mangle", "POSTROUTING", ["-s", ip], jump="MARK")

    # -- internals --------------------------------------------------------
    def _shape(self, host: Host, class_id: int, rate: BitRate, outgoing: bool) -> None:
        burst = max(rate.bits_per_second // 8, 10_000)
        self._tc(
            "class", "replace", "dev", self.interface, "parent", ROOT_HANDLE,
            "classid", f"1:{class_id}", "htb",
            "rate", rate.tc_value(), "ceil", rate.tc_value(),
            "burst", str(burst), "cburst", str(burst),
        )
        self._tc(
            "filter", "replace", "dev", self.interface, "parent", ROOT_HANDLE,
            "protocol", "ip", "prio", str(class_id), "handle", str(class_id),
            "fw", "flowid", f"1:{class_id}",
        )

        chain, address_flag, tag = (
            ("POSTROUTING", "-s", "upload") if outgoing else ("PREROUTING", "-d", "download")
        )
        self.runner.run(
            [
                "iptables", "-t", "mangle", "-A", chain,
                address_flag, host.ip, "-m", "comment",
                "--comment", f"{COMMENT_PREFIX}:{tag}",
                "-j", "MARK", "--set-mark", str(class_id),
            ]
        )

    def _tc(self, *args: str) -> bool:
        result = self.runner.run(["tc", *args])
        return result.ok

    def _delete_iptables_rule(
        self, table: str, chain: str, match: list[str], jump: str
    ) -> None:
        """Delete rules matching ``match`` until none are left (idempotent)."""
        for _ in range(8):
            listing = self.runner.output(["iptables", "-t", table, "-S", chain])
            spec = [
                line for line in listing.splitlines()
                if rule_matches(line, match, jump, chain)
            ]
            if not spec:
                return
            argv = delete_arguments(spec[0])
            if not argv or not self.runner.run(["iptables", "-t", table, *argv]).ok:
                LOGGER.warning("could not delete iptables rule: %s", spec[0])
                return

    def _delete_tagged_iptables_rules(self) -> None:
        for table, chain in (("mangle", "PREROUTING"), ("mangle", "POSTROUTING"), ("filter", "FORWARD")):
            for _ in range(64):
                listing = self.runner.output(["iptables", "-t", table, "-S", chain])
                spec = [
                    line for line in listing.splitlines()
                    if rule_matches(line, [], None, chain)
                ]
                if not spec:
                    break
                argv = delete_arguments(spec[0])
                if not argv or not self.runner.run(["iptables", "-t", table, *argv]).ok:
                    LOGGER.warning("could not delete iptables rule: %s", spec[0])
                    break

    def _enable_ip_forwarding(self) -> None:
        result = self.runner.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        if not result.ok:
            self.runner.run(["sh", "-c", f"echo 1 > {IP_FORWARD}"], check=False)

    def _disable_ip_forwarding(self) -> None:
        result = self.runner.run(["sysctl", "-w", "net.ipv4.ip_forward=0"])
        if not result.ok:
            self.runner.run(["sh", "-c", f"echo 0 > {IP_FORWARD}"], check=False)

    # -- introspection ----------------------------------------------------
    def active_rules(self) -> dict[str, HostRules]:
        return dict(self._rules)

    def active_blocks(self) -> dict[str, set[Direction]]:
        return {ip: set(flags) for ip, flags in self._blocks.items()}
