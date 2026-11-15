import ipaddress
import unittest

from evilair.core.host import Host
from evilair.net.qos import Direction, TrafficController, delete_arguments, rule_matches
from evilair.util.rate import BitRate
from evilair.util.shell import CommandRunner, Result


def controller() -> tuple[TrafficController, CommandRunner]:
    runner = CommandRunner(dry_run=True)
    return TrafficController(runner, "eth0"), runner


def commands(runner: CommandRunner) -> list[list[str]]:
    return [list(result.command) for result in runner.history]


class DirectionTests(unittest.TestCase):
    def test_parse(self):
        self.assertIs(Direction.parse("up"), Direction.UPLOAD)
        self.assertIs(Direction.parse("download"), Direction.DOWNLOAD)
        self.assertIs(Direction.parse(None), Direction.BOTH)
        with self.assertRaises(ValueError):
            Direction.parse("sideways")

    def test_labels(self):
        self.assertEqual(Direction.BOTH.label(), "upload/download")


class SetupTests(unittest.TestCase):
    def test_setup_installs_default_class_and_forwarding(self):
        tc, runner = controller()
        self.assertTrue(tc.setup())
        issued = commands(runner)
        self.assertTrue(any(cmd[:3] == ["tc", "qdisc", "replace"] for cmd in issued))
        self.assertTrue(
            any("default" in cmd and "htb" in cmd for cmd in issued),
            "root qdisc must keep a default class so other hosts keep working",
        )
        self.assertTrue(any(cmd[:2] == ["sysctl", "-w"] for cmd in issued))
        self.assertIn("class", " ".join(issued[2]))

    def test_teardown_removes_qdisc_and_forwarding(self):
        tc, runner = controller()
        tc.setup()
        tc.teardown()
        issued = [" ".join(cmd) for cmd in commands(runner)]
        self.assertTrue(any("qdisc del dev eth0 root" in cmd for cmd in issued))
        self.assertTrue(any("ip_forward=0" in cmd for cmd in issued))


class LimitTests(unittest.TestCase):
    def test_limit_both_directions_shape_and_mark(self):
        tc, runner = controller()
        host = Host(ip="192.168.1.50", mac="aa:bb:cc:dd:ee:ff")
        tc.limit(host, Direction.BOTH, BitRate.parse("512kbit"))

        issued = [" ".join(cmd) for cmd in commands(runner)]
        self.assertTrue(any("classid 1:1" in cmd and "512000bit" in cmd for cmd in issued))
        self.assertTrue(any("classid 1:2" in cmd for cmd in issued))
        self.assertTrue(
            any(
                "mangle -A POSTROUTING -s 192.168.1.50" in cmd and "evilair:upload" in cmd
                for cmd in issued
            )
        )
        self.assertTrue(
            any(
                "mangle -A PREROUTING -d 192.168.1.50" in cmd and "evilair:download" in cmd
                for cmd in issued
            )
        )
        self.assertEqual(host.upload_limit, 512_000)
        self.assertEqual(host.download_limit, 512_000)
        self.assertEqual(host.status(), "limited")

    def test_limit_one_direction_only(self):
        tc, runner = controller()
        host = Host(ip="192.168.1.51", mac="aa:bb:cc:dd:ee:01")
        tc.limit(host, Direction.UPLOAD, BitRate.parse("1mbit"))
        self.assertIsNotNone(host.upload_limit)
        self.assertIsNone(host.download_limit)
        self.assertFalse(
            any("-A" in cmd and "PREROUTING" in cmd for cmd in commands(runner)),
            "download must not be marked when only upload is limited",
        )

    def test_ids_are_reused_after_release(self):
        tc, _ = controller()
        first = Host(ip="192.168.1.52", mac="aa:bb:cc:dd:ee:02")
        second = Host(ip="192.168.1.53", mac="aa:bb:cc:dd:ee:03")
        tc.limit(first, Direction.BOTH, BitRate.parse("1mbit"))
        tc.clear(first.ip)
        tc.limit(second, Direction.BOTH, BitRate.parse("1mbit"))
        rules = tc.active_rules()[second.ip]
        self.assertEqual(sorted(rules.used_ids()), [1, 2])

    def test_asymmetric_rates_are_honoured(self):
        tc, runner = controller()
        host = Host(ip="192.168.1.54", mac="aa:bb:cc:dd:ee:04")
        tc.limit(host, Direction.BOTH, BitRate.parse("1mbit"), BitRate.parse("256kbit"))
        self.assertEqual(host.upload_limit, 1_000_000)
        self.assertEqual(host.download_limit, 256_000)
        issued = [" ".join(cmd) for cmd in commands(runner)]
        self.assertTrue(any("256000bit" in cmd for cmd in issued))


class BlockTests(unittest.TestCase):
    def test_block_drops_forwarded_packets(self):
        tc, runner = controller()
        host = Host(ip="192.168.1.60", mac="aa:bb:cc:dd:ee:05")
        tc.block(host, Direction.BOTH)
        issued = [" ".join(cmd) for cmd in commands(runner)]
        self.assertTrue(any("-A FORWARD -s 192.168.1.60" in cmd and "DROP" in cmd for cmd in issued))
        self.assertTrue(any("-A FORWARD -d 192.168.1.60" in cmd and "DROP" in cmd for cmd in issued))
        self.assertTrue(host.blocked)
        self.assertEqual(host.status(), "blocked")

    def test_block_clears_previous_limit(self):
        tc, _ = controller()
        host = Host(ip="192.168.1.61", mac="aa:bb:cc:dd:ee:06")
        tc.limit(host, Direction.BOTH, BitRate.parse("1mbit"))
        tc.block(host, Direction.UPLOAD)
        self.assertFalse(host.limited)
        self.assertTrue(host.blocked_upload)

    def test_clear_is_idempotent(self):
        tc, runner = controller()
        tc.clear("10.0.0.1")
        tc.clear("10.0.0.1")
        host = Host(ip="10.0.0.2", mac="aa:bb:cc:dd:ee:07")
        tc.block(host, Direction.BOTH)
        tc.clear(host.ip)
        self.assertEqual(tc.active_blocks(), {})

    def test_rules_survive_only_until_clear(self):
        tc, _ = controller()
        host = Host(ip="192.168.1.62", mac="aa:bb:cc:dd:ee:08")
        tc.limit(host, Direction.BOTH, BitRate.parse("2mbit"))
        self.assertIn(host.ip, tc.active_rules())
        tc.clear(host.ip)
        self.assertNotIn(host.ip, tc.active_rules())
        tc.flush()
        self.assertEqual(tc.active_rules(), {})


class _FakeIptables:
    """Stateful stand-in for iptables that mimics ``-A``, ``-D`` and ``-S``."""

    def __init__(self) -> None:
        self.rules: dict[tuple[str, str], list[list[str]]] = {}
        self.commands: list[list[str]] = []

    @staticmethod
    def _is_ip(token: str) -> bool:
        try:
            ipaddress.IPv4Address(token)
            return True
        except ValueError:
            return False

    @classmethod
    def _normalise(cls, spec: list[str]) -> list[str]:
        return [part[:-3] if part.endswith("/32") and cls._is_ip(part[:-3]) else part for part in spec]

    def run(self, command, check: bool = False) -> Result:
        cmd = list(command)
        self.commands.append(cmd)
        if cmd[:2] == ["iptables", "-t"] and len(cmd) >= 5:
            table, action, chain = cmd[2], cmd[3], cmd[4]
            key = (table, chain)
            if action == "-A":
                self.rules.setdefault(key, []).append(cmd[5:])
            elif action == "-D":
                wanted = self._normalise(cmd[5:])
                bucket = self.rules.get(key, [])
                for index, spec in enumerate(bucket):
                    if self._normalise(spec) == wanted:
                        bucket.pop(index)
                        break
        return Result(command=tuple(cmd), returncode=0)

    def output(self, command: list[str]) -> str:
        table, chain = command[2], command[4]
        lines = []
        for spec in self.rules.get((table, chain), []):
            rendered: list[str] = []
            quote_next = False
            for token in spec:
                if quote_next:
                    rendered.append(f'"{token}"')
                    quote_next = False
                    continue
                if self._is_ip(token):
                    token += "/32"
                rendered.append(token)
                quote_next = token == "--comment"
            lines.append("-A " + chain + " " + " ".join(rendered))
        return "\n".join(lines)


class IptablesRuleParsingTests(unittest.TestCase):
    UPLOAD = (
        '-A POSTROUTING -s 192.168.1.50/32 -m comment --comment "evilair:upload" '
        "-j MARK --set-xmark 0x1/0xffffffff"
    )
    DROP = (
        '-A FORWARD -d 192.168.1.50/32 -m comment --comment "evilair:block:download" '
        "-j DROP"
    )

    def test_matches_rules_with_prefix_length(self):
        self.assertTrue(rule_matches(self.UPLOAD, ["-s", "192.168.1.50"], "MARK", "POSTROUTING"))
        self.assertTrue(rule_matches(self.UPLOAD, ["-s", "192.168.1.50/32"], "MARK"))
        self.assertFalse(rule_matches(self.UPLOAD, ["-s", "192.168.1.51"], "MARK"))
        self.assertFalse(rule_matches(self.UPLOAD, ["-d", "192.168.1.50"], "MARK"))
        self.assertFalse(rule_matches(self.UPLOAD, ["-s", "192.168.1.50"], "MARK", "PREROUTING"))

    def test_ignores_rules_without_our_comment(self):
        foreign = "-A POSTROUTING -s 10.0.0.1/32 -j MASQUERADE"
        self.assertFalse(rule_matches(foreign, ["-s", "10.0.0.1"], None))
        self.assertFalse(rule_matches(foreign, [], None, "POSTROUTING"))

    def test_delete_arguments_unquote_comment(self):
        argv = delete_arguments(self.UPLOAD)
        self.assertEqual(argv[0], "-D")
        self.assertIn("evilair:upload", argv)
        self.assertFalse(any('"evilair' in part for part in argv))


class IptablesCleanupTests(unittest.TestCase):
    def test_clear_removes_mark_rules_for_host(self):
        runner = _FakeIptables()
        controller = TrafficController(runner, "eth0")
        host = Host(ip="192.168.1.50", mac="aa:bb:cc:dd:ee:ff")
        controller.limit(host, Direction.BOTH, BitRate.parse("1mbit"))
        self.assertEqual(len(runner.rules.get(("mangle", "POSTROUTING"), [])), 1)
        self.assertEqual(len(runner.rules.get(("mangle", "PREROUTING"), [])), 1)

        controller.clear(host.ip)
        self.assertEqual(runner.rules.get(("mangle", "POSTROUTING")), [])
        self.assertEqual(runner.rules.get(("mangle", "PREROUTING")), [])

        deleted = [cmd for cmd in runner.commands if cmd[:4] == ["iptables", "-t", "mangle", "-D"]]
        self.assertEqual(len(deleted), 2)
        self.assertTrue(any("evilair:upload" in cmd for cmd in deleted))
        self.assertTrue(any("evilair:download" in cmd for cmd in deleted))
        self.assertFalse(any(any('"evilair' in part for part in cmd) for cmd in deleted))

    def test_clear_after_block_removes_drop_rule(self):
        runner = _FakeIptables()
        controller = TrafficController(runner, "eth0")
        host = Host(ip="192.168.1.60", mac="aa:bb:cc:dd:ee:05")
        controller.block(host, Direction.UPLOAD)
        self.assertEqual(len(runner.rules.get(("filter", "FORWARD"), [])), 1)

        controller.clear(host.ip)
        self.assertEqual(runner.rules.get(("filter", "FORWARD")), [])
        deleted = [cmd for cmd in runner.commands if cmd[:4] == ["iptables", "-t", "filter", "-D"]]
        self.assertEqual(len(deleted), 1)
        self.assertIn("evilair:block:upload", deleted[0])

    def test_flush_deletes_all_tagged_rules(self):
        runner = _FakeIptables()
        controller = TrafficController(runner, "eth0")
        controller.limit(Host(ip="192.168.1.70", mac="aa:bb:cc:dd:ee:06"), Direction.BOTH, BitRate.parse("1mbit"))
        controller.block(Host(ip="192.168.1.71", mac="aa:bb:cc:dd:ee:07"), Direction.BOTH)

        controller.flush()
        self.assertEqual({key: value for key, value in runner.rules.items() if value}, {})


if __name__ == "__main__":
    unittest.main()
