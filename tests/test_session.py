import ipaddress
import unittest

from evilair.core.host import Host
from evilair.net.qos import Direction
from evilair.session import Session, SessionConfig, SessionError
from evilair.ui.console import Console


class SessionSelectionTests(unittest.TestCase):
    def setUp(self):
        config = SessionConfig(
            interface="lo",
            gateway_ip="192.168.1.1",
            gateway_mac="11:22:33:44:55:66",
            network=ipaddress.IPv4Network("192.168.1.0/24"),
            dry_run=True,
        )
        self.console = Console(quiet=True)
        self.session = Session(config, self.console)
        self.session.hosts = [
            Host(ip="192.168.1.10", mac="aa:aa:aa:aa:aa:01", name="laptop"),
            Host(ip="192.168.1.11", mac="aa:aa:aa:aa:aa:02", name="phone"),
            Host(ip="192.168.1.12", mac="aa:aa:aa:aa:aa:03", name="tv"),
        ]

    def test_select_by_index_ip_mac_and_all(self):
        self.assertEqual(self.session.select("1")[0].ip, "192.168.1.11")
        self.assertEqual(self.session.select("192.168.1.12")[0].name, "tv")
        self.assertEqual(self.session.select("AA:AA:AA:AA:AA:01")[0].name, "laptop")
        self.assertEqual(len(self.session.select("all")), 3)

    def test_select_by_range(self):
        selected = self.session.select("0-1")
        self.assertEqual([host.ip for host in selected], ["192.168.1.10", "192.168.1.11"])

    def test_select_rejects_unknown(self):
        with self.assertRaises(SessionError):
            self.session.select("9")
        with self.assertRaises(SessionError):
            self.session.select("10.0.0.1")

    def test_deduplicates(self):
        self.assertEqual(len(self.session.select("0,0,192.168.1.10")), 1)

    def test_limit_records_state_without_touching_the_network(self):
        hosts = self.session.limit("0", "256kbit", Direction.BOTH)
        host = hosts[0]
        self.assertEqual(host.upload_limit, 256_000)
        self.assertEqual(host.download_limit, 256_000)
        self.assertTrue(host.spoofed)

    def test_limit_rejects_bad_rate(self):
        with self.assertRaises(SessionError):
            self.session.limit("0", "ten", Direction.BOTH)
        with self.assertRaises(SessionError):
            self.session.limit("0", "10bit", Direction.BOTH)

    def test_free_resets_state(self):
        self.session.limit("all", "1mbit", Direction.BOTH)
        self.session.free("all")
        for host in self.session.hosts:
            self.assertFalse(host.managed)
            self.assertFalse(host.spoofed)

    def test_watch_toggles_flag(self):
        self.session.watch("0", True)
        self.assertTrue(self.session.hosts[0].watched)
        self.session.watch("0", False)
        self.assertFalse(self.session.hosts[0].watched)

    def test_expand_range(self):
        self.assertEqual(len(Session._expand_range("192.168.1.0/30")), 2)
        self.assertEqual(Session._expand_range("10.0.0.1-10.0.0.3")[2], "10.0.0.3")

    def test_export_json(self):
        import json
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "hosts.json"
            self.session.export(str(target))
            payload = json.loads(target.read_text())
            self.assertEqual(payload["interface"], "lo")
            self.assertEqual(len(payload["hosts"]), 3)
            self.assertEqual(payload["hosts"][0]["ip"], "192.168.1.10")

    def _with_gateway(self):
        gateway = Host(ip="192.168.1.1", mac="00:11:22:33:44:55")
        self.session.hosts.insert(0, gateway)
        return gateway

    def test_bulk_block_skips_gateway(self):
        gateway = self._with_gateway()
        blocked = self.session.block("all", Direction.BOTH)
        self.assertNotIn(gateway, blocked)
        self.assertFalse(gateway.managed)
        self.assertTrue(all(host.blocked for host in blocked))

    def test_bulk_limit_skips_gateway(self):
        gateway = self._with_gateway()
        limited = self.session.limit("all", "1mbit", Direction.BOTH)
        self.assertNotIn(gateway, limited)
        self.assertFalse(gateway.limited)

    def test_gateway_can_still_be_targeted_explicitly(self):
        gateway = self._with_gateway()
        self.session.block("192.168.1.1", Direction.BOTH)
        self.assertTrue(gateway.blocked)

    def test_free_all_skips_gateway(self):
        gateway = self._with_gateway()
        self.session.block("192.168.1.1", Direction.BOTH)
        freed = self.session.free("all")
        self.assertNotIn(gateway, freed)
        self.assertTrue(gateway.blocked)

    def test_gateway_can_be_freed_explicitly(self):
        gateway = self._with_gateway()
        self.session.block("192.168.1.1", Direction.BOTH)
        freed = self.session.free("192.168.1.1")
        self.assertIn(gateway, freed)
        self.assertFalse(gateway.managed)


class HostModelTests(unittest.TestCase):
    def test_status_and_hashing(self):
        host = Host(ip="10.0.0.5", mac="aa:bb:cc:dd:ee:ff")
        self.assertEqual(host.status(), "free")
        host.blocked_upload = True
        self.assertEqual(host.status(), "blocked")
        host.upload_limit = 1000
        self.assertEqual(host.status(), "limited+blocked")
        host.forget_control_state()
        self.assertEqual(host.status(), "free")
        self.assertEqual(hash(host), hash(Host(ip="10.0.0.5", mac="11:22:33:44:55:66")))


if __name__ == "__main__":
    unittest.main()
