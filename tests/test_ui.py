import unittest

from evilair.core.host import Host, TrafficSnapshot
from evilair.ui.charts import bar_rows
from evilair.ui.console import Console


class ConsoleTests(unittest.TestCase):
    def test_host_table_includes_all_hosts(self):
        console = Console(quiet=True)
        hosts = [
            Host(ip="10.0.0.1", mac="aa:bb:cc:dd:ee:01", name="router-copy"),
            Host(ip="10.0.0.2", mac="aa:bb:cc:dd:ee:02"),
        ]
        hosts[1].upload_limit = 512_000
        hosts[1].traffic = TrafficSnapshot(upload_rate=1000, download_rate=2000)
        table = console.host_table(hosts)
        self.assertEqual(table.row_count, 2)
        titles = [column.header for column in table.columns]
        self.assertIn("Status", titles)
        self.assertIn("Limit", titles)

    def test_traffic_table_renders(self):
        console = Console(quiet=True)
        hosts = [Host(ip="10.0.0.3", mac="aa:bb:cc:dd:ee:03")]
        table = console.traffic_table(hosts)
        self.assertEqual(table.row_count, 1)


class ChartTests(unittest.TestCase):
    def test_bars_are_proportional_and_sorted(self):
        rows = bar_rows([("a", 100), ("b", 400), ("c", 0)], width=10)
        self.assertEqual(len(rows), 3)
        self.assertTrue(rows[0].plain.startswith("b"))
        self.assertIn("▇" * 10, rows[0].plain)
        self.assertTrue(rows[-1].plain.startswith("c"))

    def test_empty_values(self):
        self.assertEqual(bar_rows([]), [])


if __name__ == "__main__":
    unittest.main()
