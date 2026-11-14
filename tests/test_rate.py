import unittest

from evilair.util.rate import BitRate, ByteSize, RateFormatError, format_bytes, format_bitrate, format_mac


class BitRateTests(unittest.TestCase):
    def test_parses_common_units(self):
        self.assertEqual(BitRate.parse("512kbit").bits_per_second, 512_000)
        self.assertEqual(BitRate.parse("2mbit").bits_per_second, 2_000_000)
        self.assertEqual(BitRate.parse("1gbit").bits_per_second, 1_000_000_000)
        self.assertEqual(BitRate.parse("9600bit").bits_per_second, 9_600)
        self.assertEqual(BitRate.parse("3 mbps").bits_per_second, 3_000_000)

    def test_parses_plain_numbers_as_bits(self):
        self.assertEqual(BitRate.parse(1500).bits_per_second, 1500)

    def test_rejects_garbage(self):
        for value in ("abc", "-5kbit", "10flop"):
            with self.assertRaises(RateFormatError):
                BitRate.parse(value)

    def test_formatting_and_comparison(self):
        self.assertEqual(str(BitRate(512_000)), "512.0kbit")
        self.assertEqual(str(BitRate(2_000_000)), "2.0mbit")
        self.assertEqual(BitRate.parse("1mbit").tc_value(), "1000000bit")
        self.assertLess(BitRate.parse("1mbit"), BitRate.parse("2mbit"))


class ByteSizeTests(unittest.TestCase):
    def test_parse_and_format(self):
        self.assertEqual(ByteSize.parse("1mb").bytes, 1024**2)
        self.assertEqual(format_bytes(2048), "2.0KB")
        self.assertEqual(str(ByteSize(0)), "0B")

    def test_arithmetic(self):
        total = ByteSize.parse("1mb") + ByteSize.parse("512kb")
        self.assertEqual(int(total.bytes), 1024**2 + 512 * 1024)


class MacTests(unittest.TestCase):
    def test_normalises(self):
        self.assertEqual(format_mac("AA:BB:CC:DD:EE:FF"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(format_mac("aabb.ccdd.eeff"), "aa:bb:cc:dd:ee:ff")

    def test_rejects_invalid(self):
        with self.assertRaises(ValueError):
            format_mac("aa:bb:cc")


class FormatTests(unittest.TestCase):
    def test_bitrate_scales(self):
        self.assertEqual(format_bitrate(999), "999bit")
        self.assertEqual(format_bitrate(1_500), "1.5kbit")
        self.assertEqual(format_bitrate(2_500_000_000), "2.5gbit")


if __name__ == "__main__":
    unittest.main()
