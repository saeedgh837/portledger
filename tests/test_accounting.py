import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "port_traffic.py"
SPEC = importlib.util.spec_from_file_location("port_traffic", SOURCE)
pt = importlib.util.module_from_spec(SPEC)
if SOURCE.exists():
    SPEC.loader.exec_module(pt)


def state():
    return {
        "version": 1, "generation": "abc123", "interface": "eth0",
        "boot_id": "boot-a", "events": [], "last_sync": None,
        "ports": {"40199": {
            "since": "2026-10-26T00:00:00+00:00", "rx_bytes": 0, "tx_bytes": 0,
            "raw_rx": 0, "raw_tx": 0,
        }},
    }


def snapshot(rx=100, tx=200, generation="abc123"):
    return {"generation": generation, "counters": {"p40199_rx": rx, "p40199_tx": tx}}


class AccountingTests(unittest.TestCase):
    def test_cumulative_sample_is_counted_exactly_once(self):
        first = pt.apply_sample(state(), snapshot(), "2026-10-26T00:00:10+00:00")
        again = pt.apply_sample(first, snapshot(), "2026-10-26T00:00:20+00:00")
        self.assertEqual((again["ports"]["40199"]["rx_bytes"],
                          again["ports"]["40199"]["tx_bytes"]), (100, 200))
        final = pt.apply_sample(again, snapshot(175, 250), "2026-10-26T00:00:30+00:00")
        self.assertEqual((final["ports"]["40199"]["rx_bytes"],
                          final["ports"]["40199"]["tx_bytes"]), (175, 250))

    def test_does_not_mutate_previous_checkpoint(self):
        before = state()
        original = copy.deepcopy(before)
        pt.apply_sample(before, snapshot(), "2026-10-26T00:00:10+00:00")
        self.assertEqual(before, original)

    def test_raw_counter_reset_retains_total_and_warns(self):
        first = pt.apply_sample(state(), snapshot(100, 200), "2026-10-26T00:00:10+00:00")
        final = pt.apply_sample(first, snapshot(20, 30), "2026-10-26T00:00:20+00:00")
        self.assertEqual((final["ports"]["40199"]["rx_bytes"],
                          final["ports"]["40199"]["tx_bytes"]), (120, 230))
        self.assertTrue(any(e["kind"] == "counter_reset" for e in final["events"]))

    def test_missing_counter_never_silently_becomes_zero(self):
        broken = snapshot()
        del broken["counters"]["p40199_tx"]
        with self.assertRaises(ValueError):
            pt.apply_sample(state(), broken, "2026-10-26T00:00:10+00:00")

    def test_unknown_table_generation_is_rejected(self):
        with self.assertRaises(ValueError):
            pt.apply_sample(state(), snapshot(generation="foreign"), "2026-10-26T00:00:10+00:00")

    def test_negative_and_noninteger_samples_are_rejected(self):
        for value in (-1, 1.5, True, "10"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                pt.apply_sample(state(), snapshot(value, 0), "2026-10-26T00:00:10+00:00")

    def test_large_integer_bytes_remain_exact(self):
        final = pt.apply_sample(state(), snapshot(2**60 + 7, 2**60 + 9), "2026-10-26T00:00:10+00:00")
        self.assertEqual(final["ports"]["40199"]["rx_bytes"], 1152921504606846983)
        self.assertEqual(final["ports"]["40199"]["tx_bytes"], 1152921504606846985)

    def test_decimal_gigabytes_not_gibibytes(self):
        s = state()
        s["ports"]["40199"].update(rx_bytes=1_000_000_000, tx_bytes=2_000_000_000)
        report = pt.make_report(s, "40199")
        self.assertEqual(report["total_bytes"], 3_000_000_000)
        self.assertEqual(report["total_gb"], "3.000000")
        self.assertEqual(report["upload_gb"], "1.000000")
        self.assertEqual(report["download_gb"], "2.000000")

    def test_rebuild_keeps_total_but_starts_new_raw_baseline(self):
        old = pt.apply_sample(state(), snapshot(), "2026-10-26T00:00:10+00:00")
        rebuilt = pt.new_generation(old, "new123", "boot-b", "reboot")
        final = pt.apply_sample(rebuilt, snapshot(10, 20, "new123"), "2026-10-26T00:00:40+00:00")
        self.assertEqual((final["ports"]["40199"]["rx_bytes"],
                          final["ports"]["40199"]["tx_bytes"]), (110, 220))
        self.assertEqual(final["generation"], "new123")
        self.assertTrue(final["events"])


class InputTests(unittest.TestCase):
    def test_invalid_ports_rejected_before_nft(self):
        for value in ("0", "65536", "-3", "22; reboot", "1.5", "", " 22", "*", "۲۲"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                pt.valid_port(value)
        self.assertEqual(pt.valid_port("65535"), "65535")
        self.assertEqual(pt.valid_port("22"), "22")

    def test_interface_cannot_inject_nft_syntax(self):
        for value in ('eth0"; drop', "eth 0", "", "a" * 16):
            with self.subTest(value=value), self.assertRaises(ValueError):
                pt.valid_interface(value)
        self.assertEqual(pt.valid_interface("ens3.100"), "ens3.100")

    def test_nft_json_parser_ignores_other_tables_and_extracts_named_counters(self):
        data = {"nftables": [
            {"table": {"family": "inet", "name": "port_traffic", "comment": "port-traffic:v1:abc123"}},
            {"counter": {"family": "inet", "table": "port_traffic", "name": "p40199_rx", "bytes": 123, "packets": 4}},
            {"counter": {"family": "inet", "table": "port_traffic", "name": "p40199_tx", "bytes": 456, "packets": 8}},
            {"counter": {"family": "inet", "table": "other", "name": "p40199_rx", "bytes": 999}},
        ]}
        result = pt.parse_snapshot(data)
        self.assertEqual(result["generation"], "abc123")
        self.assertEqual(result["counters"], {"p40199_rx": 123, "p40199_tx": 456})

    def test_refuses_unowned_table(self):
        with self.assertRaises(ValueError):
            pt.parse_snapshot({"nftables": [{"table": {"family": "inet", "name": "port_traffic"}}]})

    def test_corrupt_existing_state_is_never_replaced_with_empty_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text('{"broken"', encoding="utf-8")
            with self.assertRaises(ValueError):
                pt.read_state(path)
            self.assertEqual(path.read_text(), '{"broken"')

    def test_atomic_state_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            pt.save_state(path, state())
            self.assertEqual(pt.read_state(path), state())
            new = pt.apply_sample(state(), snapshot(), "2026-10-26T00:00:10+00:00")
            pt.save_state(path, new)
            self.assertEqual(pt.read_state(path)["ports"]["40199"]["tx_bytes"], 200)
            self.assertEqual(list(Path(tmp).glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
