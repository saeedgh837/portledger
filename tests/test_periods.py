import contextlib
import copy
from datetime import datetime, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "port_traffic.py"
SPEC = importlib.util.spec_from_file_location("period_meter", SOURCE)
pt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pt)


def stamp(value):
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc).isoformat(timespec="seconds")


def legacy():
    return {"version": 1, "generation": "abc123", "interface": "eth0", "boot_id": "boot-a",
            "events": [], "last_sync": stamp("2026-10-01T00:00:00"),
            "ports": {"8443": {"since": stamp("2026-09-01T00:00:00"),
                               "rx_bytes": 1000, "tx_bytes": 2000, "raw_rx": 100, "raw_tx": 200}}}


def snapshot(rx=100, tx=200):
    return {"generation": "abc123", "counters": {"p8443_rx": rx, "p8443_tx": tx}}


def baseline(when="2026-10-01T00:00:00"):
    return pt.apply_sample(legacy(), snapshot(), stamp(when))


def periods(state, zone="UTC"):
    return {row["key"]: row for row in pt.make_report(state, "8443", zone)["periods"]}


class HistoryTests(unittest.TestCase):
    def test_upgrade_preserves_legacy_delta_without_inventing_history(self):
        before = legacy()
        final = pt.apply_sample(before, snapshot(150, 260), stamp("2026-10-02T12:00:00"))
        self.assertEqual(final["version"], 2)
        self.assertEqual((final["ports"]["8443"]["rx_bytes"], final["ports"]["8443"]["tx_bytes"]),
                         (1050, 2060))
        self.assertEqual(before, legacy())
        recent = periods(final)["last_24_hours"]
        self.assertEqual(recent["status"], "partial")
        self.assertEqual(recent["total_bytes"], 0)
        self.assertEqual(periods(final)["all_time"]["total_bytes"], 3110)

    def test_same_minute_deltas_merge_and_repeated_sample_does_not_duplicate(self):
        first = pt.apply_sample(baseline(), snapshot(110, 220), stamp("2026-10-01T00:00:10"))
        final = pt.apply_sample(first, snapshot(130, 250), stamp("2026-10-01T00:00:20"))
        final = pt.apply_sample(final, snapshot(130, 250), stamp("2026-10-01T00:00:30"))
        self.assertEqual(final["ports"]["8443"]["history"]["buckets"], [[1790812800, 30, 50]])
        self.assertEqual(periods(final)["today"]["total_bytes"], 80)

    def test_idle_samples_store_coverage_without_zero_buckets(self):
        final = pt.apply_sample(baseline(), snapshot(), stamp("2026-10-01T00:01:00"))
        self.assertEqual(final["ports"]["8443"]["history"]["buckets"], [])
        self.assertEqual(periods(final)["today"]["status"], "complete")
        self.assertEqual(periods(final)["today"]["total_bytes"], 0)

    def test_gap_marks_overlapping_windows_incomplete_not_just_recovery_bucket(self):
        s = pt.apply_sample(baseline(), snapshot(200, 400), stamp("2026-10-03T00:00:00"))
        rows = periods(s)
        self.assertEqual(rows["last_24_hours"]["status"], "incomplete")
        self.assertEqual(rows["last_24_hours"]["total_bytes"], 300)
        self.assertTrue(rows["last_24_hours"]["reasons"])

    def test_counter_reset_marks_history_incomplete_and_retains_all_time(self):
        s = pt.apply_sample(baseline(), snapshot(10, 20), stamp("2026-10-01T00:00:10"))
        self.assertEqual(periods(s)["today"]["status"], "incomplete")
        self.assertEqual(periods(s)["all_time"]["total_bytes"], 3030)

    def test_rollback_excludes_future_buckets_and_marks_uncertainty(self):
        s = pt.apply_sample(baseline(), snapshot(110, 220), stamp("2026-10-01T00:01:00"))
        s = pt.apply_sample(s, snapshot(120, 240), stamp("2026-10-01T00:00:30"))
        self.assertEqual(periods(s)["today"]["total_bytes"], 30)
        self.assertEqual(periods(s)["today"]["status"], "incomplete")
        self.assertEqual(len(s["ports"]["8443"]["history"]["buckets"]), 2)
        self.assertEqual(periods(s)["all_time"]["total_bytes"], 3060)

    def test_monotonic_clock_detects_forward_jump_without_long_real_gap(self):
        s = pt.apply_sample(legacy(), snapshot(), stamp("2026-10-01T00:00:00"), monotonic_ns=10_000_000_000)
        s = pt.apply_sample(s, snapshot(110, 220), stamp("2026-10-01T00:01:00"), monotonic_ns=20_000_000_000)
        self.assertEqual(periods(s)["today"]["status"], "incomplete")
        self.assertTrue(any(e["kind"] == "clock_change" for e in s["events"]))

    def test_retention_prunes_history_not_all_time_and_floor_survives_rollback(self):
        s = pt.apply_sample(baseline(), snapshot(110, 220), stamp("2026-10-01T00:01:00"))
        s = pt.apply_sample(s, snapshot(120, 240), stamp("2026-11-03T00:00:00"))
        s = pt.apply_sample(s, snapshot(130, 260), stamp("2026-11-03T00:00:10"))
        self.assertTrue(all(b[0] >= 1790985600 for b in s["ports"]["8443"]["history"]["buckets"]))
        s = pt.apply_sample(s, snapshot(140, 280), stamp("2026-10-01T00:01:00"))
        self.assertNotEqual(periods(s)["today"]["status"], "complete")
        self.assertEqual(periods(s)["all_time"]["total_bytes"], 3120)

    def test_clock_jump_cannot_prune_valid_history_after_later_samples_or_reload(self):
        s = pt.apply_sample(legacy(), snapshot(), stamp("2026-10-01T00:00:00"), monotonic_ns=0)
        s = pt.apply_sample(s, snapshot(110, 220), stamp("2026-10-01T00:01:00"),
                            monotonic_ns=60_000_000_000)
        s["ports"]["8443"]["history"]["gaps"] = [[1790812810, 1790812820]]
        s = pt.apply_sample(s, snapshot(120, 240), stamp("2026-12-01T00:01:10"),
                            monotonic_ns=70_000_000_000)
        for second, rx in ((20, 130), (30, 140), (40, 150)):
            s = pt.apply_sample(s, snapshot(rx, rx * 2), stamp(f"2026-12-01T00:01:{second}"),
                                monotonic_ns=(second + 60) * 1_000_000_000)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            pt.save_state(path, s)
            s = pt.apply_sample(pt.read_state(path), snapshot(160, 320), stamp("2026-12-01T00:01:50"),
                                monotonic_ns=110_000_000_000)
        history = s["ports"]["8443"]["history"]
        self.assertIn([1790812860, 10, 20], history["buckets"])
        self.assertEqual(history["retained_since"], 1790812800)
        self.assertIn([1790812810, 1790812820], history["gaps"])
        s = pt.apply_sample(s, snapshot(170, 340), stamp("2026-10-01T00:02:00"),
                            monotonic_ns=120_000_000_000)
        self.assertEqual(periods(s)["today"]["total_bytes"], 60)
        self.assertEqual(periods(s)["today"]["status"], "incomplete")
        self.assertEqual(periods(s)["all_time"]["total_bytes"], 3210)

    def test_first_sample_after_interrupted_activation_marks_unmonitored_history(self):
        s = baseline()
        s["last_sync"] = None
        s = pt.apply_sample(s, snapshot(), stamp("2026-10-03T12:00:00"))
        self.assertEqual(periods(s)["today"]["status"], "incomplete")
        self.assertEqual(periods(s)["last_24_hours"]["status"], "incomplete")
        self.assertEqual(periods(s)["today"]["total_bytes"], 0)
        self.assertEqual(periods(s)["all_time"]["total_bytes"], 3000)

    def test_invalid_pruning_guard_cannot_replace_valid_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            s = baseline()
            pt.save_state(path, s)
            before = path.read_bytes()
            for invalid in (None, 0, "false"):
                with self.subTest(value=invalid):
                    s["history_pruning_suspended"] = invalid
                    with self.assertRaises(ValueError):
                        pt.save_state(path, s)
                    self.assertEqual(path.read_bytes(), before)

    def test_invalid_history_never_overwrites_valid_balances(self):
        s = baseline()
        s["ports"]["8443"]["history"]["buckets"] = [[1790812800, -1, 2]]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            original = json.dumps(s)
            path.write_text(original, encoding="utf-8")
            with self.assertRaises(ValueError):
                pt.read_state(path)
            self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_history_and_totals_roundtrip_in_one_checkpoint(self):
        s = pt.apply_sample(baseline(), snapshot(110, 220), stamp("2026-10-01T00:00:10"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            pt.save_state(path, s)
            self.assertEqual(pt.read_state(path), s)
            self.assertEqual(periods(pt.read_state(path))["today"]["total_bytes"], 30)


class LifecycleTests(unittest.TestCase):
    def test_sync_saves_real_monotonic_observation_with_balances(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(pt.shutil, "which", return_value="nft"):
            meter = pt.Meter(tmp)
            pt.save_state(meter.path, baseline())
            with patch.object(meter, "ensure", return_value=(baseline(), snapshot(110, 220))), \
                    patch.object(meter, "check_rules"), patch.object(pt, "utcnow", return_value=stamp("2026-10-01T00:00:10")):
                saved = meter.sync()
            self.assertIsInstance(saved["last_monotonic_ns"], int)
            self.assertGreater(saved["last_monotonic_ns"], 0)
            self.assertEqual(pt.read_state(meter.path), saved)
            self.assertEqual(periods(saved)["today"]["total_bytes"], 30)

    def test_generation_recovery_marks_gaps_and_preserves_same_boot_clock_evidence(self):
        before = baseline()
        before["last_monotonic_ns"] = 10
        with patch.object(pt, "utcnow", return_value=stamp("2026-10-01T00:00:30")):
            after = pt.new_generation(before, "def456", "boot-a", "table removed")
        self.assertEqual(after["ports"]["8443"]["history"]["gaps"], [[1790812800, 1790812830]])
        self.assertEqual(after["last_monotonic_ns"], 10)
        self.assertEqual(periods(after)["today"]["status"], "incomplete")
        self.assertEqual(after["ports"]["8443"]["rx_bytes"], 1000)

    def test_new_boot_generation_clears_incomparable_monotonic_baseline(self):
        before = baseline()
        before["last_monotonic_ns"] = 10**30
        with patch.object(pt, "utcnow", return_value=stamp("2026-10-01T00:00:30")):
            after = pt.new_generation(before, "def456", "boot-b", "boot changed")
        self.assertIsNone(after["last_monotonic_ns"])
        after = pt.apply_sample(after, {"generation": "def456", "counters": {
            "p8443_rx": 0, "p8443_tx": 0}}, stamp("2026-10-01T00:00:40"), monotonic_ns=10)
        self.assertFalse(after["history_pruning_suspended"])
        self.assertEqual(periods(after)["all_time"]["total_bytes"], 3000)

    def test_same_boot_table_recovery_keeps_history_across_clock_jump(self):
        s = pt.apply_sample(legacy(), snapshot(), stamp("2026-10-01T00:00:00"), monotonic_ns=0)
        s = pt.apply_sample(s, snapshot(110, 220), stamp("2026-10-01T00:01:00"),
                            monotonic_ns=60_000_000_000)
        recovered = {"generation": "def456", "counters": {"p8443_rx": 0, "p8443_tx": 0}}
        with tempfile.TemporaryDirectory() as tmp, patch.object(pt.shutil, "which", return_value="nft"):
            meter = pt.Meter(tmp)
            pt.save_state(meter.path, s)
            read_text = pt.Path.read_text
            def read_boot_id(path, *args, **kwargs):
                if str(path).replace("\\", "/") == "/proc/sys/kernel/random/boot_id":
                    return "boot-a"
                return read_text(path, *args, **kwargs)
            with patch.object(pt.Path, "read_text", autospec=True, side_effect=read_boot_id), \
                    patch.object(pt.uuid, "uuid4") as uuid4, \
                    patch.object(meter, "snapshot", side_effect=[None, recovered]), \
                    patch.object(meter, "transaction"), patch.object(meter, "check_rules"), \
                    patch.object(pt, "utcnow", return_value=stamp("2026-12-01T00:01:20")), \
                    patch.object(pt.time, "monotonic_ns", return_value=80_000_000_000):
                uuid4.return_value.hex = "def456"
                s = meter.sync()
            self.assertTrue(s["history_pruning_suspended"])
            self.assertIn([1790812860, 10, 20], s["ports"]["8443"]["history"]["buckets"])
            s = pt.apply_sample(pt.read_state(meter.path), recovered, stamp("2026-10-01T00:01:30"),
                                monotonic_ns=90_000_000_000)
        self.assertEqual(periods(s)["today"]["total_bytes"], 30)
        self.assertEqual(periods(s)["today"]["status"], "incomplete")
        self.assertEqual(periods(s)["all_time"]["total_bytes"], 3030)


class WindowTests(unittest.TestCase):
    def fixture(self, now="2026-11-02T12:00:35"):
        s = baseline("2026-09-30T00:00:00")
        entry = s["ports"]["8443"]
        entry["history"]["buckets"] = []
        entry["history"]["gaps"] = []
        s["last_sync"] = stamp(now)
        for when, rx, tx in (("2026-10-02T12:00:00", 1, 2),
                             ("2026-10-03T12:00:00", 10, 20),
                             ("2026-10-26T12:00:00", 100, 200),
                             ("2026-11-01T12:00:00", 1000, 2000),
                             ("2026-11-02T00:00:00", 10000, 20000),
                             ("2026-11-02T12:01:00", 100000, 200000)):
            epoch = int(datetime.fromisoformat(stamp(when)).timestamp())
            entry["history"]["buckets"].append([epoch, rx, tx])
        entry.update(rx_bytes=111111, tx_bytes=222222)
        return s

    def test_rolling_cutoffs_are_minute_rounded_inclusive_and_exclude_future(self):
        rows = periods(self.fixture())
        self.assertEqual([rows[k]["total_bytes"] for k in
                          ("today", "last_24_hours", "last_7_days", "last_30_days", "all_time")],
                         [30000, 33000, 33300, 33330, 333333])
        self.assertEqual(rows["last_24_hours"]["start"], stamp("2026-11-01T12:00:00"))
        self.assertTrue(all(rows[k]["status"] == "complete" for k in rows if k != "all_time"))

    def test_today_uses_selected_timezone_midnight_not_24_hours(self):
        s = self.fixture("2026-11-02T00:30:00")
        s["ports"]["8443"]["history"]["buckets"] = [[1793566800, 10, 20], [1793577600, 100, 200]]
        utc = periods(s)["today"]
        tehran = periods(s, "Asia/Tehran")["today"]
        self.assertEqual(utc["total_bytes"], 300)
        self.assertEqual(tehran["total_bytes"], 330)
        self.assertEqual(tehran["start"], "2026-11-01T20:30:00+00:00")

    def test_dst_today_is_local_calendar_day(self):
        rows = periods(self.fixture("2026-11-02T04:30:00"), "America/New_York")
        self.assertEqual(rows["today"]["start"], "2026-11-01T04:00:00+00:00")
        self.assertEqual(rows["last_24_hours"]["start"], "2026-11-01T04:30:00+00:00")

    def test_today_uses_first_midnight_during_midnight_dst_fold(self):
        s = self.fixture("2026-11-01T05:30:00")
        s["ports"]["8443"]["history"]["buckets"] = [[1793506500, 40, 60]]
        row = periods(s, "America/Havana")["today"]
        self.assertEqual(row["start"], "2026-11-01T04:00:00+00:00")
        self.assertEqual(row["total_bytes"], 100)
        self.assertEqual(row["status"], "complete")

    def test_bad_timezone_fails_explicitly(self):
        with self.assertRaisesRegex(ValueError, "timezone"):
            pt.make_report(self.fixture(), "8443", "Not/A_Zone")

    def test_existing_json_fields_and_exact_large_integers_are_preserved(self):
        s = self.fixture()
        s["ports"]["8443"].update(rx_bytes=2**60 + 7, tx_bytes=2**60 + 9)
        report = pt.make_report(s, "8443")
        self.assertEqual(report["total_bytes"], 2**61 + 16)
        self.assertEqual(report["total_gb"], report["periods"][-1]["total_gb"])
        self.assertEqual(report["timezone"], "UTC")
        self.assertEqual(report["bucket_seconds"], 60)

    def test_periods_longer_than_port_lifetime_include_full_balance(self):
        # A port created 1 day ago has total_bytes = 28 GB, but history only recorded 12 GB.
        # Periods starting before port creation (7 days, 30 days) must reflect the full 28 GB balance.
        s = baseline("2026-10-27T12:00:00")
        entry = s["ports"]["8443"]
        entry["since"] = stamp("2026-10-26T12:00:00")
        entry["rx_bytes"] = 5_000_000_000
        entry["tx_bytes"] = 23_000_000_000
        entry["history"] = {
            "since": stamp("2026-10-27T00:00:00"),
            "retained_since": int(datetime.fromisoformat(stamp("2026-10-27T00:00:00")).timestamp()),
            "buckets": [[int(datetime.fromisoformat(stamp("2026-10-27T06:00:00")).timestamp()), 2_000_000_000, 10_000_000_000]],
            "gaps": [],
        }
        report = pt.make_report(s, "8443")
        rows = {r["key"]: r for r in report["periods"]}
        self.assertEqual(rows["last_7_days"]["total_bytes"], 28_000_000_000)
        self.assertEqual(rows["last_30_days"]["total_bytes"], 28_000_000_000)
        self.assertEqual(rows["all_time"]["total_bytes"], 28_000_000_000)


class TableTests(unittest.TestCase):
    def render(self, **kwargs):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            pt.print_reports(baseline(), "8443", False, **kwargs)
        return output.getvalue()

    def test_table_has_five_periods_and_all_direction_columns(self):
        text = self.render()
        for label in ("Today", "Last 24 hours", "Last 7 days", "Last 30 days", "All time",
                      "Download (GB)", "Upload (GB)", "Total (GB)", "History", "Partial", "UTC"):
            self.assertIn(label, text)
        self.assertNotIn("\x1b[", text)
        self.assertIn("Exact total bytes: 3000", text)

    def test_colors_do_not_change_alignment_or_numeric_content(self):
        plain = self.render(color="never")
        colored = self.render(color="always")
        self.assertIn("\x1b[", colored)
        self.assertEqual(re.sub(r"\x1b\[[0-9;]*m", "", colored), plain)
        table_lines = [line for line in plain.splitlines() if line.startswith("|")]
        self.assertEqual(len({len(line) for line in table_lines}), 1)

    def test_automatic_color_respects_no_color_and_dumb_terminal(self):
        for env in ({"NO_COLOR": ""}, {"TERM": "dumb"}):
            with self.subTest(env=env), patch.dict(os.environ, env), patch("sys.stdout.isatty", return_value=True):
                self.assertFalse(pt.use_color("auto"))
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertTrue(pt.use_color("always"))
            self.assertFalse(pt.use_color("never"))

    def test_suspended_pruning_is_visible_even_without_recent_events(self):
        s = baseline()
        s["history_pruning_suspended"] = True
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            pt.print_reports(s, "8443", False, color="never")
        self.assertIn("History pruning suspended", output.getvalue())
        self.assertTrue(pt.make_report(s, "8443")["history_pruning_suspended"])

    def test_json_never_contains_ansi_even_when_forced(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            pt.print_reports(baseline(), "8443", True, color="always")
        self.assertNotIn("\x1b", output.getvalue())
        report = json.loads(output.getvalue())
        self.assertEqual(report["periods"][-1]["total_bytes"], 3000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
