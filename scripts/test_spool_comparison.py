"""Do not hide capacity loss, replay loss, or absent resource measurements."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("comparison", Path(__file__).with_name("spool-comparison.py"))
COMPARISON = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPARISON)


def result():
    return {"confirmed_records": 8, "requested_records": 8, "stopped": None,
            "batches": [{"reserve_encrypt_ms": 1, "commit_ms": 2, "durable_batch_ms": 3}],
            "growth": [], "max_disk_bytes": 4096, "final_stats": {"disk_bytes": 2048},
            "replay": {"acknowledged_prefix_present": True}}


class ReportingTests(unittest.TestCase):
    def test_full_is_preserved_as_incomplete_coverage(self):
        raw = result()
        raw.update(requested_records=16, stopped={"error": "Full"})
        report = COMPARISON.describe(raw)
        self.assertFalse(report["all_requested_confirmed"])
        self.assertEqual(report["stopped"], {"error": "Full"})

    def test_replay_and_quota_failure_do_not_pass(self):
        raw = result()
        raw["replay"]["acknowledged_prefix_present"] = False
        raw["final_stats"]["disk_bytes"] = 4097
        report = COMPARISON.describe(raw)
        self.assertFalse(report["replayed_acknowledged_prefix"])
        self.assertFalse(report["within_disk_cap"])

    def test_empty_batch_statistics_are_not_zero_latency(self):
        raw = result()
        raw.update(confirmed_records=0, batches=[])
        report = COMPARISON.describe(raw)
        self.assertIsNone(report["latency_ms"]["commit_ms"]["p99"])
        self.assertIsNone(report["bytes_per_confirmed_record"])

    def test_resource_units_and_missing_measurements(self):
        darwin = "1.20 real 0.10 user 0.20 sys\n 1048576 maximum resident set size"
        linux = "User time (seconds): 0.10\nSystem time (seconds): 0.20\nMaximum resident set size (kbytes): 1024"
        self.assertEqual(COMPARISON.time_report(darwin, "Darwin")["maximum_rss_bytes"], 1048576)
        self.assertEqual(COMPARISON.time_report(linux, "Linux")["maximum_rss_bytes"], 1048576)
        with self.assertRaises(ValueError):
            COMPARISON.time_report("", "Darwin")


if __name__ == "__main__":
    unittest.main()
