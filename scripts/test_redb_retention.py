"""Reporter tests for the production redb retention qualification."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "redb_retention", Path(__file__).with_name("redb-retention.py")
)
RETENTION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RETENTION)


def run(root, *, requested=100, confirmed=100, disk=4096, rss=1024, replayed=100, verified=100):
    artifact = root / "result.json"
    artifact.write_text("{}\n")
    return {
        "name": "regular",
        "requested_records": requested,
        "confirmed_records": confirmed,
        "stopped": None if confirmed == requested else "spool resource budget exhausted",
        "max_disk_bytes": 1_073_741_824,
        "final_stats": {"disk_bytes": disk},
        "replay": {"records": replayed, "verified_records": verified},
        "resources": {"maximum_rss_bytes": rss},
        "artifacts": {"result": str(artifact)},
    }


class RetentionReportTests(unittest.TestCase):
    def test_maximum_fixture_obeys_field_and_attempt_bounds(self):
        value = RETENTION.maximum_record_fixture()
        self.assertEqual(len(value["attempts"]), 64)
        self.assertEqual(value["attempt_count"], 64)
        self.assertEqual(len(RETENTION.compact_json(RETENTION.qualified_fixture(value, 0))), 524288)
        def check(entry):
            if isinstance(entry, str):
                self.assertLessEqual(len(entry.encode()), 512)
            elif isinstance(entry, dict):
                for child in entry.values():
                    check(child)
            elif isinstance(entry, list):
                for child in entry:
                    check(child)
        check(value)

    def test_missing_measurements_do_not_pass(self):
        self.assertFalse(RETENTION.summarize([])["qualification_passed"])
        with tempfile.TemporaryDirectory() as temporary:
            incomplete = run(Path(temporary))
            del incomplete["final_stats"]["disk_bytes"]
            del incomplete["resources"]["maximum_rss_bytes"]
            self.assertFalse(RETENTION.summarize([incomplete])["qualification_passed"])

    def test_nearest_rank_percentile(self):
        self.assertEqual(RETENTION.percentile([9, 1, 5, 3], .5), 3)
        self.assertEqual(RETENTION.percentile([9, 1, 5, 3], .95), 9)
        self.assertIsNone(RETENTION.percentile([], .99))

    def test_loss_and_stopped_quota_are_reported_as_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = RETENTION.summarize([run(Path(temporary), confirmed=99, replayed=99)])
        self.assertFalse(result["all_requested_confirmed"])
        self.assertEqual(result["runs"][0]["stopped"], "spool resource budget exhausted")

    def test_disk_and_memory_limits_are_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = RETENTION.summarize(
                [run(Path(temporary), disk=1_073_741_825, rss=1_073_741_825)]
            )
        self.assertFalse(result["within_disk_cap"])
        self.assertFalse(result["within_memory_cap"])

    def test_replay_verification_and_artifact_paths_are_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            good = RETENTION.summarize([run(root)])
            self.assertTrue(good["all_replayed_records_verified"])
            self.assertTrue(good["all_artifact_paths_exist"])
            missing = run(root)
            missing["artifacts"]["fixture"] = str(root / "missing.json")
            bad = RETENTION.summarize([missing])
        self.assertFalse(bad["all_artifact_paths_exist"])


if __name__ == "__main__":
    unittest.main()
