"""Added-latency reporter guards: a run that skipped a control must not publish."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("added_latency", Path(__file__).with_name("added-latency.py"))
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


def row(arm, round_no, p50, p99, counted=100, success=100):
    return {"arm": arm, "round": round_no, "counted": counted, "success": success, "error_rate": 0,
            "http_errors": {}, "p50_us": p50 + 1000, "p99_us": p99 + 1000,
            "p50_from_send_us": p50, "p99_from_send_us": p99, "load_before": [10.0], "load_after": [12.0]}


class AddedLatencyTests(unittest.TestCase):
    def test_every_round_runs_every_arm_and_the_first_arm_moves(self):
        orders = [BENCH.round_order(r) for r in range(1, 7)]
        for order in orders:
            self.assertEqual(sorted(order), sorted(BENCH.ARMS))
        self.assertGreater(len({order[0] for order in orders}), 2)

    def test_added_is_minimum_over_minimum_not_mean(self):
        rows = [row("direct", 1, 1000, 3000), row("direct", 2, 900, 5000),
                row("controls-on", 1, 1500, 4000), row("controls-on", 2, 9000, 9000)]
        table = {r["arm"]: r for r in BENCH.summarize(rows)}
        for base in ("from_send", "from_scheduled"):
            self.assertEqual(table["controls-on"][base]["added_p50_us"], 600)
            self.assertEqual(table["controls-on"][base]["added_p99_us"], 1000)
        self.assertEqual(table["direct"]["from_send"]["p99_min_us"], 3000)
        self.assertEqual(table["direct"]["from_scheduled"]["p99_min_us"], 4000)

    def test_configs_add_one_control_group_per_arm(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "key.digest").write_text("0" * 64)
            config = {arm: BENCH.proxy_config(arm, 1, 2, "127.0.0.1:3", run_dir) for arm in BENCH.ARMS[1:]}
        self.assertNotIn("auth:", config["controls-off"])
        self.assertIn("    limits: false\n    spend: false", config["auth"])
        self.assertIn("limits:\n  - key: tenant", config["auth-limits"])
        self.assertNotIn("pricing:", config["auth-limits"])
        self.assertIn("    spend: true", config["auth-limits-spend"])
        self.assertNotIn("ledger:", config["auth-limits-spend"])
        for block in ("auth:", "limits:\n", "pricing:", "ledger:", "on_unavailable: reject"):
            self.assertIn(block, config["controls-on"])

    def test_evidence_refuses_a_run_whose_controls_did_not_run(self):
        good = {"unauthenticated_status": 401, "key_spend": {"spend_micro_usd": 5}, "ledger_entries_sample": 3}
        BENCH.check_evidence("controls-on", good)
        for broken in ({**good, "unauthenticated_status": 200},
                       {**good, "key_spend": {"spend_micro_usd": 0}},
                       {**good, "ledger_entries_sample": 0}):
            with self.assertRaises(RuntimeError):
                BENCH.check_evidence("controls-on", broken)


if __name__ == "__main__":
    unittest.main()
