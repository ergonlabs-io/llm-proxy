"""Reporter guards: do not turn loss, latency regression, or memory excess green."""
import importlib.util
from pathlib import Path
import unittest
import io

SPEC = importlib.util.spec_from_file_location("qualification", Path(__file__).with_name("capture-qualification.py"))
QUALIFICATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALIFICATION)
AGENT_SPEC = importlib.util.spec_from_file_location("agent_qualification", Path(__file__).with_name("capture-agent-qualification.py"))
AGENT_QUALIFICATION = importlib.util.module_from_spec(AGENT_SPEC)
AGENT_SPEC.loader.exec_module(AGENT_QUALIFICATION)


def fixture(name, state, p99=1000, error_rate=0, rss=1024):
    metrics = {"envoy_llmproxy_metadata_durable": 10 if state == "on" else 0,
               "envoy_llmproxy_capture_active_requests": 1 if state == "on" else 0}
    return {"name": name, "state": state, "rate": 5, "duration": 30, "warmup": 3, "memory_stress": False,
            "loadgen": {"result": {"error_rate": error_rate, "success": 10, "streams_started": 10,
                                   "ttft_from_scheduled_us": {"p99": p99}, "total_from_scheduled_us": {"p99": p99}},
                        "open_loop": {"achieved_rate": 5, "driver_saturated": False}},
            "peak_rss_bytes": {"proxy": rss}, "metrics_after": metrics, "peak_metrics": metrics,
            "samples": [{"elapsed_seconds": 3, "metrics": {"envoy_llmproxy_metadata_durable": 1}},
                        {"elapsed_seconds": 5, "metrics": {"envoy_llmproxy_metadata_durable": 3}}],
            "teardown": []}


class ReportingTests(unittest.TestCase):
    def test_agent_control_rejects_oversized_or_mismatched_frames(self):
        class Stream(io.BytesIO):
            recv = io.BytesIO.read
        for header in [b"LMC1\x04" + (1025).to_bytes(4, "big"),
                       b"LMC1\x02" + (1).to_bytes(4, "big"), b"bad"]:
            with self.assertRaises(RuntimeError):
                AGENT_QUALIFICATION.receive(Stream(header), 4)

    def test_cpu_time_parsing_and_warmup_exclusion(self):
        self.assertEqual(QUALIFICATION.cpu_seconds("01:02.50"), 62.5)
        self.assertEqual(QUALIFICATION.cpu_seconds("1-02:03:04"), 93784)
        samples = [{"elapsed_seconds": wall, "cpu_seconds": {"proxy": cpu}}
                   for wall, cpu in [(0, 0), (3, 100), (4, 100.5), (5, 101.5), (31, 200)]]
        report = QUALIFICATION.cpu_summary(samples, 3, 30)
        self.assertEqual(report["proxy"]["mean_percent"], 75)
        self.assertEqual(report["proxy"]["peak_percent"], 100)

    def test_legacy_cpu_measurements_remain_missing(self):
        self.assertEqual(QUALIFICATION.cpu_summary(fixture("off", "off")["samples"], 3, 30), {})
        self.assertIsNone(QUALIFICATION.summarize([fixture("off", "off"), fixture("on", "on")])
                          ["runs"][0]["cpu_during_load"])
        self.assertFalse(QUALIFICATION.summarize([fixture("off", "off"), fixture("on", "on")])
                         ["all_cpu_measured"])

    def test_regression_over_five_percent_fails(self):
        report = QUALIFICATION.summarize([fixture("off", "off"), fixture("on", "on", p99=1051)])
        self.assertFalse(report["comparisons"][0]["ttft_from_scheduled_us"]["within_provisional_5_percent"])

    def test_forwarding_errors_do_not_pass(self):
        report = QUALIFICATION.summarize([fixture("off", "off"), fixture("on", "on", error_rate=.01)])
        self.assertFalse(report["all_forwarding_error_rates_zero"])

    def test_memory_excess_does_not_pass(self):
        report = QUALIFICATION.summarize([fixture("off", "off"), fixture("on", "on", rss=1073741825)])
        self.assertFalse(report["all_proxy_peak_rss_below_1GiB"])

    def test_pending_reservations_do_not_pass(self):
        run = fixture("on", "on")
        run["control_after"] = {"active_requests": 0, "outstanding_events": 1, "retained_event_bytes": 65536}
        self.assertFalse(QUALIFICATION.summarize([fixture("off", "off"), run])["all_reservations_drained"])
        run["control_after"] = {"active_requests": 0, "outstanding_events": 0, "retained_event_bytes": 0}
        self.assertTrue(QUALIFICATION.summarize([fixture("off", "off"), run])["all_reservations_drained"])

    def test_delivery_coverage_is_not_http_coverage(self):
        run = fixture("on", "on")
        run["metrics_after"]["envoy_llmproxy_metadata_durable"] = 4
        report = QUALIFICATION.summarize([fixture("off", "off"), run])
        self.assertTrue(report["all_forwarding_error_rates_zero"])
        self.assertEqual(report["runs"][1]["durable_fraction_of_started"], .4)
        self.assertEqual(report["runs"][1]["durable_rps_during_load"], 1)


if __name__ == "__main__":
    unittest.main()
