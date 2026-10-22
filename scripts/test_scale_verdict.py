"""Scale-run verdicts: a broken sampler is INVALID, never PASS, and S5 judges each fault."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("scale_verdict", Path(__file__).with_name("scale-verdict.py"))
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)

C, PER, T, DUR = 300, 57.97, 3.45, 180


def report(success=1000, errors=None, transport=0, p50_us=3_500_000):
    return {"result": {"success": success, "http_errors": errors or {}, "transport_errors": transport,
                       "total_from_send_us": {"p50": p50_us}}}


def series(level, start=1000.0, secs=DUR, overrides=None):
    """Samples every 0.5 s at `level`; overrides maps (lo, hi) offsets to a level."""
    out = []
    for i in range(int(secs * 2) + 1):
        ts = start + i / 2
        v = level
        for (lo, hi), lvl in (overrides or {}).items():
            if lo <= ts - start < hi:
                v = lvl
        out.append((ts, v, v))
    return out


def faults_run(after_up_level=C, refill_after=4.0):
    # Kill at +60, redis down at +100, up at +130 (the runner's schedule).
    over = {(60, 60 + refill_after): 200, (100, 130): 450, (130, 201): after_up_level}
    events = {"SIGKILL replica 3": 1060.0, "redis down": 1100.0, "redis up": 1130.0}
    # Recovery needs samples past up + 60 s and before the last stream time.
    return series(C, secs=200, overrides=over), events


class S4bTests(unittest.TestCase):
    def test_all_zero_samples_are_invalid_not_pass(self):
        lines, ok = V.s4b(series(0), [report()], {}, C, PER, T, DUR, False)
        self.assertIsNone(ok)
        self.assertIn("INVALID", lines[0])

    def test_at_the_ceiling_passes_and_above_the_bound_fails(self):
        _, ok = V.s4b(series(C), [report()], {}, C, PER, T, DUR, False)
        self.assertTrue(ok)
        _, ok = V.s4b(series(C, overrides={(40, 41): C + 200}), [report()], {}, C, PER, T, DUR, False)
        self.assertFalse(ok)

    def test_bound_is_one_lease_publish_interval_of_the_other_replicas(self):
        # 300 + 2 x 57.97 x 0.25 = 328.99: S4a's 1 s reconcile interval would
        # allow 415.
        _, ok = V.s4b(series(C, overrides={(40, 41): 328}), [report()], {}, C, PER, T, DUR, False)
        self.assertTrue(ok)
        _, ok = V.s4b(series(C, overrides={(40, 41): 330}), [report()], {}, C, PER, T, DUR, False)
        self.assertFalse(ok)

    def test_a_spike_inside_the_ramp_is_not_steady_state(self):
        _, ok = V.s4b(series(C, overrides={(2, 3): C + 200}), [report()], {}, C, PER, T, DUR, False)
        self.assertTrue(ok)

    def test_non_429_errors_fail(self):
        _, ok = V.s4b(series(C), [report(errors={"429": 50})], {}, C, PER, T, DUR, False)
        self.assertTrue(ok)
        _, ok = V.s4b(series(C), [report(errors={"401": 3})], {}, C, PER, T, DUR, False)
        self.assertFalse(ok)

    def test_faults_pass_when_refilled_and_ceiling_holds_after_redis(self):
        samples, events = faults_run()
        lines, ok = V.s4b(samples, [report(transport=40)], events, C, PER, T, 200, True)
        self.assertTrue(ok, lines)
        # Fail-open above the ceiling while Redis is down is reported, not failed.
        self.assertTrue(any("peak in flight 450" in l for l in lines), lines)

    def test_faults_fail_when_the_killed_replicas_slots_stay_held(self):
        samples, events = faults_run(refill_after=12.0)
        lines, ok = V.s4b(samples, [report()], events, C, PER, T, 200, True)
        self.assertFalse(ok, lines)

    def test_faults_fail_when_the_ceiling_is_lost_after_redis_returns(self):
        samples, events = faults_run(after_up_level=450)
        _, ok = V.s4b(samples, [report()], events, C, PER, T, 200, True)
        self.assertFalse(ok)

    def test_empty_redis_restart_fails_on_its_401s(self):
        # S5: after an empty restart every key is refused, so the mock goes
        # quiet (which alone would look like a held ceiling) and loadgen
        # counts 401s.
        samples, events = faults_run(after_up_level=0)
        _, ok = V.s4b(samples, [report(errors={"401": 3197})], events, C, PER, T, 200, True)
        self.assertFalse(ok)


class S4aTests(unittest.TestCase):
    def test_bound_is_one_reconcile_interval_of_the_other_replicas(self):
        per = 2 * 6000 / 3 / 60
        bound = 3 * (6000 + 2 * per)
        _, ok = V.s4a([report(success=int(bound))], 6000, per)
        self.assertTrue(ok)
        _, ok = V.s4a([report(success=int(bound) + 1)], 6000, per)
        self.assertFalse(ok)


class FileTests(unittest.TestCase):
    def test_sampler_lines_with_na_or_garbage_are_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "streams_active.txt"
            p.write_text("1.0 5 7 3 3 NA\n2.0 NA NA 1 1 1\ncurl: (7) refused\n3.0 4 4\n")
            self.assertEqual(V.load_samples(p), [(1.0, 5, 7), (3.0, 4, 4)])


if __name__ == "__main__":
    unittest.main()
