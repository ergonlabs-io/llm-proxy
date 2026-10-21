#!/usr/bin/env python3
"""Verdicts for the fleet-limit scenarios of scripts/scale-experiment-remote.sh.

    scale-verdict.py s4a DIR RPM PER_REPLICA_RPS
    scale-verdict.py s4b DIR STREAMS PER_REPLICA_RPS INTRINSIC_S DURATION [faults]

Inputs are the files the runner leaves in DIR: loadgen reports r*.json, the
stream sampler's streams_active.txt, and (for S5) events.txt. Everything is
recomputable from the raw files, so a verdict can be rerun after the droplet
is gone.

streams_active.txt has one line per 500 ms poll:

    EPOCH MOCK_IN_FLIGHT MOCK_PEAK [SS_R1 SS_R2 SS_R3]

MOCK_* come from mock-upstream's GET /_mock/stats: the streams the upstream
is actually serving, and the highest count since the previous poll. That is
the ground truth for a fleet ceiling, because a stream the proxy refuses
never reaches the upstream. SS_* are established downstream connections per
replica (Linux `ss`, "NA" elsewhere), kept as a cross-check: they also count a
refused stream until its 429 is written, so they overstate.
"""
import glob
import json
import os
import sys

# ADR-0006: one reconcile (S4a) or lease publish (S4b) interval, in seconds.
SYNC_INTERVAL_S = 1.0
# A killed replica's leases expire after their 5 s TTL, plus two publishes.
RELEASE_BOUND_S = 7.0
# After Redis returns, allow one policy poll bound (60 s) before the ceiling
# must hold again.
RECOVERY_S = 60.0
REPLICAS = 3


def load_reports(d):
    reports = []
    for f in sorted(glob.glob(os.path.join(d, "r*.json"))):
        with open(f) as fh:
            reports.append(json.load(fh))
    return reports


def load_samples(path):
    """[(epoch, in_flight, peak)] from streams_active.txt; bad lines skipped."""
    samples = []
    with open(path) as fh:
        lines = fh.readlines()
    for line in lines:
        parts = line.split()
        if len(parts) < 3 or "NA" in parts[1:3]:
            continue
        try:
            samples.append((float(parts[0]), int(parts[1]), int(parts[2])))
        except ValueError:
            continue
    return samples


def load_events(path):
    events = {}
    if os.path.exists(path):
        with open(path) as fh:
            lines = fh.readlines()
        for line in lines:
            ts, what = line.split(" ", 1)
            events[what.strip()] = float(ts)
    return events


def s4a(reports, rpm, per_replica_rps, windows=3, replicas=REPLICAS):
    ok = sum(r["result"]["success"] for r in reports)
    bound = windows * (rpm + (replicas - 1) * per_replica_rps * SYNC_INTERVAL_S)
    lines = [f"admitted={ok} limit={windows * rpm} bound={bound:.0f} over={ok - windows * rpm}"]
    return lines, ok <= bound


def _peak(samples, lo, hi):
    window = [p for ts, _, p in samples if lo <= ts <= hi]
    return max(window, default=None), len(window)


def s4b(samples, reports, events, streams, per_replica_rps, intrinsic_s, duration, faults,
        replicas=REPLICAS):
    """Returns (report lines, verdict). verdict is None when the run is not evidence."""
    lines = []
    if not samples or max(p for _, _, p in samples) == 0:
        return ["INVALID: the mock reported no streams in flight; the sampler is broken, "
                "not the limit"], None
    start = samples[0][0]
    steady_lo, steady_hi = start + 15, start + duration - intrinsic_s
    bound = streams + (replicas - 1) * per_replica_rps * SYNC_INTERVAL_S

    kill, down, up = events.get("SIGKILL replica 3"), events.get("redis down"), events.get("redis up")
    # The fault window is excluded from the steady-state check: fail-open
    # while Redis is down is expected to exceed the ceiling.
    fault_lo = kill if kill is not None else down
    fault_hi = (up + RECOVERY_S) if up is not None else None
    if faults and fault_lo is not None:
        steady = [p for ts, _, p in samples
                  if steady_lo <= ts <= steady_hi and not (fault_lo <= ts <= (fault_hi or steady_hi))]
    else:
        steady = [p for ts, _, p in samples if steady_lo <= ts <= steady_hi]
    steady_max = max(steady, default=0)
    lines.append(f"mock in flight: peak={max(p for _, _, p in samples)} steady_max={steady_max} "
                 f"ceiling={streams} bound={bound:.0f} steady_samples={len(steady)}")
    verdict = bool(steady) and steady_max <= bound

    ok = sum(r["result"]["success"] for r in reports)
    counted_secs = duration - 10
    mean_s = sum(r["result"]["success"] * r["result"]["total_from_send_us"]["p50"]
                 for r in reports) / max(ok, 1) / 1e6
    lines.append(f"little's law mean in flight ~= {ok * mean_s / counted_secs:.0f} "
                 f"(admitted {ok} x p50 {mean_s:.2f} s / {counted_secs} s)")
    errors = {}
    for r in reports:
        for k, v in r["result"]["http_errors"].items():
            errors[k] = errors.get(k, 0) + v
    transport = sum(r["result"]["transport_errors"] for r in reports)
    lines.append(f"http_errors={errors} transport_errors={transport}")

    if faults:
        if kill is not None:
            # The killed replica's streams leave the mock at once (its
            # sockets close); its leases hold their slots until the TTL. The
            # slots are free again once the survivors refill the fleet to 90%
            # of the ceiling. Uses the current count, not the poll's peak,
            # which still remembers the moment before the kill.
            after_kill = [(ts, f) for ts, f, _ in samples
                          if ts > kill + 0.5 and (down is None or ts < down)]
            dip_ts, dip = min(((ts, f) for ts, f in after_kill if ts <= kill + 3),
                              key=lambda s: s[1], default=(None, None))
            refill = next((ts - kill for ts, f in after_kill
                           if dip_ts is not None and ts > dip_ts and f >= 0.9 * streams), None)
            lines.append(f"after SIGKILL: lowest in flight within 3 s = {dip}")
            if dip is None or dip >= 0.9 * streams:
                lines.append("after SIGKILL: no dip below 90% of the ceiling; the kill did not "
                             "free slots, or the fleet was not at the ceiling")
                verdict = False
            elif refill is None:
                lines.append("after SIGKILL: fleet never refilled to 90% of the ceiling before redis down")
                verdict = False
            else:
                lines.append(f"after SIGKILL: refilled to 90% of the ceiling in {refill:.1f} s "
                             f"(bound {RELEASE_BOUND_S:.0f} s)")
                verdict = verdict and refill <= RELEASE_BOUND_S
        if down is not None and up is not None:
            outage_peak, _ = _peak(samples, down, up)
            lines.append(f"redis down {up - down:.0f} s: peak in flight {outage_peak} (fail open)")
        if up is not None:
            after_peak, n = _peak(samples, up + RECOVERY_S, steady_hi)
            lines.append(f"after redis up +{RECOVERY_S:.0f} s: peak={after_peak} samples={n}")
            if not n:
                lines.append("no samples after recovery: the run ended too soon to judge it")
                verdict = False
            else:
                verdict = verdict and after_peak <= bound
        # Transport errors are expected from the killed replica's own loadgen.
    unexpected = {k: v for k, v in errors.items() if k != "429"}
    if unexpected:
        lines.append(f"unexpected http_errors={unexpected}")
    return lines, verdict and not unexpected


def main(argv):
    kind, d = argv[1], argv[2]
    if kind == "s4a":
        lines, ok = s4a(load_reports(d), int(argv[3]), float(argv[4]))
    elif kind == "s4b":
        lines, ok = s4b(load_samples(os.path.join(d, "streams_active.txt")), load_reports(d),
                        load_events(os.path.join(d, "events.txt")), int(argv[3]), float(argv[4]),
                        float(argv[5]), int(argv[6]), len(argv) > 7 and argv[7] == "faults")
    else:
        print(f"unknown verdict: {kind}", file=sys.stderr)
        return 2
    print("\n".join(lines))
    print("INVALID" if ok is None else ("PASS" if ok else "FAIL"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
