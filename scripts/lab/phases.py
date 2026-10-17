#!/usr/bin/env python3
"""Per-phase latency from a latency-lab run's access logs.

Usage: phases.py RUN_DIR [--json OUT] [--skip-s N]
       phases.py ACCESS_LOG [--skip-s N]

RUN_DIR is what scripts/lab/ab-remote.sh wrote with ACCESS_LOG=json|text:
an access.log in each logging arm's directory. Each line carries the
dialect's `timing_us` phases (%COMMON_DURATION%, in microseconds, in request
order), and this prints p50 and p99 of each, per scenario and arm, pooled
over that arm's rounds.

Two derived columns sit beside the phases:

- `proxy`: the sum of the phases less `us_wait`, per request. `us_wait` is
  the upstream's own time to response headers (the mock's TTFT), so `proxy`
  is the time the request spent in the proxy or on the loopback hops. It is
  a per-request sum, so its p50 is not the sum of the phase p50s.
- `total`: the sum of every phase but `us_connect`. The phases are
  consecutive, so this is DS_RX_BEG to DS_TX_END: the request's whole time
  between the proxy's codec reading it and writing the last byte back.
  (%DURATION% is whole milliseconds, too coarse at this scale.)

The log holds the warm-up requests too, which loadgen leaves out of its own
numbers. --skip-s drops the requests that started in the first N seconds of
each log; the default is the run's warm-up from manifest.txt, else 5.
"""
import argparse
import datetime
import glob
import json
import os
import re
import sys

PHASES = ["ds_rx", "pre_upstream", "us_connect", "us_tx", "us_wait", "resp_head", "ds_tx"]
TEXT_START = re.compile(r"^\[([^\]]+)\]")
TEXT_TIMING = re.compile(r'timing_us="([^"]*)"')


def parse_time(value):
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()
    except (TypeError, ValueError):
        return None


def micros(value):
    """A phase value: an integer, or None for `-` (a point never reached)."""
    if value is None or value == "-":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def records(path):
    """(start, {phase: us or None}) per log line."""
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                rec = json.loads(line)
                phases = {p: micros(rec.get(f"{p}_us")) for p in PHASES}
                yield parse_time(rec.get("start_time")), phases
            else:
                start, timing = TEXT_START.match(line), TEXT_TIMING.search(line)
                if not timing:
                    continue
                kv = dict(f.split("=", 1) for f in timing.group(1).split() if "=" in f)
                phases = {p: micros(kv.get(p)) for p in PHASES}
                yield parse_time(start.group(1)) if start else None, phases


def load(path, skip_s):
    rows = list(records(path))
    starts = [r[0] for r in rows if r[0] is not None]
    if starts and skip_s > 0:
        cutoff = min(starts) + skip_s
        rows = [r for r in rows if r[0] is None or r[0] >= cutoff]
    return rows


def pct(values, q):
    if not values:
        return None
    values = sorted(values)
    return values[min(len(values) - 1, int(q * len(values)))]


def summarize(rows):
    cols = {p: [] for p in PHASES + ["proxy", "total"]}
    for _, phases in rows:
        for p in PHASES:
            if phases[p] is not None:
                cols[p].append(phases[p])
        # A request that never reached a phase (a local reply) has no proxy
        # sum; us_connect is left out because a reused connection repeats
        # the connect from when it was dialed, and a real connect is inside
        # pre_upstream already.
        consecutive = [phases[p] for p in PHASES if p != "us_connect"]
        if all(v is not None for v in consecutive):
            cols["total"].append(sum(consecutive))
            cols["proxy"].append(sum(consecutive) - phases["us_wait"])
    return {
        "requests": len(rows),
        "phases": {
            name: {"n": len(v), "p50_us": pct(v, 0.50), "p99_us": pct(v, 0.99)}
            for name, v in cols.items() if v
        },
    }


def render(title, summary):
    lines = [f"== {title}  ({summary['requests']} requests)",
             f"  {'phase':<14} {'p50 us':>9} {'p99 us':>9}"]
    for name, s in summary["phases"].items():
        lines.append(f"  {name:<14} {s['p50_us']:>9} {s['p99_us']:>9}")
    return "\n".join(lines)


def manifest_warmup(run_dir):
    try:
        with open(os.path.join(run_dir, "manifest.txt")) as f:
            m = re.search(r"warmup: (\d+)s", f.read())
            return int(m.group(1)) if m else None
    except OSError:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--json")
    ap.add_argument("--skip-s", type=float)
    args = ap.parse_args()

    if os.path.isfile(args.path):
        skip = 0 if args.skip_s is None else args.skip_s
        print(render(args.path, summarize(load(args.path, skip))))
        return 0

    skip = args.skip_s
    if skip is None:
        skip = manifest_warmup(args.path) or 5
    report = {"run_dir": args.path, "skip_s": skip, "scenarios": {}}
    out = []
    for sdir in sorted(glob.glob(os.path.join(args.path, "*", ""))):
        scen = os.path.basename(sdir.rstrip("/"))
        for arm in ("base", "cand"):
            logs = sorted(glob.glob(os.path.join(sdir, f"{arm}-r*", "access.log")))
            if not logs:
                continue
            rows = [r for log in logs for r in load(log, skip)]
            summary = summarize(rows)
            summary["rounds"] = len(logs)
            report["scenarios"].setdefault(scen, {})[arm] = summary
            out.append(render(f"{scen} {arm} ({len(logs)} rounds pooled)", summary))
    if not out:
        print(f"no access.log under {args.path}", file=sys.stderr)
        return 1
    print("\n".join(out))
    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
