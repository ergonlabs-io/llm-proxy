#!/usr/bin/env python3
"""Compare the two arms of a latency-lab A/B run.

Usage: ab_compare.py RUN_DIR [--json OUT]

RUN_DIR is what scripts/lab/ab-remote.sh wrote: one directory per scenario,
holding `direct/` and `base-rN/`, `cand-rN/` per round.

For each metric it reports every arm's per-round values, their minimum and
median, and a verdict. A change counts only when the two arms' ranges do
not overlap: every candidate round beat every base round, or lost to it.
On a shared host, one before/after pair measures the neighbour; disjoint
ranges across alternated rounds are the evidence that the change did it.
With 4 rounds per arm, chance alone gives disjoint ranges about 3% of the
time (2 / C(8,4)), so treat one flagged metric in a long list with care.
"""
import argparse
import glob
import json
import os
import statistics
import sys

# name -> (path into loadgen.json, scale to display unit, unit, lower is better)
LATENCY = {
    # The fastest request, from send: the floor the proxy adds, free of the
    # queueing that moves p50 and p99 on a busy host.
    "total_min_ms": (("result", "total_from_send_us", "min"), 1e-3, "ms"),
    "total_p50_ms": (("result", "total_from_scheduled_us", "p50"), 1e-3, "ms"),
    "total_p99_ms": (("result", "total_from_scheduled_us", "p99"), 1e-3, "ms"),
    "ttft_p50_ms": (("result", "ttft_from_scheduled_us", "p50"), 1e-3, "ms"),
    "ttft_p99_ms": (("result", "ttft_from_scheduled_us", "p99"), 1e-3, "ms"),
    "inter_token_p50_ms": (("result", "inter_token_us", "p50"), 1e-3, "ms"),
    "inter_token_p99_ms": (("result", "inter_token_us", "p99"), 1e-3, "ms"),
}


def dig(obj, path):
    for key in path:
        if not isinstance(obj, dict) or obj.get(key) is None:
            return None
        obj = obj[key]
    return obj


def metrics(run):
    """Metrics of one arm run (a base-rN or cand-rN directory)."""
    with open(os.path.join(run, "loadgen.json")) as f:
        lg = json.load(f)
    out = {}
    for name, (path, scale, _) in LATENCY.items():
        v = dig(lg, path)
        if v is not None:
            out[name] = v * scale
    res = lg["result"]
    out["errors"] = res["streams_counted"] - res["success"]
    proc_path = os.path.join(run, "proc.json")
    if os.path.exists(proc_path):
        with open(proc_path) as f:
            proc = json.load(f)
        # CPU is measured over the whole run, warm-up included, so divide by
        # every stream started, not only the counted ones.
        started = res["streams_started"] or 1
        out["cpu_ms_per_req"] = 1000 * proc["cpu_ticks"] / proc["clk_tck"] / started
        out["rss_idle_mb"] = proc["rss_idle_kb"] / 1024
        out["rss_peak_mb"] = proc["rss_peak_kb"] / 1024
    return out


UNITS = {**{k: v[2] for k, v in LATENCY.items()},
         "errors": "", "cpu_ms_per_req": "ms", "rss_idle_mb": "MB", "rss_peak_mb": "MB"}


def verdict(base, cand):
    if not base or not cand:
        return "n/a"
    if max(cand) < min(base):
        return "lower"
    if min(cand) > max(base):
        return "higher"
    return "no change"


def compare_scenario(sdir):
    arms = {"base": [], "cand": []}
    for arm in arms:
        for run in sorted(glob.glob(os.path.join(sdir, f"{arm}-r*"))):
            arms[arm].append(metrics(run))
    direct = None
    if os.path.exists(os.path.join(sdir, "direct", "loadgen.json")):
        direct = metrics(os.path.join(sdir, "direct"))
    names = [n for n in UNITS if any(n in m for m in arms["base"] + arms["cand"])]
    table = {}
    for n in names:
        b = [m[n] for m in arms["base"] if n in m]
        c = [m[n] for m in arms["cand"] if n in m]
        row = {
            "unit": UNITS[n],
            "base": [round(x, 3) for x in b],
            "cand": [round(x, 3) for x in c],
            "base_min": round(min(b), 3) if b else None,
            "cand_min": round(min(c), 3) if c else None,
            "base_median": round(statistics.median(b), 3) if b else None,
            "cand_median": round(statistics.median(c), 3) if c else None,
            "verdict": verdict(b, c),
        }
        if b and c:
            row["median_delta"] = round(statistics.median(c) - statistics.median(b), 3)
        if direct and n in direct:
            row["direct"] = round(direct[n], 3)
        table[n] = row
    return {"rounds": {k: len(v) for k, v in arms.items()}, "metrics": table}


def render(report):
    lines = []
    for scen, data in report["scenarios"].items():
        lines.append(f"== {scen}  (rounds: base {data['rounds']['base']}, cand {data['rounds']['cand']})")
        lines.append(f"  {'metric':<20} {'direct':>8} {'base med':>9} {'cand med':>9} {'delta':>8}  verdict")
        for n, r in data["metrics"].items():
            d = r.get("direct")
            fmt = lambda v: "-" if v is None else f"{v:.2f}"
            delta = r.get("median_delta")
            mark = "  <--" if r["verdict"] in ("lower", "higher") else ""
            if n == "errors" and (r["base_median"] or r["cand_median"]):
                mark = "  <-- errors"
            lines.append(
                f"  {n:<20} {fmt(d):>8} {fmt(r['base_median']):>9} {fmt(r['cand_median']):>9} "
                f"{('-' if delta is None else f'{delta:+.2f}'):>8}  {r['verdict']}{mark}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--json")
    args = ap.parse_args()
    report = {"run_dir": args.run_dir, "scenarios": {}}
    manifest = os.path.join(args.run_dir, "manifest.txt")
    if os.path.exists(manifest):
        with open(manifest) as f:
            report["manifest"] = f.read().strip().splitlines()
    for sdir in sorted(glob.glob(os.path.join(args.run_dir, "*", ""))):
        if glob.glob(os.path.join(sdir, "base-r*")):
            report["scenarios"][os.path.basename(sdir.rstrip("/"))] = compare_scenario(sdir)
    if not report["scenarios"]:
        print(f"no scenario results under {args.run_dir}", file=sys.stderr)
        return 1
    print("\n".join(report.get("manifest", [])))
    print(render(report))
    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
