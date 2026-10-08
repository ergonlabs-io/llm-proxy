#!/usr/bin/env python3
"""Bounded local storage experiment; no agent integration or persistent migration.

Run make spool-comparison-build first. Fresh directories retain encrypted data,
private test keys, fixture/source snapshots, command lines, timings and failures.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve() / "release/examples/spool_comparison"


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def fixture(escaped=False):
    field = ('"\\\n' * 170)[:510] if escaped else "model-a"
    usage = {"input_tokens": 100, "cache_read_tokens": 0, "cache_write_tokens": 0,
             "output_tokens": 25, "completeness": "complete", "provenance": "upstream"}
    cost = {"amount": 1500, "unit": "nanodollar", "currency": "USD",
            "rate_card_version": "example-v1", "kind": "list"}
    attempt = {"schema_version": 1, "event_id": "seed:attempt:terminal", "request_id": "seed",
               "attempt_id": "seed:attempt", "attempt_index": 0, "trace_id": None,
               "span_id": None, "parent_span_id": None, "cluster": "provider-a", "provider": "example",
               "upstream_model": field, "started_at": "2026-10-08T12:00:00Z",
               "finished_at": "2026-10-08T12:00:01Z", "duration_ms": 1000, "status": 200,
               "termination": "complete", "retry_reason": None, "bytes_request": 100,
               "bytes_response": 500, "usage": usage, "cost": cost}
    attempts = [dict(attempt, attempt_index=n) for n in range(8 if escaped else 1)]
    return {"schema_version": 1, "event_id": "seed:terminal", "request_id": "seed",
            "instance_id": "comparison-instance", "started_at": "2026-10-08T12:00:00Z",
            "finished_at": "2026-10-08T12:00:01Z", "tenant_id": "default", "user_id": None,
            "key_id": None, "trace_id": None, "routing_revision": "example-routing-v1",
            "policy_generation": 1, "capture_policy_version": "example-capture-v1",
            "method": "POST", "route": "/v1/chat/completions", "requested_model": field,
            "selected_cluster": "provider-a", "selected_provider": "example", "selected_model": field,
            "status": 200, "termination": "complete", "error_category": None, "response_flags": [],
            "duration_ms": 1000, "time_to_first_byte_ms": 250, "bytes_request": 100,
            "bytes_response": 500, "usage": usage, "cost": cost, "attempt_count": len(attempts),
            "physical_attempt_count": len(attempts), "attempts": attempts, "attempts_truncated": False}


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def time_report(raw, system):
    if system == "Darwin":
        match = re.search(r"([0-9.]+) real\s+([0-9.]+) user\s+([0-9.]+) sys", raw)
        rss = re.search(r"(\d+)\s+maximum resident set size", raw)
        if not match or not rss:
            raise ValueError("incomplete Darwin time measurements")
        return {"wall_seconds": float(match[1]), "user_seconds": float(match[2]),
                "system_seconds": float(match[3]), "maximum_rss_bytes": int(rss[1])}
    user = re.search(r"User time \(seconds\): ([0-9.]+)", raw)
    sys = re.search(r"System time \(seconds\): ([0-9.]+)", raw)
    rss = re.search(r"Maximum resident set size \(kbytes\): (\d+)", raw)
    if not user or not sys or not rss:
        raise ValueError("incomplete Linux time measurements")
    return {"user_seconds": float(user[1]), "system_seconds": float(sys[1]),
            "maximum_rss_bytes": int(rss[1]) * 1024}


def describe(raw):
    batches = raw["batches"]
    result = {key: value for key, value in raw.items() if key not in ("batches", "growth")}
    result["latency_ms"] = {
        field: {"p50": percentile([b[field] for b in batches], .5),
                "p95": percentile([b[field] for b in batches], .95),
                "p99": percentile([b[field] for b in batches], .99)}
        for field in ("reserve_encrypt_ms", "commit_ms", "durable_batch_ms")}
    result["all_requested_confirmed"] = (raw["confirmed_records"] == raw["requested_records"]
                                         and raw["stopped"] is None)
    result["within_disk_cap"] = raw["final_stats"]["disk_bytes"] <= raw["max_disk_bytes"]
    result["replayed_acknowledged_prefix"] = raw["replay"]["acknowledged_prefix_present"]
    result["bytes_per_confirmed_record"] = (raw["final_stats"]["disk_bytes"] / raw["confirmed_records"]
                                            if raw["confirmed_records"] else None)
    return result


def command(directory, backend, source, key, mode="bench", records=1600, rate=0, stage=""):
    return [str(BIN), "--root", str(directory), "--backend", backend, "--fixture", str(source),
            "--key", str(key), "--mode", mode, "--records", str(records), "--batch", "8",
            "--rate", str(rate), "--disk", "1073741824", "--cache", "8388608", "--stage", stage]


def stop_owned(child):
    if child.poll() is None:
        os.killpg(child.pid, signal.SIGKILL)
    child.wait(timeout=10)


def bench(output, name, backend, source, key, records, rate):
    directory = output / name
    directory.mkdir(mode=0o700)
    cmd = command(directory, backend, source, key, records=records, rate=rate)
    timed = ["/usr/bin/time", "-l" if platform.system() == "Darwin" else "-v", *cmd]
    write_json(directory / "command.json", timed)
    with (directory / "result.json").open("w") as stdout, (directory / "time.txt").open("w") as stderr:
        child = subprocess.Popen(timed, stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            code = child.wait(timeout=max(120, records / rate + 60 if rate else 120))
        finally:
            stop_owned(child)
    if code:
        raise RuntimeError(f"{name} failed; inspect its result.json/time.txt")
    raw = json.loads((directory / "result.json").read_text())
    result = describe(raw)
    result.update(name=name, resources=time_report((directory / "time.txt").read_text(), platform.system()))
    if not result["within_disk_cap"] or not result["replayed_acknowledged_prefix"]:
        raise RuntimeError(f"{name} violated disk/replay contract")
    print(f"{name}: {result['confirmed_records']}/{records} confirmed; "
          f"{result['final_stats']['disk_bytes']} bytes", flush=True)
    return result


def crash(output, backend, source, key, stage):
    name = f"{backend}-sigkill-{stage}"
    directory = output / name
    directory.mkdir(mode=0o700)
    cmd = command(directory, backend, source, key, mode="crash", records=16, stage=stage)
    write_json(directory / "crash-command.json", cmd)
    with (directory / "crash.log").open("w") as log:
        child = subprocess.Popen(cmd, stdout=log, stderr=log, start_new_session=True)
        try:
            deadline = time.monotonic() + 20
            while not (directory / "ready.json").exists():
                if child.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError(f"{name} did not reach kill boundary")
                time.sleep(.01)
            acknowledged = json.loads((directory / "acknowledged.json").read_text())
            os.killpg(child.pid, signal.SIGKILL)
            status = child.wait(timeout=10)
        finally:
            stop_owned(child)
    if status != -signal.SIGKILL:
        raise RuntimeError(f"{name} was not terminated by SIGKILL")
    cmd = command(directory, backend, source, key, mode="recover", records=16)
    write_json(directory / "recover-command.json", cmd)
    with (directory / "recovered.json").open("w") as log:
        subprocess.run(cmd, stdout=log, stderr=subprocess.PIPE, timeout=30, check=True)
    recovered = json.loads((directory / "recovered.json").read_text())
    expected_rows = ((8,) if stage == "after_append" else (16,) if stage == "after_commit" else (8, 16))
    valid = (acknowledged == {"records": 8, "through_sequence": 8}
             and recovered["replay"]["acknowledged_prefix_present"]
             and recovered["replay"]["records"] in expected_rows
             and recovered["next_probe_sequence"] == 17)
    if not valid:
        raise RuntimeError(f"{name} lost acknowledged records or reused a sequence")
    return {"name": name, "sigkill": True, "acknowledged": acknowledged,
            "recovered": recovered, "contract_verified": valid}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--records", type=int, default=1600)
    parser.add_argument("--long-records", type=int, default=12000)
    parser.add_argument("--long-rate", type=float, default=100)
    parser.add_argument("--skip-long", action="store_true")
    args = parser.parse_args()
    if not (1 <= args.repeats <= 5 and 1 <= args.records <= 8000
            and 1 <= args.long_records <= 20000 and math.isfinite(args.long_rate)
            and 5 <= args.long_rate <= 500):
        parser.error("bounded repeats/records/rate required")
    if platform.system() not in ("Darwin", "Linux"):
        parser.error("requires Unix /usr/bin/time")
    output = args.out.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error("output must be empty; preserve prior encrypted spools")
    key = output / "test.key"
    key.write_bytes(os.urandom(32))
    key.chmod(0o600)
    regular, escaped = output / "metadata.json", output / "escaped.json"
    write_json(regular, fixture())
    write_json(escaped, fixture(True))
    changed = subprocess.check_output(["git", "diff", "HEAD"], cwd=ROOT)
    (output / "source.diff").write_bytes(changed)
    (output / "comparison-script.py").write_bytes(Path(__file__).read_bytes())
    # git diff excludes new files; preserve every experiment source explicitly.
    sources = ["crates/proxy-capture-spool/examples/spool_comparison.rs",
               "crates/proxy-capture-spool/tests/support/redb_spool.rs",
               "crates/proxy-capture-spool/tests/redb_spool_prototype.rs"]
    source_hashes = {}
    for name in sources:
        destination = output / "source" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        data = (ROOT / name).read_bytes()
        destination.write_bytes(data)
        source_hashes[name] = hashlib.sha256(data).hexdigest()
    write_json(output / "environment.json", {"commit": subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(), "source_diff_sha256":
        hashlib.sha256(changed).hexdigest(), "source_sha256": source_hashes,
        "binary_sha256": hashlib.sha256(BIN.read_bytes()).hexdigest(), "binary": str(BIN),
        "platform": platform.platform(), "cpu_count": os.cpu_count(),
        "arguments": vars(args) | {"out": str(output)}, "redb_version": "4.2.0",
        "notes": ["Prototype only; production spool unchanged; v2 not implemented.",
                  "Common 1GiB logical byte cap, 512KiB record cap, eight-record batches.",
                  "v1 additionally retains 1024 segments, 64MiB segment cap, 60s age.",
                  "No batching-window/transport/proxy latency measured; storage service times only."]})
    results = {"runs": [], "crash_checks": [], "complete": False}
    try:
        for repetition in range(args.repeats):
            order = ("v1", "redb") if repetition % 2 == 0 else ("redb", "v1")
            for backend in order:
                results["runs"].append(bench(output, f"metadata-{repetition+1}-{backend}", backend,
                                             regular, key, args.records, 0))
                write_json(output / "summary.json", results)
        for backend in ("v1", "redb"):
            results["runs"].append(bench(output, f"escaped-{backend}", backend, escaped, key, 128, 0))
            write_json(output / "summary.json", results)
            stages = ("after_append", "after_commit", "before_sync", "after_sync") if backend == "redb" else ("after_append", "after_commit")
            for stage in stages:
                results["crash_checks"].append(crash(output, backend, regular, key, stage))
                write_json(output / "summary.json", results)
        if not args.skip_long:
            for backend in ("v1", "redb"):
                results["runs"].append(bench(output, f"long-{backend}", backend, regular, key,
                                             args.long_records, args.long_rate))
                write_json(output / "summary.json", results)
        results["complete"] = True
    except Exception as error:
        results["failure"] = str(error)
        raise
    finally:
        write_json(output / "summary.json", results)
    print(f"Evidence: {output}", flush=True)


if __name__ == "__main__":
    main()
