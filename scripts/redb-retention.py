#!/usr/bin/env python3
"""Qualify bounded retention and replay through the production redb spool.

The executable is built by the repository's `make redb-retention-build` target.
Every run uses a fresh directory and keeps its encrypted spool and private test
key for later inspection. No record is acknowledged or evicted.
"""
import argparse
import hashlib
import importlib.util
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
MAX_RECORD_BYTES = 512 * 1024
MAX_DISK_BYTES = 1024 * 1024 * 1024
MAX_RSS_BYTES = 256 * 1024 * 1024
BIN = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve() / "release/examples/redb_retention"
PREVIOUS_EXPERIMENT = ROOT / "scripts/spool-comparison.py"
SPEC = importlib.util.spec_from_file_location("previous_spool_comparison", PREVIOUS_EXPERIMENT)
PREVIOUS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREVIOUS)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def compact_json(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def qualified_fixture(value, index):
    result = json.loads(json.dumps(value))
    event = f"retention-{index:08}"
    result["event_id"] = f"{event}:terminal"
    result["request_id"] = event
    for offset, attempt in enumerate(result.get("attempts", [])):
        attempt["event_id"] = f"{event}:attempt:{offset}"
        attempt["request_id"] = event
        attempt["attempt_id"] = f"{event}:attempt:{offset}"
    return result


def maximum_record_fixture():
    # Saturate valid bounded strings across all 64 retained attempts. A single
    # oversized route would exercise opaque storage but fail agent validation.
    value = PREVIOUS.fixture(escaped=True)
    template = value["attempts"][0]
    value["attempts"] = [dict(template, attempt_index=n) for n in range(64)]
    value["attempt_count"] = value["physical_attempt_count"] = 64
    slots = [(attempt, field) for attempt in value["attempts"]
             for field in ("cluster", "provider", "upstream_model", "retry_reason")]
    slots.extend((value, field) for field in (
        "route", "requested_model", "selected_cluster", "selected_provider", "selected_model"))
    for owner, field in slots:
        owner[field] = ""
    remaining = MAX_RECORD_BYTES - len(compact_json(qualified_fixture(value, 0)))
    if remaining < 0:
        raise ValueError("base maximum fixture already exceeds record cap")
    for owner, field in slots:
        escaped_chars = min(512, remaining // 6)
        owner[field] = "\u0001" * escaped_chars
        remaining -= escaped_chars * 6
        ascii_chars = min(512 - escaped_chars, remaining)
        owner[field] += "r" * ascii_chars
        remaining -= ascii_chars
    if remaining or len(compact_json(qualified_fixture(value, 0))) != MAX_RECORD_BYTES:
        raise ValueError("could not construct exact bounded maximum fixture")
    return value


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
    wall = re.search(r"Elapsed \(wall clock\) time .*: ([0-9:]+(?:\.[0-9]+)?)", raw)
    if not user or not sys or not rss:
        raise ValueError("incomplete Linux time measurements")
    return {"wall_time": wall[1] if wall else None, "user_seconds": float(user[1]),
            "system_seconds": float(sys[1]), "maximum_rss_bytes": int(rss[1]) * 1024}


def stop_owned(child):
    if child.poll() is None:
        os.killpg(child.pid, signal.SIGKILL)
    child.wait(timeout=10)


def source_snapshot(output):
    changed = subprocess.check_output(["git", "diff", "HEAD"], cwd=ROOT)
    (output / "source.diff").write_bytes(changed)
    (output / "commit.txt").write_text(
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() + "\n"
    )
    status = subprocess.check_output(["git", "status", "--short"], cwd=ROOT, text=True)
    (output / "source.status").write_text(status)
    tracked = [
        "Cargo.toml",
        "Cargo.lock",
        "crates/proxy-capture-spool/Cargo.toml",
        "crates/proxy-capture-spool/src/lib.rs",
        "crates/proxy-capture-spool/src/format.rs",
        "crates/proxy-capture-spool/src/storage.rs",
        "crates/proxy-capture-spool/examples/redb_retention.rs",
        "scripts/redb-retention.py",
        "scripts/test_redb_retention.py",
        "scripts/spool-comparison.py",
    ]
    hashes = {}
    for name in tracked:
        source = ROOT / name
        destination = output / "source" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        content = source.read_bytes()
        destination.write_bytes(content)
        hashes[name] = hashlib.sha256(content).hexdigest()
    for name in ("regular.json", "escaped.json", "maximum-record.json"):
        source = output / "fixtures" / name
        hashes[f"fixtures/{name}"] = hashlib.sha256(source.read_bytes()).hexdigest()
    return changed, hashes, status


def run_one(output, name, fixture_path, records, rate):
    directory = output / name
    directory.mkdir(mode=0o700)
    key = output / "test.key"
    command = [str(BIN), "--root", str(directory), "--fixture", str(fixture_path),
               "--key", str(key), "--records", str(records), "--rate", str(rate)]
    timed = ["/usr/bin/time", "-l" if platform.system() == "Darwin" else "-v", *command]
    stdout_path, stderr_path = directory / "result.json", directory / "time.txt"
    write_json(directory / "command.json", timed)
    with stdout_path.open("w") as stdout, stderr_path.open("w") as stderr:
        child = subprocess.Popen(timed, stdout=stdout, stderr=stderr, start_new_session=True)
        paced_seconds = records / rate if rate else records / 500
        deadline = time.monotonic() + paced_seconds + 120
        try:
            code = child.wait(timeout=deadline - time.monotonic())
        finally:
            stop_owned(child)
    try:
        raw = json.loads(stdout_path.read_text())
    except (ValueError, OSError) as error:
        raw = {"requested_records": records, "confirmed_records": 0,
               "stopped": f"process result unavailable: {error}", "max_disk_bytes": MAX_DISK_BYTES}
    raw["name"] = name
    try:
        raw["resources"] = time_report(stderr_path.read_text(), platform.system())
    except (ValueError, OSError) as error:
        raw["resources"] = {"measurement_error": str(error)}
    raw["artifacts"] = {
        "result": str(stdout_path),
        "time": str(stderr_path),
        "command": str(directory / "command.json"),
        "fixture": str(fixture_path),
        "database": str(directory / "spool/capture.redb"),
        "key_reference": str(key),
    }
    if code:
        raw["process_exit_code"] = code
        raw["stopped"] = raw.get("stopped") or f"qualification process exited {code}"
    return raw


def summarize(runs):
    run_summaries = []
    for run in runs:
        replay = run.get("replay", {})
        stats = run.get("final_stats", {})
        resources = run.get("resources", {})
        confirmed = run.get("confirmed_records", 0)
        batches = run.get("batches", [])
        run_summaries.append({
            "name": run.get("name"),
            "requested_records": run.get("requested_records"),
            "confirmed_records": confirmed,
            "stopped": run.get("stopped"),
            "disk_bytes": stats.get("disk_bytes"),
            "max_disk_bytes": run.get("max_disk_bytes"),
            "maximum_rss_bytes": resources.get("maximum_rss_bytes"),
            "replayed_records": replay.get("records"),
            "verified_records": replay.get("verified_records"),
            "batch_latency_ms": {
                key: {quantile: percentile([batch[key] for batch in batches if key in batch], q)
                      for quantile, q in (("p50", .50), ("p95", .95), ("p99", .99))}
                for key in ("reserve_encrypt_ms", "commit_ms", "durable_batch_ms")
            },
            "recovery_duration_ms": run.get("recovery_duration_ms"),
            "artifacts": run.get("artifacts", {}),
        })
    disk_ok = bool(run_summaries) and all(
        isinstance(run["disk_bytes"], int) and isinstance(run["max_disk_bytes"], int)
        and 0 <= run["disk_bytes"] <= run["max_disk_bytes"] <= MAX_DISK_BYTES
        for run in run_summaries)
    memory_ok = bool(run_summaries) and all(
        isinstance(run["maximum_rss_bytes"], int) and 0 < run["maximum_rss_bytes"] <= MAX_RSS_BYTES
        for run in run_summaries)
    all_confirmed = bool(run_summaries) and all(run["confirmed_records"] == run["requested_records"] and not run["stopped"]
                        for run in run_summaries)
    replay_ok = all(run["replayed_records"] == run["confirmed_records"]
                    and run["verified_records"] == run["confirmed_records"] for run in run_summaries)
    artifact_paths_exist = bool(run_summaries) and all(
        run["artifacts"] and all(Path(path).exists() for path in run["artifacts"].values())
        for run in run_summaries)
    return {
        "runs": run_summaries,
        "all_requested_confirmed": all_confirmed,
        "within_disk_cap": disk_ok,
        "within_memory_cap": memory_ok,
        "all_replayed_records_verified": replay_ok,
        "all_artifact_paths_exist": artifact_paths_exist,
        "qualification_passed": all((all_confirmed, disk_ok, memory_ok, replay_ok, artifact_paths_exist)),
        "limits": {"max_record_bytes": MAX_RECORD_BYTES, "max_disk_bytes": MAX_DISK_BYTES,
                   "max_rss_bytes": MAX_RSS_BYTES, "pending_batch_records": 8,
                   "cache_bytes": 4 * 1024 * 1024, "acknowledgement": "none",
                   "automatic_eviction": False},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--records", type=int, default=60_000)
    parser.add_argument("--rate", type=int, default=100)
    args = parser.parse_args()
    if not 1 <= args.records <= 100_000 or not 0 <= args.rate <= 500:
        parser.error("records must be 1..=100000 and rate must be 0..=500")
    if platform.system() not in ("Darwin", "Linux"):
        parser.error("requires Unix /usr/bin/time")
    if not BIN.is_file():
        parser.error(f"missing executable {BIN}; run make redb-retention-build")
    output = args.out.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error("output must be empty; preserve prior encrypted spools")
    key = output / "test.key"
    key.write_bytes(os.urandom(32))
    key.chmod(0o600)
    fixtures = output / "fixtures"
    regular = fixtures / "regular.json"
    escaped = fixtures / "escaped.json"
    maximum = fixtures / "maximum-record.json"
    write_json(regular, PREVIOUS.fixture())
    write_json(escaped, PREVIOUS.fixture(escaped=True))
    write_json(maximum, maximum_record_fixture())
    changed, source_hashes, status = source_snapshot(output)
    binary_hash = hashlib.sha256(BIN.read_bytes()).hexdigest()
    environment = {
        "commit": (output / "commit.txt").read_text().strip(),
        "source_diff_sha256": hashlib.sha256(changed).hexdigest(),
        "source_sha256": source_hashes,
        "binary_sha256": binary_hash,
        "binary": str(BIN),
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "arguments": {"out": str(output), "records": args.records, "rate": args.rate},
        "key_reference": str(key),
        "git_status": status.splitlines(),
        "notes": [
            "Production MetadataSpool API and encrypted redb format; no prototype adapter.",
            "All runs use the same 1 GiB logical disk cap, 512 KiB record cap, batches of eight, and 4 MiB cache.",
            "No acknowledgement or automatic eviction occurs; all confirmed records are replayed and byte-compared.",
        ],
    }
    write_json(output / "environment.json", environment)
    runs = []
    try:
        for name, fixture_path, records, rate in (
            ("regular", regular, args.records, args.rate),
            ("escaped", escaped, 128, 0),
            ("maximum-record", maximum, 8, 0),
        ):
            runs.append(run_one(output, name, fixture_path, records, rate))
            report = summarize(runs)
            write_json(output / "summary.json", {"environment": environment, **report, "complete": False})
    except Exception as error:
        write_json(output / "summary.json", {"environment": environment, **summarize(runs),
                                             "failure": str(error), "complete": False})
        raise
    final = {"environment": environment, **summarize(runs), "complete": True}
    write_json(output / "summary.json", final)
    print(json.dumps({key: final[key] for key in (
        "qualification_passed", "all_requested_confirmed", "within_disk_cap",
        "within_memory_cap", "all_replayed_records_verified")}, indent=2))


if __name__ == "__main__":
    main()
