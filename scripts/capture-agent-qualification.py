#!/usr/bin/env python3
"""Eight concurrent maximum-record producers against the production local agent.

Keeps private encrypted spools and test keys. No remote delivery or reclamation.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


QUAL = module("capture_qualification", "capture-qualification.py")
RETENTION = module("redb_retention", "redb-retention.py")


def receive(sock, kind):
    def exact(size):
        data = bytearray()
        while len(data) < size:
            part = sock.recv(size - len(data))
            if not part:
                raise RuntimeError("agent closed before receipt")
            data.extend(part)
        return data
    header = exact(9)
    length = int.from_bytes(header[5:], "big")
    if header[:4] != b"LMC1" or header[4] != kind or not 0 < length <= 1024:
        raise RuntimeError("invalid agent control frame")
    return json.loads(exact(length))


def send(sock, kind, payload):
    sock.sendall(b"LMC1" + bytes([kind]) + len(payload).to_bytes(4, "big") + payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--rounds", type=int, default=16)
    args = parser.parse_args()
    if not 1 <= args.rounds <= 64:
        parser.error("rounds must be 1..=64")
    output = args.out.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error("output must be empty; preserve prior spools")
    runtime = Path(tempfile.mkdtemp(prefix="cam-", dir="/private/tmp"))
    runtime.chmod(0o700)
    key = runtime / "key"
    key.write_bytes(os.urandom(32))
    key.chmod(0o600)
    config = {"version": 1, "mode": "metadata_spool_only", "socket_path": str(runtime / "agent.sock"),
              "node_id": "maximum-qualification", "producers": [{"producer_id": "maximum-producer",
              "uid": os.getuid(), "tenants": ["default"]}],
              "spool": {"directory": str(output / "spool"), "max_record_bytes": 524288,
                        "max_disk_bytes": 1073741824, "cache_bytes": 4194304},
              "active_key_id": "qualification-key",
              "keys": [{"key_id": "qualification-key", "key_file": str(key)}]}
    QUAL.write_json(output / "agent.json", config)
    binary = QUAL.BIN / "llm-capture-agent"
    QUAL.write_json(output / "environment.json", {
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=QUAL.ROOT, text=True).strip(),
        "binary": str(binary), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "helpers_sha256": {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                           for name in ("capture-qualification.py", "redb-retention.py")},
        "rounds": args.rounds, "peers": 8, "record_bytes": 524288,
        "memory_cap_bytes": 268435456, "disk_cap_bytes": 1073741824})
    (output / "qualification-script.py").write_bytes(Path(__file__).read_bytes())
    for name in ("capture-qualification.py", "redb-retention.py"):
        (output / name).write_bytes(Path(__file__).with_name(name).read_bytes())
    (output / "source.diff").write_bytes(subprocess.check_output(
        ["git", "diff", "HEAD", "--", "crates", "Cargo.toml", "Cargo.lock"], cwd=QUAL.ROOT))
    template = RETENTION.maximum_record_fixture()
    # Construct payloads before measurement, outside the independently resourced agent.
    payloads = [RETENTION.compact_json(RETENTION.qualified_fixture(template, index))
                for index in range(8 * args.rounds)]
    assert all(len(payload) == 524288 for payload in payloads)
    QUAL.write_json(output / "payload-sha256.json", [hashlib.sha256(payload).hexdigest() for payload in payloads])
    processes = QUAL.Processes(output)
    samples = []
    receipts = []
    barrier = threading.Barrier(8, timeout=5)
    result = {"requested_records": len(payloads), "record_bytes": 524288, "peers": 8}
    try:
        agent = processes.start("agent", [binary, "--config", output / "agent.json"])
        QUAL.wait_for(agent, lambda: (runtime / "agent.sock").exists(), "agent")
        started = time.monotonic()

        def producer(peer):
            acknowledgements = []
            with socket.socket(socket.AF_UNIX) as sock:
                sock.settimeout(5)
                sock.connect(str(runtime / "agent.sock"))
                send(sock, 1, json.dumps({"version": 1, "producer_id": "maximum-producer"}).encode())
                if receive(sock, 2) != {"version": 1, "node_id": "maximum-qualification"}:
                    raise RuntimeError("agent identity mismatch")
                for round_index in range(args.rounds):
                    index = round_index * 8 + peer
                    barrier.wait()
                    send(sock, 3, payloads[index])
                    receipt = receive(sock, 4)
                    if (receipt.get("version") != 1 or receipt.get("node_id") != "maximum-qualification"
                            or receipt.get("outcome") != "durable"
                            or receipt.get("event_id") != f"retention-{index:08}:terminal"
                            or not isinstance(receipt.get("sequence"), int) or receipt["sequence"] <= 0):
                        raise RuntimeError("missing matching durable receipt")
                    acknowledgements.append(receipt)
            return acknowledgements

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(producer, peer) for peer in range(8)]
            while not all(future.done() for future in futures):
                if time.monotonic() - started > 60:
                    barrier.abort()
                    raise TimeoutError("maximum-record workload exceeded 60 seconds")
                samples.append({"elapsed_seconds": time.monotonic() - started,
                                **QUAL.process_usage(processes.children)})
                time.sleep(.02)
            for future in futures:
                receipts.extend(future.result())
        samples.append({"elapsed_seconds": time.monotonic() - started,
                        **QUAL.process_usage(processes.children)})
        result["confirmed_records"] = len(receipts)
        result["unique_sequences"] = len({receipt["sequence"] for receipt in receipts})
        result["peak_agent_rss_bytes"] = max(sample["rss_bytes"].get("agent", 0) for sample in samples)
        result["cpu"] = QUAL.cpu_summary(samples, 0, float("inf"))
        result["disk_bytes"] = sum(p.stat().st_size for p in (output / "spool").rglob("*") if p.is_file())
        result["first_teardown"] = processes.close()
        if (runtime / "agent.sock").exists() or any(item.get("forced_kill") or item.get("returncode", 0) != 0
                                                   for item in result["first_teardown"]):
            raise RuntimeError("agent did not shut down cleanly before authenticated reopen")
        reopen_started = time.monotonic()
        reopened = processes.start("agent-reopened", [binary, "--config", output / "agent.json"])
        def reopen_ready():
            samples.append({"elapsed_seconds": time.monotonic() - started,
                            **QUAL.process_usage(processes.children)})
            return (runtime / "agent.sock").exists()
        QUAL.wait_for(reopened, reopen_ready, "reopened agent")
        result["authenticated_reopen_ms"] = 1000 * (time.monotonic() - reopen_started)
        result["peak_agent_rss_bytes"] = max(result["peak_agent_rss_bytes"],
            max(sample["rss_bytes"].get("agent-reopened", 0) for sample in samples))
        result["cpu"] = QUAL.cpu_summary(samples, 0, float("inf"))
        result["qualification_passed"] = (
            result["confirmed_records"] == result["unique_sequences"] == len(payloads)
            and 0 < result["peak_agent_rss_bytes"] <= 268435456
            and result["disk_bytes"] <= 1073741824 and bool(result["cpu"]))
        if not result["qualification_passed"]:
            raise RuntimeError("maximum-record qualification failed its acceptance limits")
    except Exception as error:
        result["failure"] = str(error)
        result["qualification_passed"] = False
        raise
    finally:
        result["samples"] = samples
        result["receipts"] = receipts
        result["teardown"] = processes.close()
        QUAL.write_json(output / "measurements.json", result)
    print(json.dumps({key: result[key] for key in ("qualification_passed", "confirmed_records",
          "peak_agent_rss_bytes", "disk_bytes", "authenticated_reopen_ms", "cpu")}, indent=2))


if __name__ == "__main__":
    main()
