#!/usr/bin/env python3
"""Finite local-spool qualification using the existing omission-aware loadgen.

Build with make capture-qualification-build. No real providers, remote stores,
host sysctl changes, or production sockets. Keeps encrypted test spools, logs,
configs and raw measurements; never reclaims committed data to improve results.
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
import socket
import statistics
import subprocess
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve() / "release"
METRIC = re.compile(r"^(envoy_llmproxy_(?:capture|metadata)_[^{ ]+)(\{[^}]*\})?\s+([0-9.eE+-]+)$")


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def http(port, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=2) as reply:
        return reply.read().decode()


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def control(path, command):
    def read_exact(sock, size):
        data = b""
        while len(data) < size:
            part = sock.recv(size - len(data))
            if not part:
                raise RuntimeError("control socket closed")
            data += part
        return data
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(2)
        sock.connect(str(path))
        payload = json.dumps(command).encode()
        sock.sendall(len(payload).to_bytes(4, "big") + payload)
        length = int.from_bytes(read_exact(sock, 4), "big")
        if not 0 < length <= 1024:
            raise RuntimeError("invalid control response size")
        return json.loads(read_exact(sock, length))


class Processes:
    def __init__(self, directory):
        self.directory = directory
        self.children = []

    def start(self, name, command):
        with (self.directory / f"{name}.log").open("w") as log:
            child = subprocess.Popen([str(x) for x in command], stdout=log, stderr=log,
                                     env={**os.environ, "TOKIO_WORKER_THREADS": "4", "RUST_LOG": "warn"})
        self.children.append((name, child))
        return child

    def close(self):
        outcomes = []
        for name, child in reversed(self.children):
            if child.poll() is None:
                child.send_signal(signal.SIGCONT)
                child.terminate()
                try:
                    child.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
                    outcomes.append({"name": name, "forced_kill": True})
            outcomes.append({"name": name, "pid": child.pid, "returncode": child.returncode})
        return outcomes


def wait_for(child, predicate, label):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError(f"{label} exited early: {child.returncode}")
        try:
            if predicate():
                return
        except (OSError, ValueError):
            pass
        time.sleep(.1)
    raise TimeoutError(f"{label} not ready")


def bootstrap(listener, admin, upstream, capture, protocol):
    node = "node:\n  id: qualification\n  cluster: local\n"
    if capture is not None:
        node += f"  metadata:\n    io.llmproxy.capture: {json.dumps(capture)}\n"
    h2 = ""
    if protocol == "http2":
        h2 = '''      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config:
            http2_protocol_options: {}
'''
    return node + f'''admin:
  address:
    socket_address: {{address: 127.0.0.1, port_value: {admin}}}
static_resources:
  listeners:
    - name: ingress
      address:
        socket_address: {{address: 127.0.0.1, port_value: {listener}}}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress
                route_config:
                  name: local
                  virtual_hosts:
                    - name: mock
                      domains: ["*"]
                      routes:
                        - match: {{prefix: "/"}}
                          route: {{cluster: mock, timeout: 60s}}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
    - name: mock
      type: STATIC
      connect_timeout: 5s
      circuit_breakers:
        thresholds:
          - priority: DEFAULT
            max_connections: 10000
            max_pending_requests: 10000
            max_requests: 10000
{h2}      load_assignment:
        cluster_name: mock
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{address: 127.0.0.1, port_value: {upstream}}}
'''


def metrics(admin):
    values = {}
    for line in http(admin, "/stats/prometheus").splitlines():
        match = METRIC.match(line)
        if match:
            values[match[1] + (match[2] or "")] = float(match[3])
    if not values:
        raise RuntimeError("capture metrics missing from scrape")
    return values


def rss(children):
    live = [(name, child) for name, child in children if child.poll() is None]
    if not live:
        return {}
    output = subprocess.check_output(["ps", "-o", "pid=,rss=", "-p",
                                      ",".join(str(child.pid) for _, child in live)], text=True, timeout=2)
    by_pid = {int(row.split()[0]): int(row.split()[1]) * 1024
              for row in output.splitlines() if len(row.split()) == 2}
    return {name: by_pid[child.pid] for name, child in live if child.pid in by_pid}


def scenario(output, name, state, rate, duration, warmup, memory=False):
    directory = output / name
    directory.mkdir(mode=0o700)
    processes = Processes(directory)
    # macOS temp paths can exceed sockaddr_un's 103-byte filesystem limit.
    runtime = Path(tempfile.mkdtemp(prefix="cq-", dir="/private/tmp"))
    os.chmod(runtime, 0o700)
    write_json(directory / "runtime-path.json", {"path": str(runtime)})
    samples = []
    result = {"name": name, "state": state, "rate": rate, "duration": duration,
              "warmup": warmup, "memory_stress": memory, "samples": samples}
    try:
        mock = processes.start("mock", [BIN / "mock-upstream", "--listen", "127.0.0.1:0",
                                       "--protocol", "auto", "--tokens", "1" if memory else "16",
                                       "--ttft-ms", "20000" if memory else "250",
                                       "--inter-token-ms", "0" if memory else "25"])
        def mock_ready():
            return "listening on" in (directory / "mock.log").read_text()
        wait_for(mock, mock_ready, "mock")
        upstream = int(re.search(r"listening on 127.0.0.1:(\d+)", (directory / "mock.log").read_text())[1])
        agent = None
        if state in ("on", "pause"):
            key = runtime / "key"
            key.write_bytes(os.urandom(32))
            key.chmod(0o600)
            agent_config = {"version": 1, "mode": "metadata_spool_only",
                            "socket_path": str(runtime / "agent.sock"), "node_id": "qualification-node",
                            "producers": [{"producer_id": "qualification-proxy", "uid": os.getuid(), "tenants": ["default"]}],
                            "spool": {"directory": str(directory / "spool"), "max_record_bytes": 524288,
                                      "max_segment_bytes": 67108864, "max_disk_bytes": 1073741824,
                                      "max_segments": 1024, "max_segment_age_seconds": 60},
                            "active_key_id": "qualification-key",
                            "keys": [{"key_id": "qualification-key", "key_file": str(key)}]}
            write_json(directory / "agent.json", agent_config)
            agent = processes.start("agent", [BIN / "llm-capture-agent", "--config", directory / "agent.json"])
            wait_for(agent, lambda: (runtime / "agent.sock").exists(), "agent")
        capture = None
        if state != "off":
            capture = {"version": 1, "metadata": {"enabled": True}, "policy": {"version": "qualification"},
                       "endpoint": {"unix_socket_path": str(runtime / "agent.sock"), "expected_agent_uid": os.getuid(),
                                    "expected_node_id": "qualification-node", "producer_id": "qualification-proxy"},
                       "emergency_control": {"unix_socket_path": str(runtime / "control.sock"), "operator_uid": os.getuid()}}
        listener, admin = port(), port()
        if listener == admin:
            raise RuntimeError("ephemeral ports collided; rerun")
        config = directory / "proxy.yaml"
        config.write_text(bootstrap(listener, admin, upstream, capture, "http1" if memory else "http2"))
        subprocess.run([BIN / "llm-proxy", "-c", config, "--mode", "validate", "--concurrency", "4"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=True)
        proxy = processes.start("proxy", [BIN / "llm-proxy", "-c", config, "--concurrency", "4",
                                           "--drain-time-s", "1", "--drain-strategy", "immediate"])
        wait_for(proxy, lambda: http(admin, "/ready").strip() == "LIVE", "proxy")
        result["metrics_before"] = metrics(admin)
        result["rss_before"] = rss(processes.children)
        pool_size = 6000 if memory else (512 if rate >= 200 else 128)
        load = processes.start("loadgen", [BIN / "loadgen", "--target", f"http://127.0.0.1:{listener}",
                                           "--endpoint", "chat", "--model", "qualification-default", "--rate", str(rate),
                                           "--duration", str(duration), "--warmup", str(warmup), "--timeout", "45",
                                           "--downstream-mode", "h1-pool", "--downstream-h1-pool-size", str(pool_size),
                                           "--out", directory / "loadgen.json"])
        started = time.monotonic()
        paused = resumed = disabled = False
        while load.poll() is None or time.monotonic() - started < duration + 12:
            elapsed = time.monotonic() - started
            if elapsed > duration + 50:
                raise TimeoutError("loadgen exceeded bounded run deadline")
            if state == "pause" and not paused and elapsed >= 5:
                agent.send_signal(signal.SIGSTOP)
                paused = True
                result["agent_pause_seconds"] = elapsed
            if paused and not resumed and elapsed >= max(15, duration / 2):
                agent.send_signal(signal.SIGCONT)
                resumed = True
                result["agent_resume_seconds"] = elapsed
            if memory and capture and not disabled and elapsed >= duration + 1:
                status = control(runtime / "control.sock", {"command": "Status"})
                result["control_before_disable"] = status
                result["control_disable"] = control(runtime / "control.sock", {
                    "command": "Disable", "expected_generation": status["generation"]})
                result["disable_seconds"] = elapsed
                disabled = True
            sample = {"rss_bytes": rss(processes.children), "metrics": metrics(admin)}
            sample["elapsed_seconds"] = time.monotonic() - started
            samples.append(sample)
            time.sleep(.5)
        if load.wait(timeout=2) != 0:
            raise RuntimeError(f"loadgen failed; inspect {directory / 'loadgen.log'}")
        result["loadgen"] = json.loads((directory / "loadgen.json").read_text())
        result["metrics_after"] = metrics(admin)
        if capture:
            result["control_after"] = control(runtime / "control.sock", {"command": "Status"})
        result["peak_rss_bytes"] = {name: max(sample["rss_bytes"].get(name, 0) for sample in samples)
                                    for name, _ in processes.children}
        result["peak_metrics"] = {key: max(sample["metrics"].get(key, 0) for sample in samples)
                                  for key in result["metrics_after"]}
        result["spool_file_bytes"] = sum(p.stat().st_size for p in (directory / "spool").rglob("*") if p.is_file())
    finally:
        result["teardown"] = processes.close()
        write_json(directory / "measurements.json", result)
    print(json.dumps({"completed": name, "peak_rss_bytes": result["peak_rss_bytes"],
                      "error_rate": result["loadgen"]["result"]["error_rate"]}), flush=True)
    return result


def summarize(runs):
    comparisons = []
    for rate in sorted({r["rate"] for r in runs if not r["memory_stress"] and r["state"] == "off"}):
        baseline = [r for r in runs if r["rate"] == rate and r["state"] == "off" and not r["memory_stress"]]
        enabled = [r for r in runs if r["rate"] == rate and r["state"] == "on"]
        comparison = {"rate": rate, "baseline_runs": [r["name"] for r in baseline],
                      "enabled_runs": [r["name"] for r in enabled]}
        for field in ("ttft_from_scheduled_us", "total_from_scheduled_us"):
            off = statistics.median(r["loadgen"]["result"][field]["p99"] for r in baseline)
            on = statistics.median(r["loadgen"]["result"][field]["p99"] for r in enabled)
            comparison[field] = {"off_median_p99_us": off, "on_median_p99_us": on,
                                 "regression_percent": (on / off - 1) * 100,
                                 "within_provisional_5_percent": on <= off * 1.05}
        comparisons.append(comparison)
    def metric(run, name, labels="", peak=False):
        return run["peak_metrics" if peak else "metrics_after"].get("envoy_llmproxy_" + name + labels, 0)

    def describe(run):
        result = run["loadgen"]["result"]
        samples = [sample for sample in run["samples"]
                   if run["warmup"] <= sample["elapsed_seconds"] <= run["duration"]]
        durable_rate = None
        if len(samples) > 1:
            elapsed = samples[-1]["elapsed_seconds"] - samples[0]["elapsed_seconds"]
            durable_rate = (samples[-1]["metrics"].get("envoy_llmproxy_metadata_durable", 0)
                            - samples[0]["metrics"].get("envoy_llmproxy_metadata_durable", 0)) / elapsed
        return {"name": run["name"], "counted_successes": result["success"],
                "started": result["streams_started"], "error_rate": result["error_rate"],
                "achieved_rps": run["loadgen"]["open_loop"]["achieved_rate"],
                "driver_saturated": run["loadgen"]["open_loop"]["driver_saturated"],
                "ttft_p99_ms": result["ttft_from_scheduled_us"]["p99"] / 1000,
                "total_p99_ms": result["total_from_scheduled_us"]["p99"] / 1000,
                "peak_rss_MiB": {name: count / 1048576 for name, count in run["peak_rss_bytes"].items()},
                "durable": metric(run, "metadata_durable"), "durable_rps_during_load": durable_rate,
                "durable_fraction_of_started": metric(run, "metadata_durable") / result["streams_started"],
                "peak_active": metric(run, "capture_active_requests", peak=True),
                "peak_state_reserved_bytes": metric(run, "capture_state_reserved_bytes", peak=True),
                "peak_event_reserved_bytes": metric(run, "capture_event_reserved_bytes", peak=True),
                "peak_queue_depth": metric(run, "metadata_queue_depth", peak=True),
                "state_capacity_declines": metric(run, "capture_state_admission", '{outcome="capacity_exceeded"}'),
                "queue_capacity_declines": metric(run, "metadata_admission", '{outcome="capacity_exceeded"}'),
                "drops": {key: count for key, count in run["metrics_after"].items() if "capture_drops" in key},
                "tail_control_status": run.get("control_after"), "teardown": run["teardown"]}

    return {"comparisons": comparisons, "runs": [describe(run) for run in runs],
            "all_forwarding_error_rates_zero": all(r["loadgen"]["result"]["error_rate"] == 0 for r in runs),
            "all_proxy_peak_rss_below_1GiB": all(r["peak_rss_bytes"]["proxy"] <= 1073741824 for r in runs),
            "all_agent_peak_rss_below_256MiB": all(r["peak_rss_bytes"].get("agent", 0) <= 268435456 for r in runs),
            "notes": ["Median of run p99s, not a pooled percentile or confidence interval.",
                      "Shared-host macOS local qualification; not a dedicated-host capacity result.",
                      "RSS sampled every 0.5s; shorter transients may be missed.",
                      "Default metadata, one attempt; not worst-case 64-attempt or escaped-record qualification.",
                      "No oldest-backlog-age metric exists; expiration/recovery inferred from timeline and counters."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--rates", default="5,100")
    parser.add_argument("--skip-memory", action="store_true")
    parser.add_argument("--only", choices=("failure-checks", "memory-stress", "queue-full", "pause-recovery"),
                        help="Run supplemental failure checks, or just the 4800-request capture state stress")
    parser.add_argument("--summarize", type=Path, help="Regenerate the summary from an existing completed run; no load")
    args = parser.parse_args()
    if args.summarize:
        runs = [json.loads(path.read_text()) for path in sorted(args.summarize.glob("*/measurements.json"))]
        completed = [run for run in runs if "loadgen" in run]
        if not completed:
            parser.error("completed measurements required")
        summary = summarize(completed)
        summary["incomplete_runs"] = [run["name"] for run in runs if "loadgen" not in run]
        summary["all_runs_completed"] = len(completed) == len(runs)
        write_json(args.summarize / "summary.json", summary)
        return
    if args.duration < 20 or not 0 <= args.warmup < args.duration or args.repeats < 1:
        parser.error("duration >=20, 0<=warmup<duration and repeats>=1 required")
    rates = [float(rate) for rate in args.rates.split(",")]
    if any(not math.isfinite(rate) or rate <= 0 or rate > 500 for rate in rates):
        parser.error("comparison rates must be in (0,500]")
    output = (args.out or Path(tempfile.mkdtemp(prefix="capture-qualification-", dir=ROOT / "target"))).resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error("output directory must be empty; preserve previous spools")
    binary_hashes = {name: hashlib.sha256((BIN / name).read_bytes()).hexdigest()
                     for name in ("llm-proxy", "llm-capture-agent", "mock-upstream", "loadgen")}
    production_diff = subprocess.check_output(["git", "diff", "HEAD", "--", "crates", "Cargo.toml", "Cargo.lock"], cwd=ROOT)
    (output / "source.diff").write_bytes(production_diff)
    (output / "qualification-script.py").write_bytes(Path(__file__).read_bytes())
    write_json(output / "environment.json", {"commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                                            "production_dirty": bool(production_diff),
                                            "production_diff_file": "source.diff",
                                            "qualification_script_file": "qualification-script.py",
                                            "production_diff_sha256": hashlib.sha256(production_diff).hexdigest(),
                                            "qualification_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                            "platform": platform.platform(), "machine": platform.machine(),
                                            "cpu_count": os.cpu_count(), "binary_sha256": binary_hashes,
                                            "arguments": vars(args) | {"out": str(output)},
                                            "topology": "four proxy workers; h1 pooled downstream; h2 upstream except active-state stress; encrypted local spool"})
    print(f"Qualification output: {output}", flush=True)
    runs = []
    if args.only == "pause-recovery":
        for rate in rates:
            for repetition in range(args.repeats):
                runs.append(scenario(output, f"r{rate:g}-{repetition + 1}-pause", "pause", rate, args.duration, args.warmup))
                write_json(output / "summary.json", summarize(runs))
        print(json.dumps(summarize(runs), indent=2), flush=True)
        return
    if args.only == "queue-full":
        runs.append(scenario(output, "queue-full", "absent", 250, args.duration, args.warmup))
        write_json(output / "summary.json", summarize(runs))
        print(json.dumps(summarize(runs), indent=2), flush=True)
        return
    if args.only == "failure-checks":
        for name, state, rate in (("queue-full", "absent", 250), ("recovery", "pause", 5)):
            runs.append(scenario(output, name, state, rate, args.duration, args.warmup))
        write_json(output / "summary.json", summarize(runs))
        print(json.dumps(summarize(runs), indent=2), flush=True)
        return
    if args.only == "memory-stress":
        runs.append(scenario(output, "active4800-absent", "absent", 400, 12, 0, memory=True))
        write_json(output / "summary.json", summarize(runs))
        print(json.dumps(summarize(runs), indent=2), flush=True)
        return
    for rate in rates:
        for repetition in range(args.repeats):
            for state in (("off", "on") if repetition % 2 == 0 else ("on", "off")):
                runs.append(scenario(output, f"r{rate:g}-{repetition + 1}-{state}", state, rate, args.duration, args.warmup))
                write_json(output / "summary.json", {"completed_runs": [r["name"] for r in runs]})
    for state in ("absent", "pause"):
        runs.append(scenario(output, f"r100-{state}", state, 100, args.duration, args.warmup))
    if not args.skip_memory:
        for state in ("off", "absent"):
            runs.append(scenario(output, f"active4800-{state}", state, 400, 12, 0, memory=True))
            if state == "off":
                # Two h1 hops consume ~9600 ports. Clear the measured TIME_WAIT
                # envelope before the next run; it is not a data-plane ceiling.
                cooldown = runs[-1]["loadgen"]["rig"]["time_wait"]["secs"] + 5
                print(f"High-connection cooldown: {cooldown}s", flush=True)
                while cooldown > 0:
                    interval = min(15, cooldown)
                    time.sleep(interval)
                    cooldown -= interval
    write_json(output / "summary.json", summarize(runs))
    print(json.dumps(summarize(runs), indent=2), flush=True)


if __name__ == "__main__":
    main()
