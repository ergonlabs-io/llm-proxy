#!/usr/bin/env python3
"""Added-latency benchmark: what the proxy adds to a request, controls on.

Build with make bench-build; run with make bench-added-latency.
Method and published results: internal-docs/capacity/added-latency.md.

Each round runs every arm once, in an order that rotates and reverses from
round to round, so a slow drift in host load lands on every arm. Each arm
run starts a fresh mock upstream (and proxy), so no run inherits another's
pools or heap. The summary compares the minimum across rounds, not the mean:
on a shared box the minimum is the run the neighbours disturbed least.

Arms (cumulative, so each step prices one control group):
  direct             loadgen straight to the mock upstream: the baseline
  controls-off       proxy, one route, no auth, limits, spend or ledger
  auth               + virtual-key auth, model policy and object ownership
  auth-limits        + tenant token, request and concurrency limits
  auth-limits-spend  + rate card and tenant and key spend budgets
  controls-on        + the billing ledger: everything a production chain runs

Only loopback ports the kernel hands out are used. Every child is stopped on
exit, and the run fails if any of its binaries is still running afterwards.
"""
import argparse
import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import secrets
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve() / "release"
BINARIES = {"proxy": BIN / "llm-proxy", "mock": BIN / "mock-upstream", "loadgen": BIN / "loadgen"}

ARMS = ["direct", "controls-off", "auth", "auth-limits", "auth-limits-spend", "controls-on"]
MODEL = "mock-model"
TENANT = "bench"
KEY_ID = "bench-key"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def loadavg():
    return [round(x, 2) for x in os.getloadavg()]


def admin_call(port, method, path, token, body=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=5) as reply:
        return json.loads(reply.read().decode() or "null")


class Processes:
    """Children of one arm run. close() stops them all, forcibly if needed."""

    def __init__(self):
        self.children = []

    def start(self, command, log_path, env=None):
        with log_path.open("w") as log:
            child = subprocess.Popen([str(x) for x in command], stdout=log, stderr=subprocess.STDOUT,
                                     env={**os.environ, **(env or {})})
        self.children.append(child)
        return child

    def close(self):
        for child in reversed(self.children):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
        self.children = []


def wait_until(child, predicate, label, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError(f"{label} exited early with {child.returncode}")
        try:
            value = predicate()
            if value:
                return value
        except OSError:
            pass
        time.sleep(0.1)
    raise TimeoutError(f"{label} not ready after {timeout}s")


def start_mock(procs, directory, args):
    log = directory / "mock.log"
    child = procs.start([BINARIES["mock"], "--listen", "127.0.0.1:0", "--protocol", "auto",
                         "--tokens", args.tokens, "--ttft-ms", args.ttft_ms], log)

    def announced():
        for line in log.read_text().splitlines():
            if line.startswith("mock-upstream listening on "):
                return line.split()[3]
        return None
    return wait_until(child, announced, "mock upstream")


def proxy_config(arm, listen, admin, mock_addr, run_dir):
    """The dialect config for one proxy arm. Published verbatim by the page."""
    lines = [
        "version: 0",
        f"listen: 127.0.0.1:{listen}",
        f"admin: 127.0.0.1:{admin}",
        "providers:",
        "  mock:",
        f"    base_url: http://{mock_addr}",
        "routes:",
        '  - model: "*"',
        "    provider: mock",
    ]
    if arm == "controls-off":
        return "\n".join(lines) + "\n"
    level = ARMS.index(arm)
    limits_on = level >= ARMS.index("auth-limits")
    spend_on = level >= ARMS.index("auth-limits-spend")
    lines += [
        "auth:",
        f"  hmac_secret_file: {run_dir / 'hmac.secret'}",
        "  keys:",
        f"    - id: {KEY_ID}",
        f"      tenant: {TENANT}",
        f"      digest: {(run_dir / 'key.digest').read_text().strip()}",
        "  enforce:",
        "    tenants_without_policy: allow",
        f"    limits: {str(limits_on).lower()}",
        f"    spend: {str(spend_on).lower()}",
    ]
    if limits_on:
        # High enough never to refuse at the benchmark rate, so every request
        # pays the admission check and the usage reconcile, and none is a 429.
        lines += [
            "limits:",
            "  - key: tenant",
            "    tokens_per_minute: 100m",
            "    requests_per_minute: 10m",
            "    concurrent_sessions: 4096",
        ]
    if spend_on:
        lines += [
            "pricing:",
            "  price_list:",
            "    version: bench-1",
            '    effective_from: "2026-01-01T00:00:00Z"',
            "    entries:",
            "      - provider_type: openai-compatible",
            f"        model: {MODEL}",
            "        tier_mode: whole_request",
            "        tiers:",
            "          - input_nanodollars_per_token: 1250",
            "            cached_input_nanodollars_per_token: 125",
            "            cache_write_nanodollars_per_token: 1560",
            "            output_nanodollars_per_token: 10000",
        ]
    if arm == "controls-on":
        lines += [
            "ledger:",
            f"  directory: {run_dir / 'ledger'}",
            f"  encryption_key_file: {run_dir / 'ledger.key'}",
            "  encryption_key_id: bench",
            "  max_disk_bytes: 10737418240",
            "  on_unavailable: reject",
        ]
    return "\n".join(lines) + "\n"


def start_proxy(procs, arm, directory, mock_addr, run_dir, args, admin_token):
    listen, admin = free_port(), free_port()
    config = directory / "config.yaml"
    config.write_text(proxy_config(arm, listen, admin, mock_addr, run_dir))
    command = [BINARIES["proxy"], "--config", config, "--service-node", f"bench-{arm}"]
    if args.proxy_workers:
        command += ["--concurrency", args.proxy_workers]
    child = procs.start(command, directory / "proxy.log",
                        env={"LLMPROXY_ADMIN_TOKEN": admin_token, "RUST_LOG": "warn"})

    def ready():
        with urllib.request.urlopen(f"http://127.0.0.1:{admin}/ready", timeout=2) as reply:
            return reply.status == 200
    wait_until(child, ready, f"proxy ({arm})")
    if ARMS.index(arm) >= ARMS.index("auth-limits-spend"):
        # Budgets far above what a run spends: every request is priced and
        # checked against both ceilings, and none is refused.
        budget = {"schema_version": 2, "budget": {"max_usd": "1000000.00", "period": "monthly"}}
        admin_call(admin, "PUT", f"/tenants/{TENANT}/budget", admin_token, budget)
        admin_call(admin, "PUT", f"/keys/{KEY_ID}/budget", admin_token, budget)
    return listen, admin


def run_loadgen(procs, directory, target, args, api_key):
    command = [BINARIES["loadgen"], "--target", target, "--endpoint", "chat", "--model", MODEL,
               "--no-stream", "--max-tokens", args.tokens, "--rate", args.rate,
               "--duration", args.duration, "--warmup", args.warmup,
               "--downstream-mode", "h1-pool", "--downstream-h1-pool-size", args.pool_size,
               "--out", directory / "loadgen.json"]
    if api_key:
        command += ["--api-key", api_key]
    child = procs.start(command, directory / "loadgen.txt")
    child.wait(timeout=args.duration + args.warmup + 120)
    report = json.loads((directory / "loadgen.json").read_text())
    if child.returncode != 0:
        raise RuntimeError(f"loadgen exited {child.returncode}; see {directory / 'loadgen.txt'}")
    return report


def controls_evidence(arm, listen, admin, admin_token):
    """Proof the arm's controls ran: auth refuses, spend is charged, entries are written.

    A config that parses but leaves a filter out would otherwise publish a
    controls-on number that measured nothing.
    """
    evidence = {"unauthenticated_status": unauthenticated_status(listen)}
    if ARMS.index(arm) >= ARMS.index("auth-limits-spend"):
        spend = admin_call(admin, "GET", f"/keys/{KEY_ID}/spend", admin_token)
        evidence["key_spend"] = spend
    if arm == "controls-on":
        entries = admin_call(admin, "GET", "/ledger/entries?after=0&limit=10", admin_token)
        evidence["ledger_entries_sample"] = len(entries.get("entries", []))
    return evidence


def check_evidence(arm, evidence):
    if arm not in ("direct", "controls-off") and evidence.get("unauthenticated_status") != 401:
        raise RuntimeError(f"{arm}: a request with no key got {evidence.get('unauthenticated_status')}, not 401")
    if "key_spend" in evidence and not evidence["key_spend"].get("spend_micro_usd", 0) > 0:
        raise RuntimeError(f"{arm}: no spend recorded, so the spend filter did not run: {evidence['key_spend']}")
    if arm == "controls-on" and not evidence.get("ledger_entries_sample"):
        raise RuntimeError(f"{arm}: the ledger holds no entries, so it did not run")


def unauthenticated_status(listen):
    body = json.dumps({"model": MODEL, "messages": [{"role": "user", "content": "hi"}]}).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{listen}/v1/chat/completions", data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=5) as reply:
            return reply.status
    except urllib.error.HTTPError as error:
        return error.code


def run_arm(arm, round_no, out_dir, run_dir, args, api_key):
    directory = out_dir / "runs" / f"r{round_no}-{arm}"
    directory.mkdir(parents=True)
    procs = Processes()
    try:
        mock_addr = start_mock(procs, directory, args)
        admin_token = secrets.token_hex(32)
        if arm == "direct":
            target, key, listen, admin = f"http://{mock_addr}", None, None, None
        else:
            listen, admin = start_proxy(procs, arm, directory, mock_addr, run_dir, args, admin_token)
            target, key = f"http://127.0.0.1:{listen}", (api_key if arm != "controls-off" else None)
        load_before = loadavg()
        report = run_loadgen(procs, directory, target, args, key)
        load_after = loadavg()
        evidence = controls_evidence(arm, listen, admin, admin_token) if admin else {}
        check_evidence(arm, evidence)
        if report["result"]["success"] == 0 or report["result"]["error_rate"] > 0.001:
            raise RuntimeError(f"{arm}: errors {report['result']['http_errors']}, "
                               f"transport {report['result']['transport_errors']}; see {directory}")
    finally:
        procs.close()
    row = summarize_run(arm, round_no, report, load_before, load_after)
    row["evidence"] = evidence
    (directory / "row.json").write_text(json.dumps(row, indent=2) + "\n")
    return row


def summarize_run(arm, round_no, report, load_before, load_after):
    result = report["result"]
    total = result.get("total_from_scheduled_us") or {}
    sent = result.get("total_from_send_us") or {}
    return {
        "arm": arm,
        "round": round_no,
        "counted": result["streams_counted"],
        "success": result["success"],
        "error_rate": result["error_rate"],
        "http_errors": result["http_errors"],
        "p50_us": total.get("p50"),
        "p99_us": total.get("p99"),
        "p50_from_send_us": sent.get("p50"),
        "p99_from_send_us": sent.get("p99"),
        "load_before": load_before,
        "load_after": load_after,
    }


def round_order(round_no):
    """ABC.. then ..CBA, each rotated by the round, so no arm always goes first."""
    shift = (round_no - 1) // 2 % len(ARMS)
    order = ARMS[shift:] + ARMS[:shift]
    return order if round_no % 2 else list(reversed(order))


# Two clocks for the same requests. From send: the time from writing the
# request to the last response byte, which is what the proxy can add. From
# scheduled: the same plus however late the open-loop driver started the
# request, which is coordinated-omission honest but also carries the driver's
# own timer lateness, shared by every arm including direct.
BASES = {"from_send": ("p50_from_send_us", "p99_from_send_us"), "from_scheduled": ("p50_us", "p99_us")}


def summarize(rows):
    """Per arm and clock: minimum and median p50/p99, and minimum added over direct."""
    table = []
    by_arm = {arm: [r for r in rows if r["arm"] == arm and r["p50_us"] is not None] for arm in ARMS}
    direct = by_arm["direct"]
    for arm in ARMS:
        runs = by_arm[arm]
        if not runs:
            continue
        loads = [r["load_before"][0] for r in runs] + [r["load_after"][0] for r in runs]
        entry = {"arm": arm, "rounds": len(runs), "load1_min": min(loads), "load1_max": max(loads),
                 "errors": sum(r["counted"] - r["success"] for r in runs)}
        for base, (k50, k99) in BASES.items():
            p50s = sorted(r[k50] for r in runs)
            p99s = sorted(r[k99] for r in runs)
            base50 = min((r[k50] for r in direct), default=None)
            base99 = min((r[k99] for r in direct), default=None)
            entry[base] = {
                "p50_min_us": p50s[0],
                "p50_median_us": p50s[len(p50s) // 2],
                "p99_min_us": p99s[0],
                "p99_median_us": p99s[len(p99s) // 2],
                "added_p50_us": None if base50 is None else p50s[0] - base50,
                "added_p99_us": None if base99 is None else p99s[0] - base99,
            }
        table.append(entry)
    return table


def ms(us):
    return "n/a" if us is None else f"{us / 1000:.3f}"


def render_table(table):
    out = []
    for base in BASES:
        out += [f"Latency {base.replace('_', ' ')}:", "",
                "| arm | p50 ms (min) | p99 ms (min) | added p50 ms | added p99 ms "
                "| p50 ms (median) | p99 ms (median) | load1 during runs | errors |",
                "|---|---|---|---|---|---|---|---|---|"]
        for row in table:
            v = row[base]
            added50 = "baseline" if row["arm"] == "direct" else ms(v["added_p50_us"])
            added99 = "baseline" if row["arm"] == "direct" else ms(v["added_p99_us"])
            out.append(f"| {row['arm']} | {ms(v['p50_min_us'])} | {ms(v['p99_min_us'])} | {added50} | {added99} "
                       f"| {ms(v['p50_median_us'])} | {ms(v['p99_median_us'])} "
                       f"| {row['load1_min']:.1f}-{row['load1_max']:.1f} | {row['errors']} |")
        out.append("")
    return "\n".join(out)


def machine():
    info = {"system": platform.platform(), "python": platform.python_version(), "cpus": os.cpu_count()}
    if sys.platform == "darwin":
        for key in ("hw.model", "machdep.cpu.brand_string", "hw.memsize"):
            info[key] = subprocess.run(["sysctl", "-n", key], capture_output=True, text=True).stdout.strip()
    return info


def leftovers():
    """PIDs of any of this build's benchmark binaries still running."""
    found = []
    for path in BINARIES.values():
        out = subprocess.run(["pgrep", "-f", f"^{path}"], capture_output=True, text=True).stdout
        found += [int(pid) for pid in out.split()]
    return found


def prepare_secrets(run_dir):
    secret = secrets.token_hex(32)
    key = f"llmp_bench_{secrets.token_hex(16)}"
    (run_dir / "hmac.secret").write_text(secret)
    digest = hmac.new(secret.encode(), key.encode(), hashlib.sha256).hexdigest()
    (run_dir / "key.digest").write_text(digest)
    ledger_key = run_dir / "ledger.key"
    ledger_key.write_bytes(secrets.token_bytes(32))
    os.chmod(ledger_key, 0o600)
    os.chmod(run_dir / "hmac.secret", 0o600)
    return key


def git_revision():
    out = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short=12", "HEAD"], capture_output=True, text=True)
    dirty = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=no"],
                           capture_output=True, text=True).stdout.strip()
    return out.stdout.strip() + ("-dirty" if dirty else "")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--duration", type=int, default=20, help="seconds of load per arm run, warm-up included")
    parser.add_argument("--warmup", type=int, default=3, help="seconds discarded at the start of each run")
    parser.add_argument("--rate", type=int, default=200, help="open-loop requests per second")
    parser.add_argument("--tokens", type=int, default=16, help="completion tokens per response")
    parser.add_argument("--ttft-ms", type=int, default=0, help="mock delay before its response")
    parser.add_argument("--pool-size", type=int, default=64, help="loadgen keep-alive connections")
    parser.add_argument("--proxy-workers", type=int, default=4, help="proxy --concurrency (0: its default)")
    parser.add_argument("--arms", default=",".join(ARMS), help="comma-separated subset of: " + ", ".join(ARMS))
    parser.add_argument("--out-dir", type=Path)
    args = parser.parse_args()

    missing = [str(p) for p in BINARIES.values() if not p.exists()]
    if missing:
        sys.exit(f"missing {', '.join(missing)}; run make bench-build")
    selected = [a.strip() for a in args.arms.split(",") if a.strip()]
    unknown = sorted(set(selected) - set(ARMS))
    if unknown:
        sys.exit(f"unknown arm(s): {', '.join(unknown)}")
    if "direct" not in selected:
        sys.exit("the direct arm is the baseline and cannot be left out")
    if leftovers():
        sys.exit(f"benchmark binaries already running (pids {leftovers()}); stop them first")

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = (args.out_dir or ROOT / "target" / "added-latency" / stamp).resolve()
    run_dir = out_dir / "secrets"
    run_dir.mkdir(parents=True)
    (run_dir / "ledger").mkdir(mode=0o700)
    api_key = prepare_secrets(run_dir)

    # Stop children on Ctrl-C or a kill of this script, not only on success.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    manifest = {
        "revision": git_revision(),
        "started": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "machine": machine(),
        "load_at_start": loadavg(),
        "params": {k: (str(v) if isinstance(v, Path) else v) for k, v in vars(args).items()},
        "request": {"endpoint": "/v1/chat/completions", "stream": False, "model": MODEL,
                    "max_tokens": args.tokens, "mock_completion_tokens": args.tokens,
                    "mock_ttft_ms": args.ttft_ms, "prompt": "loadgen default (one short sentence)"},
    }
    print(f"added-latency: rev {manifest['revision']}, load {manifest['load_at_start']}, out {out_dir}")
    rows = []
    try:
        for round_no in range(1, args.rounds + 1):
            for arm in [a for a in round_order(round_no) if a in selected]:
                row = run_arm(arm, round_no, out_dir, run_dir, args, api_key)
                rows.append(row)
                print(f"  r{round_no} {arm:<18} p50 {ms(row['p50_us'])} ms  p99 {ms(row['p99_us'])} ms  "
                      f"errors {row['counted'] - row['success']}  load {row['load_before'][0]}->{row['load_after'][0]}",
                      flush=True)
    finally:
        manifest["load_at_end"] = loadavg()
        table = summarize(rows)
        (out_dir / "results.json").write_text(json.dumps({"manifest": manifest, "runs": rows, "summary": table},
                                                         indent=2) + "\n")
        (out_dir / "summary.md").write_text(render_table(table))
        stray = leftovers()
        if stray:
            print(f"WARNING: benchmark binaries still running: {stray}", file=sys.stderr)
    print()
    print(render_table(table))
    print(f"raw results: {out_dir / 'results.json'}")
    if stray:
        sys.exit(1)


if __name__ == "__main__":
    main()
