#!/usr/bin/env bash
# Latency lab, Layer 1: run two proxy builds alternately on one Linux host.
#
# Usage: ab-remote.sh BASE_BIN_DIR CAND_BIN_DIR OUT_DIR
#
# Each *_BIN_DIR holds an llm-proxy binary. loadgen and mock-upstream come
# from BASE_BIN_DIR for both arms, so the harness is identical and only the
# proxy differs. scripts/latency-lab.sh builds the dirs and ships this
# script; it also runs on any Linux box by hand.
#
# Design (internal-docs/latency-lab.md, Layer 1): rounds alternate ABBA ABBA,
# so a slow drift on the host (a noisy neighbour, thermal state) lands on
# both arms equally. Each arm run starts a fresh mock and proxy, so no run
# inherits another's pools or heap. scripts/lab/ab_compare.py reads OUT_DIR.
set -euo pipefail

BASE="$1" CAND="$2" OUT="$3"
ROUNDS="${ROUNDS:-4}"
SCENARIOS="${SCENARIOS:-nonstream-1k stream-256}"
DURATION="${DURATION:-30}"
WARMUP="${WARMUP:-5}"
UPSTREAM="${UPSTREAM:-http2}"
CORES_PROXY="${CORES_PROXY:-0-3}"
CORES_UPSTREAM="${CORES_UPSTREAM:-4}"
CORES_LOADGEN="${CORES_LOADGEN:-6-7}"
PROXY_WORKERS="${PROXY_WORKERS:-4}"
# ACCESS_LOG=json|text turns on the dialect's default access log, written to
# access.log in each logging arm's directory (scripts/lab/phases.py reads
# it). ACCESS_LOG_ARMS picks the arms that log: the default, cand only,
# prices the log itself; "base cand" logs both, for a phase breakdown.
ACCESS_LOG="${ACCESS_LOG:-}"
ACCESS_LOG_ARMS="${ACCESS_LOG_ARMS:-cand}"
case "$ACCESS_LOG" in ""|json|text) ;; *) echo "ACCESS_LOG must be json or text" >&2; exit 2 ;; esac
mkdir -p "$OUT"
ulimit -n 65535 || true

PIDS=()
stop_all() {
    for pid in "${PIDS[@]:-}"; do [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true; done
    sleep 0.5
    for pid in "${PIDS[@]:-}"; do [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null || true; done
    PIDS=()
}
cleanup() {
    local status=$?
    stop_all
    local left
    # Match the binaries, not this script, whose arguments name the same dirs.
    left="$(pgrep -f "($BASE|$CAND)/(llm-proxy|loadgen|mock-upstream)" || true)"
    [[ -n "$left" ]] && { echo "WARNING: lab processes still running:"; ps -o pid,command -p $left; }
    exit $status
}
trap cleanup EXIT

free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'
}

# scenario_args NAME: sets MOCK_ARGS and LOAD_ARGS.
scenario_args() {
    case "$1" in
        # Proxy-added latency with no queueing: small non-streaming replies.
        nonstream-1k)
            MOCK_ARGS=(--tokens 16 --ttft-ms 5 --inter-token-ms 0)
            LOAD_ARGS=(--no-stream --rate 1000 --downstream-h1-pool-size 256) ;;
        # TTFT, inter-token delay and RSS while holding 256 streams.
        stream-256)
            MOCK_ARGS=(--tokens 128 --ttft-ms 250 --inter-token-ms 25)
            LOAD_ARGS=(--concurrency 256 --downstream-h1-pool-size 512) ;;
        *) echo "unknown scenario: $1 (nonstream-1k stream-256)" >&2; exit 2 ;;
    esac
}

# start_mock DIR: sets MOCK_ADDR.
start_mock() {
    taskset -c "$CORES_UPSTREAM" "$BASE/mock-upstream" --listen 127.0.0.1:0 --protocol auto \
        "${MOCK_ARGS[@]}" >"$1/mock.log" 2>&1 &
    PIDS+=($!)
    MOCK_ADDR=""
    for _ in $(seq 1 100); do
        MOCK_ADDR="$(sed -n 's/^mock-upstream listening on \([^ ]*\).*/\1/p' "$1/mock.log" | head -1)"
        [[ -n "$MOCK_ADDR" ]] && return 0
        sleep 0.1
    done
    echo "mock never announced an address" >&2; cat "$1/mock.log" >&2; exit 1
}

# start_proxy BIN_DIR DIR ARM: sets LISTEN, PROXY_PID.
start_proxy() {
    local bin="$1" dir="$2" arm="$3" admin proto="" log=""
    LISTEN="$(free_port)"; admin="$(free_port)"
    [[ "$UPSTREAM" == http2 ]] && proto="    protocol: http2"
    if [[ -n "$ACCESS_LOG" && " $ACCESS_LOG_ARMS " == *" $arm "* ]]; then
        log="observability:
  access_logs:
    output: $dir/access.log
    format: $ACCESS_LOG"
    fi
    cat >"$dir/config.yaml" <<YAML
version: 0
listen: 127.0.0.1:$LISTEN
admin: 127.0.0.1:$admin
providers:
  mock:
    base_url: http://$MOCK_ADDR
$proto
routes:
  - model: "*"
    provider: mock
$log
YAML
    taskset -c "$CORES_PROXY" "$bin/llm-proxy" --config "$dir/config.yaml" \
        --concurrency "$PROXY_WORKERS" >"$dir/proxy.log" 2>&1 &
    PROXY_PID=$!
    PIDS+=("$PROXY_PID")
    for _ in $(seq 1 200); do
        curl -fsS --max-time 2 "http://127.0.0.1:$admin/ready" >/dev/null 2>&1 && return 0
        kill -0 "$PROXY_PID" 2>/dev/null || break
        sleep 0.1
    done
    echo "proxy never became ready" >&2; cat "$dir/proxy.log" >&2; exit 1
}

# CPU ticks (utime + stime) of a process; fields 14 and 15 of /proc/PID/stat,
# counted after the ")" so a command name with spaces cannot shift them.
cpu_ticks() { sed 's/.*) //' "/proc/$1/stat" | awk '{print $12 + $13}'; }
status_kb() { awk -v k="$2:" '$1 == k {print $2}' "/proc/$1/status"; }

loadgen() {
    taskset -c "$CORES_LOADGEN" "$BASE/loadgen" --endpoint chat --model mock-model \
        --downstream-mode h1-pool --duration "$DURATION" --warmup "$WARMUP" "$@"
}

run_arm() { # run_arm SCENARIO ARM BIN_DIR ROUND
    local d="$OUT/$1/$2-r$4"
    mkdir -p "$d"
    start_mock "$d"
    start_proxy "$3" "$d" "$2"
    local t0 t1 rss_idle
    rss_idle="$(status_kb "$PROXY_PID" VmRSS)"
    t0="$(cpu_ticks "$PROXY_PID")"
    loadgen --target "http://127.0.0.1:$LISTEN" "${LOAD_ARGS[@]}" \
        --out "$d/loadgen.json" >"$d/loadgen.txt" 2>&1
    t1="$(cpu_ticks "$PROXY_PID")"
    cat >"$d/proc.json" <<JSON
{"cpu_ticks": $((t1 - t0)), "clk_tck": $(getconf CLK_TCK), "rss_idle_kb": $rss_idle,
 "rss_end_kb": $(status_kb "$PROXY_PID" VmRSS), "rss_peak_kb": $(status_kb "$PROXY_PID" VmHWM)}
JSON
    stop_all
    echo "  $1 $2 round $4 done"
}

{
    echo "base: $(cat "$BASE/REVISION" 2>/dev/null || echo "$BASE")"
    echo "cand: $(cat "$CAND/REVISION" 2>/dev/null || echo "$CAND")"
    echo "rounds: $ROUNDS  duration: ${DURATION}s  warmup: ${WARMUP}s  upstream: $UPSTREAM"
    echo "cores: proxy $CORES_PROXY (workers $PROXY_WORKERS), mock $CORES_UPSTREAM, loadgen $CORES_LOADGEN"
    echo "access log: ${ACCESS_LOG:-off}${ACCESS_LOG:+ (arms: $ACCESS_LOG_ARMS)}"
    echo "kernel: $(uname -r)  nproc: $(nproc)"
    echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
} | tee "$OUT/manifest.txt"

for s in $SCENARIOS; do
    scenario_args "$s"
    echo "=== $s ==="
    # One direct run per scenario: what the mock costs with no proxy, so the
    # report can say how much of the total is the proxy at all.
    mkdir -p "$OUT/$s/direct"
    start_mock "$OUT/$s/direct"
    loadgen --target "http://$MOCK_ADDR" "${LOAD_ARGS[@]}" \
        --out "$OUT/$s/direct/loadgen.json" >"$OUT/$s/direct/loadgen.txt" 2>&1
    stop_all
    for ((r = 1; r <= ROUNDS; r++)); do
        if ((r % 2)); then
            run_arm "$s" base "$BASE" "$r"; run_arm "$s" cand "$CAND" "$r"
        else
            run_arm "$s" cand "$CAND" "$r"; run_arm "$s" base "$BASE" "$r"
        fi
    done
done
touch "$OUT/DONE"
echo "results: $OUT"
