#!/usr/bin/env bash
# Drive one capacity sweep end to end and leave a report behind.
#
# Topology:  loadgen  ->  llm-proxy  ->  mock-upstream
#            (this box)  (this box)      (this box)
#
# Everything runs on one machine, which is the honest constraint to state up
# front: the numbers this produces are a BASELINE for regression detection,
# not a claim about what the proxy does on dedicated hardware with a real
# provider across a network. `loadgen`'s own rig detection (testing/loadgen/
# src/rig.rs) marks a run harness-bound when it hits the box's ceiling rather
# than the proxy's, and this script surfaces that verdict instead of hiding
# it.
#
# The `--upstream-protocol` flag is the point of the exercise. HTTP/1.1
# upstreams are connect-per-request (connection reuse for HTTP/1.1 is not
# built), so the proxy->mock hop burns an ephemeral port per stream and the run
# tips into
# harness-bound early. HTTP/2 upstreams go through the per-worker connection
# cache in crates/proxy-http/src/upstream_pool.rs -- one connection, every
# stream multiplexed over it. Running both and diffing them is what turns
# "h1 pooling is missing" from an assertion into a number.
#
# The mock's default timings are LLM-shaped ON PURPOSE and must not be
# tuned to zero to "go faster". Measured 2026-08-21: with a mock that
# answers in 0.1ms, loadgen drives ~5,800 connects/sec at concurrency 1,
# against a box whose sustainable rate is ~546/sec (16,383 ephemeral ports /
# 30s TIME_WAIT, macOS net.inet.tcp.msl=15000). Ports are exhausted inside
# the first level, every later level inherits the wreckage, and the sweep
# reports a proxy capacity of 1 while the proxy logs nothing wrong at all.
#
# That is worth stating as a rule rather than a war story: when responses
# are fast, the binding harness constraint is connection CHURN RATE, not
# concurrent streams -- and rig.rs's ceiling models only the latter, so it
# does not catch this. Realistic per-stream duration is what keeps the
# connect rate under budget, and it is also the traffic shape the whole
# exercise is supposed to measure (load must include the LLM
# traffic shape, not just RPC-shaped load).
#
# AGENTS.md "Running The Product" applies to this script as much as to an agent: it
# binds ports and starts long-lived processes. Do not run it concurrently
# with the test suite, and check the teardown reported at the end.
set -euo pipefail

UPSTREAM_PROTOCOL=http2
ENDPOINT=chat
TOKENS=128
TTFT_MS=250
INTER_TOKEN_MS=25
HOLD_SECS=30
WARMUP_SECS=3
MAX_CONCURRENCY=""
PROVIDER_YAML=""
ACCESS_LOGS=off
SLO_P99_MS=""
SLO_TTFT_P99_MS=""
OUT_DIR="target/capacity"
PROFILE=release

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'USAGE'

Options:
  --upstream-protocol http1|http2   How the proxy dials the mock (default: http2)
  --endpoint chat|responses|messages  Wire shape to drive (default: chat)
  --tokens N                        Streamed content chunks per response (default: 128)
  --ttft-ms N                       Mock's time-to-first-token (default: 250)
  --inter-token-ms N                Mock's inter-token delay (default: 25)
  --hold-secs N                     Seconds held at each sweep level (default: 30)
  --warmup-secs N                   Warm-up prefix discarded per level (default: 3)
  --max-concurrency N               Cap the sweep (default: loadgen's rig estimate)
  --slo-p99-ms N                    Total-latency SLO (default: 2x the mock's own
                                    generation time -- see the note below)
  --slo-ttft-p99-ms N               TTFT SLO (default: 2x the mock's own TTFT + 500ms)
  --access-logs on|off              Enable proxy access logging (default: off)
  --provider-yaml LINES             Extra lines for the mock provider block,
                                    indented 4 spaces (e.g. a higher circuit
                                    breaker, so the sweep is not capped at the
                                    default max_requests of 1024)
  --out-dir DIR                     Where the report lands (default: target/capacity)
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --upstream-protocol) UPSTREAM_PROTOCOL="$2"; shift 2 ;;
        --endpoint)          ENDPOINT="$2"; shift 2 ;;
        --tokens)            TOKENS="$2"; shift 2 ;;
        --ttft-ms)           TTFT_MS="$2"; shift 2 ;;
        --inter-token-ms)    INTER_TOKEN_MS="$2"; shift 2 ;;
        --hold-secs)         HOLD_SECS="$2"; shift 2 ;;
        --warmup-secs)       WARMUP_SECS="$2"; shift 2 ;;
        --max-concurrency)   MAX_CONCURRENCY="$2"; shift 2 ;;
        --slo-p99-ms)        SLO_P99_MS="$2"; shift 2 ;;
        --slo-ttft-p99-ms)   SLO_TTFT_P99_MS="$2"; shift 2 ;;
        --access-logs)       ACCESS_LOGS="$2"; shift 2 ;;
        --provider-yaml)     PROVIDER_YAML="$2"; shift 2 ;;
        --out-dir)           OUT_DIR="$2"; shift 2 ;;
        -h|--help)           usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage; exit 2 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
mkdir -p "$OUT_DIR"

RUN_TAG="${ENDPOINT}-${UPSTREAM_PROTOCOL}-${TOKENS}tok"
MOCK_LOG="$OUT_DIR/mock-$RUN_TAG.log"
PROXY_LOG="$OUT_DIR/proxy-$RUN_TAG.log"
CONFIG="$OUT_DIR/config-$RUN_TAG.yaml"
REPORT="$OUT_DIR/report-$RUN_TAG.json"

MOCK_PID=""
PROXY_PID=""

# Teardown runs on every exit path, including a failed `set -e` step. The
# `pgrep` at the end is the check AGENTS.md "Running The Product" asks for by name -- a
# previous session left two processes holding ports because a run was killed
# by a watchdog before it could clean up.
cleanup() {
    local status=$?
    [[ -n "$PROXY_PID" ]] && kill "$PROXY_PID" 2>/dev/null || true
    [[ -n "$MOCK_PID"  ]] && kill "$MOCK_PID"  2>/dev/null || true
    sleep 1
    [[ -n "$PROXY_PID" ]] && kill -9 "$PROXY_PID" 2>/dev/null || true
    [[ -n "$MOCK_PID"  ]] && kill -9 "$MOCK_PID"  2>/dev/null || true
    echo
    echo "--- teardown ---"
    local leftover
    # By process name: `pgrep -f llm-proxy` also matches any command line
    # that contains the repository path, such as the shell running this.
    leftover="$( { pgrep -x mock-upstream; pgrep -x llm-proxy; } || true)"
    if [[ -n "$leftover" ]]; then
        echo "WARNING: processes still running after teardown:"
        ps -o pid,command -p $leftover || true
    else
        echo "clean: no mock-upstream or llm-proxy processes remain"
    fi
    exit $status
}
trap cleanup EXIT

echo "=== building (--$PROFILE) ==="
cargo build --"$PROFILE" -p proxy -p mockupstream -p loadgen

BIN="target/$PROFILE"

echo
echo "=== starting mock upstream ==="
"$BIN/mock-upstream" \
    --listen 127.0.0.1:0 \
    --protocol auto \
    --tokens "$TOKENS" \
    --ttft-ms "$TTFT_MS" \
    --inter-token-ms "$INTER_TOKEN_MS" \
    >"$MOCK_LOG" 2>&1 &
MOCK_PID=$!

# The mock prints its bound address as its first stdout line and flushes
# before it starts serving, so waiting for that line is a real readiness
# fence -- not a sleep, and not a connect() that would succeed against
# whatever else happened to hold the port (a false-negative generator).
MOCK_ADDR=""
for _ in $(seq 1 100); do
    MOCK_ADDR="$(sed -n 's/^mock-upstream listening on \([^ ]*\).*/\1/p' "$MOCK_LOG" | head -1)"
    [[ -n "$MOCK_ADDR" ]] && break
    sleep 0.1
done
if [[ -z "$MOCK_ADDR" ]]; then
    echo "mock upstream never announced a listen address; log follows:" >&2
    cat "$MOCK_LOG" >&2
    exit 1
fi
echo "mock upstream on $MOCK_ADDR (pid $MOCK_PID)"

PROXY_PORT=18080
ADMIN_PORT=18901

PROTOCOL_LINE=""
if [[ "$UPSTREAM_PROTOCOL" == "http2" ]]; then
    PROTOCOL_LINE="    protocol: http2"
fi

ACCESS_LOG_BLOCK=""
if [[ "$ACCESS_LOGS" == "on" ]]; then
    ACCESS_LOG_BLOCK=$'observability:\n  access_logs:\n    output: stdout\n    format: json'
fi

cat > "$CONFIG" <<YAML
# Generated by scripts/capacity-sweep.sh -- do not edit, it is overwritten
# on every run. Regenerate with the same flags to reproduce a run.
version: 0

listen: 127.0.0.1:$PROXY_PORT
admin: 127.0.0.1:$ADMIN_PORT

providers:
  mock:
    base_url: http://$MOCK_ADDR
$PROTOCOL_LINE
$PROVIDER_YAML

routes:
  - model: "*"
    provider: mock

$ACCESS_LOG_BLOCK
YAML

echo
echo "=== config ==="
cat "$CONFIG"

echo
echo "=== validating config ==="
"$BIN/llm-proxy" --config "$CONFIG" --mode validate

echo
echo "=== starting proxy ==="
"$BIN/llm-proxy" --config "$CONFIG" >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

# Readiness fence: the admin endpoint's /ready, not a sleep and not a bare
# TCP connect to the data-plane port.
READY=""
for _ in $(seq 1 200); do
    if curl -fsS --max-time 2 "http://127.0.0.1:$ADMIN_PORT/ready" >/dev/null 2>&1; then
        READY=yes
        break
    fi
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
        echo "proxy exited during startup; log follows:" >&2
        cat "$PROXY_LOG" >&2
        exit 1
    fi
    sleep 0.1
done
if [[ -z "$READY" ]]; then
    echo "proxy never became ready; log follows:" >&2
    cat "$PROXY_LOG" >&2
    exit 1
fi
echo "proxy ready on 127.0.0.1:$PROXY_PORT (pid $PROXY_PID), admin on :$ADMIN_PORT"

echo
echo "=== one smoke request before the sweep ==="
# A sweep against a broken topology reports a very confident zero. Prove one
# request round-trips, and prove the proxy metered it, before spending
# minutes on the ramp.
curl -fsS --max-time 10 \
    -H 'content-type: application/json' \
    -d "{\"model\":\"mock-model\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}" \
    "http://127.0.0.1:$PROXY_PORT/v1/chat/completions" | head -c 400
echo
echo
echo "upstream_rq before sweep:"
curl -fsS --max-time 5 "http://127.0.0.1:$ADMIN_PORT/stats" 2>/dev/null \
    | grep -E 'upstream_rq(_total)?' | head -5 || echo "  (none reported)"

echo
echo "=== sweep ==="
# Tie the rig's port-budget assumption to the topology that actually
# produced it, rather than leaving the operator to remember. An h2 upstream
# reaches the connection cache, so the proxy->mock hop costs ~0 new ports per
# stream and only the loadgen->proxy hop counts; h1 is connect-per-request on
# both hops. Getting this wrong in the safe-looking direction is what makes a
# good run report itself harness-bound.
SOCKETS_PER_STREAM=2
[[ "$UPSTREAM_PROTOCOL" == "http2" ]] && SOCKETS_PER_STREAM=1

# The SLO must be expressed relative to how long the mock takes to generate a
# response, or the sweep fails at concurrency 1 forever and reports "no
# sustainable level" -- which is what happened on the first LLM-shaped run
# here (a 3,450ms stream against loadgen's stock 2,000ms total-latency
# default). Total latency for a streamed completion INCLUDES generation; it
# is not a service time the proxy controls.
#
# So saturation is defined as a RATIO, not an absolute: the proxy is
# saturated when it has doubled the response time the upstream would have
# delivered on its own. That is a claim about proxy overhead, which is the
# thing under test, rather than a claim about how fast an LLM ought to be.
INTRINSIC_MS=$(( TTFT_MS + TOKENS * INTER_TOKEN_MS ))
[[ -z "$SLO_P99_MS" ]] && SLO_P99_MS=$(( INTRINSIC_MS * 2 ))
[[ -z "$SLO_TTFT_P99_MS" ]] && SLO_TTFT_P99_MS=$(( TTFT_MS * 2 + 500 ))
echo "intrinsic stream time: ${INTRINSIC_MS}ms  ->  SLO p99=${SLO_P99_MS}ms ttft_p99=${SLO_TTFT_P99_MS}ms"

# A level must observe enough completed streams for a p99 to mean anything.
if (( HOLD_SECS * 1000 < INTRINSIC_MS * 10 )); then
    echo "WARNING: --hold-secs ${HOLD_SECS} is under 10 stream-times (${INTRINSIC_MS}ms each);" \
         "low levels will report percentiles computed from a handful of samples." >&2
fi

SWEEP_ARGS=(
    --sweep
    --sweep-pid "$PROXY_PID"
    --target "http://127.0.0.1:$PROXY_PORT"
    --endpoint "$ENDPOINT"
    --model mock-model
    --rig-sockets-per-stream "$SOCKETS_PER_STREAM"
    --slo-p99-ms "$SLO_P99_MS"
    --slo-ttft-p99-ms "$SLO_TTFT_P99_MS"
    --sweep-hold-secs "$HOLD_SECS"
    --sweep-warmup-secs "$WARMUP_SECS"
    --out "$REPORT"
)
[[ -n "$MAX_CONCURRENCY" ]] && SWEEP_ARGS+=(--sweep-max-concurrency "$MAX_CONCURRENCY")

set +e
"$BIN/loadgen" "${SWEEP_ARGS[@]}"
SWEEP_STATUS=$?
set -e

echo
echo "=== proxy-side counters after the sweep ==="
curl -fsS --max-time 5 "http://127.0.0.1:$ADMIN_PORT/stats" 2>/dev/null \
    | grep -E 'upstream_rq|downstream' | head -20 || echo "  (none reported)"

echo
echo "report:      $REPORT"
echo "proxy log:   $PROXY_LOG"
echo "mock log:    $MOCK_LOG"
echo "loadgen exit: $SWEEP_STATUS  (non-zero means harness-bound or no sustainable level found)"
