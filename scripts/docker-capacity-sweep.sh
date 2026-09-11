#!/usr/bin/env bash
# WP-30 Docker capacity baseline. Topology:
#
#   loadgen (separate cgroup) -> proxy (2 CPUs / 1 GiB) -> mock upstream
#
# Docker Desktop makes this a reproducible local baseline, not a claim about
# dedicated Linux hardware. Run the same command on the target VM before using
# a result for sizing or a regression gate.
set -euo pipefail

PROXY_CPUS="${PROXY_CPUS:-2.0}"
PROXY_MEMORY="${PROXY_MEMORY:-1g}"
TOKENS=128
TTFT_MS=250
INTER_TOKEN_MS=25
HOLD_SECS=30
WARMUP_SECS=3
MAX_CONCURRENCY=""
OUT_DIR="target/docker-capacity"
PROJECT="llmproxy-capacity-$$"
COMPOSE_FILE="testing/perf/compose.yaml"
SAMPLE_INTERVAL_SECS=0.5

usage() {
    cat <<'USAGE'
Usage: scripts/docker-capacity-sweep.sh [options]

Defaults constrain only proxy container to 2 CPUs and 1 GiB with no swap.
The load generator and mock have separate cgroups so they do not consume this
budget. Results are written under target/docker-capacity.

Options:
  --tokens N                 Streamed tokens per response (default: 128)
  --ttft-ms N                Mock time to first token (default: 250)
  --inter-token-ms N         Mock inter-token delay (default: 25)
  --hold-secs N              Seconds per capacity level (default: 30)
  --warmup-secs N            Discarded warm-up seconds per level (default: 3)
  --max-concurrency N        Sweep safety cap (default: loadgen rig estimate)
  --out-dir DIR              Output directory (default: target/docker-capacity)
  --proxy-cpus N             Proxy CPU quota (default: 2.0)
  --proxy-memory SIZE        Proxy memory limit and swap limit (default: 1g)
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tokens) TOKENS="$2"; shift 2 ;;
        --ttft-ms) TTFT_MS="$2"; shift 2 ;;
        --inter-token-ms) INTER_TOKEN_MS="$2"; shift 2 ;;
        --hold-secs) HOLD_SECS="$2"; shift 2 ;;
        --warmup-secs) WARMUP_SECS="$2"; shift 2 ;;
        --max-concurrency) MAX_CONCURRENCY="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --proxy-cpus) PROXY_CPUS="$2"; shift 2 ;;
        --proxy-memory) PROXY_MEMORY="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

COMPOSE=(docker compose -p "$PROJECT" -f "$COMPOSE_FILE")
PROXY_ID=""
SAMPLER_PID=""
RUN_TAG="chat-http2-${TOKENS}tok-${PROXY_CPUS}cpu-${PROXY_MEMORY}"
REPORT="$OUT_DIR/report-$RUN_TAG.json"
RESOURCE_SAMPLES="$OUT_DIR/resources-$RUN_TAG.tsv"
METADATA="$OUT_DIR/metadata-$RUN_TAG.txt"

cleanup() {
    local status=$?
    [[ -n "$SAMPLER_PID" ]] && kill "$SAMPLER_PID" 2>/dev/null || true
    [[ -n "$SAMPLER_PID" ]] && wait "$SAMPLER_PID" 2>/dev/null || true
    if [[ -n "$PROXY_ID" ]]; then
        docker inspect --format 'oom_killed={{.State.OOMKilled}} exit_code={{.State.ExitCode}}' "$PROXY_ID" \
            >>"$METADATA" 2>/dev/null || true
    fi
    "${COMPOSE[@]}" down --remove-orphans >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup EXIT

sample_resources() {
    printf 'unix_s\tcpu\tmemory\tmemory_percent\tpids\tcgroup_v2\n' >"$RESOURCE_SAMPLES"
    while true; do
        local now stats cgroup
        now="$(date +%s)"
        stats="$(docker stats --no-stream --format '{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.PIDs}}' "$PROXY_ID" 2>/dev/null || true)"
        cgroup="$(docker exec "$PROXY_ID" sh -c '
            root=/sys/fs/cgroup
            for key in memory.current memory.max; do
                printf "%s=" "$key"
                tr -d "\\n" <"$root/$key" 2>/dev/null || printf "unavailable"
                printf ";"
            done
            for key in usage_usec user_usec system_usec nr_periods nr_throttled throttled_usec; do
                value=$(grep "^$key " "$root/cpu.stat" 2>/dev/null | cut -d " " -f 2)
                printf "cpu.%s=%s;" "$key" "${value:-unavailable}"
            done
            for key in oom oom_kill high max; do
                value=$(grep "^$key " "$root/memory.events" 2>/dev/null | cut -d " " -f 2)
                printf "memory.%s=%s;" "$key" "${value:-unavailable}"
            done
        ' 2>/dev/null || true)"
        printf '%s\t%s\t%s\n' "$now" "${stats:-unavailable}" "${cgroup:-unavailable}" >>"$RESOURCE_SAMPLES"
        sleep "$SAMPLE_INTERVAL_SECS"
    done
}

INTRINSIC_MS=$((TTFT_MS + TOKENS * INTER_TOKEN_MS))
SLO_P99_MS=$((INTRINSIC_MS * 2))
SLO_TTFT_P99_MS=$((TTFT_MS * 2 + 500))

printf 'project=%s\nproxy_cpus=%s\nproxy_memory=%s\ntokens=%s\nttft_ms=%s\ninter_token_ms=%s\nhold_secs=%s\nwarmup_secs=%s\nintrinsic_stream_ms=%s\nslo_p99_ms=%s\nslo_ttft_p99_ms=%s\n' \
    "$PROJECT" "$PROXY_CPUS" "$PROXY_MEMORY" "$TOKENS" "$TTFT_MS" "$INTER_TOKEN_MS" \
    "$HOLD_SECS" "$WARMUP_SECS" "$INTRINSIC_MS" "$SLO_P99_MS" "$SLO_TTFT_P99_MS" >"$METADATA"

echo "=== build and start proxy (${PROXY_CPUS} CPUs, ${PROXY_MEMORY}, no swap) ==="
PERF_OUT_DIR="$OUT_DIR" PROXY_CPUS="$PROXY_CPUS" PROXY_MEMORY="$PROXY_MEMORY" \
TOKENS="$TOKENS" TTFT_MS="$TTFT_MS" INTER_TOKEN_MS="$INTER_TOKEN_MS" \
"${COMPOSE[@]}" up --build --detach mock proxy

PROXY_ID="$("${COMPOSE[@]}" ps -q proxy)"
[[ -n "$PROXY_ID" ]] || { echo 'proxy container did not start' >&2; exit 1; }

echo '=== readiness ==='
for _ in $(seq 1 120); do
    if docker exec "$PROXY_ID" curl -fsS --max-time 2 http://127.0.0.1:8901/ready >/dev/null 2>&1; then
        break
    fi
    if [[ "$(docker inspect --format '{{.State.Running}}' "$PROXY_ID")" != true ]]; then
        "${COMPOSE[@]}" logs proxy >&2 || true
        exit 1
    fi
    sleep 0.25
done
docker exec "$PROXY_ID" curl -fsS --max-time 2 http://127.0.0.1:8901/ready >/dev/null 2>&1 \
    || { echo 'proxy never became ready' >&2; exit 1; }

sample_resources &
SAMPLER_PID=$!

echo "=== sweep (intrinsic=${INTRINSIC_MS}ms, p99 SLO=${SLO_P99_MS}ms) ==="
SWEEP_ARGS=(
    --sweep
    --sweep-pid 1
    --target http://proxy:8080
    --endpoint chat
    --model mock-model
    --max-tokens "$TOKENS"
    --rig-sockets-per-stream 1
    --slo-p99-ms "$SLO_P99_MS"
    --slo-ttft-p99-ms "$SLO_TTFT_P99_MS"
    --sweep-hold-secs "$HOLD_SECS"
    --sweep-warmup-secs "$WARMUP_SECS"
    --out "/reports/$(basename "$REPORT")"
)
[[ -n "$MAX_CONCURRENCY" ]] && SWEEP_ARGS+=(--sweep-max-concurrency "$MAX_CONCURRENCY")

set +e
PERF_OUT_DIR="$OUT_DIR" PROXY_CPUS="$PROXY_CPUS" PROXY_MEMORY="$PROXY_MEMORY" \
TOKENS="$TOKENS" TTFT_MS="$TTFT_MS" INTER_TOKEN_MS="$INTER_TOKEN_MS" \
"${COMPOSE[@]}" run --rm loadgen "${SWEEP_ARGS[@]}"
SWEEP_STATUS=$?
set -e

kill "$SAMPLER_PID" 2>/dev/null || true
wait "$SAMPLER_PID" 2>/dev/null || true
SAMPLER_PID=""

echo
echo "report:            $REPORT"
echo "proxy samples:     $RESOURCE_SAMPLES"
echo "run metadata:      $METADATA"
echo "loadgen exit:      $SWEEP_STATUS (non-zero means no sustainable level or harness bound)"
exit "$SWEEP_STATUS"
