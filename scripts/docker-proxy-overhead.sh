#!/usr/bin/env bash
# WP-30 Docker proxy-overhead baseline. Topology:
#
#   loadgen (separate cgroup) -> proxy (2 CPUs / 1 GiB) -> mock upstream
#   loadgen (same separate cgroup) -----------------------> mock upstream
#
# The two passes are sequential and otherwise identical. Their latency
# percentile deltas are proxy-added overhead, not an end-to-end provider SLO.
# Docker Desktop makes this a reproducible local baseline, not a claim about
# dedicated Linux hardware. Repeat on the target VM before using a result for
# sizing or a regression gate.
set -euo pipefail

PROXY_CPUS="${PROXY_CPUS:-2.0}"
PROXY_MEMORY="${PROXY_MEMORY:-1g}"
CONCURRENCY=1
DURATION_SECS=60
WARMUP_SECS=10
TOKENS=128
TTFT_MS=250
INTER_TOKEN_MS=25
OUT_DIR="target/docker-overhead"
PROJECT="llmproxy-overhead-$$"
COMPOSE_FILE="testing/perf/compose.yaml"
SAMPLE_INTERVAL_SECS=0.5

usage() {
    cat <<'USAGE'
Usage: scripts/docker-proxy-overhead.sh [options]

Runs identical sequential streamed-chat passes through the proxy and directly
against the mock upstream. Defaults constrain only the proxy container to
2 CPUs and 1 GiB with no swap. Results are written under target/docker-overhead.

Options:
  --concurrency N            Closed-loop streams in flight (default: 1)
  --duration-secs N          Seconds in each pass (default: 60)
  --warmup-secs N            Discarded warm-up seconds in each pass (default: 10)
  --tokens N                 Streamed tokens per response (default: 128)
  --ttft-ms N                Mock time to first token (default: 250)
  --inter-token-ms N         Mock inter-token delay (default: 25)
  --proxy-cpus N             Proxy CPU quota (default: 2.0)
  --proxy-memory SIZE        Proxy memory and swap limit (default: 1g)
  --out-dir DIR              Output directory (default: target/docker-overhead)
  -h, --help                 Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --concurrency) CONCURRENCY="$2"; shift 2 ;;
        --duration-secs) DURATION_SECS="$2"; shift 2 ;;
        --warmup-secs) WARMUP_SECS="$2"; shift 2 ;;
        --tokens) TOKENS="$2"; shift 2 ;;
        --ttft-ms) TTFT_MS="$2"; shift 2 ;;
        --inter-token-ms) INTER_TOKEN_MS="$2"; shift 2 ;;
        --proxy-cpus) PROXY_CPUS="$2"; shift 2 ;;
        --proxy-memory) PROXY_MEMORY="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
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
MOCK_ID=""
SAMPLER_PID=""
RUN_TAG="chat-http2-${CONCURRENCY}c-${TOKENS}tok-${PROXY_CPUS}cpu-${PROXY_MEMORY}"
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

wait_for_healthy() {
    local name=$1 id status
    id="$("${COMPOSE[@]}" ps -q "$name")"
    [[ -n "$id" ]] || { echo "$name container did not start" >&2; exit 1; }

    for _ in $(seq 1 120); do
        status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$id")"
        [[ "$status" == healthy ]] && { printf '%s' "$id"; return; }
        if [[ "$(docker inspect --format '{{.State.Running}}' "$id")" != true ]]; then
            "${COMPOSE[@]}" logs "$name" >&2 || true
            exit 1
        fi
        sleep 0.25
    done
    "${COMPOSE[@]}" logs "$name" >&2 || true
    echo "$name never became healthy" >&2
    exit 1
}

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

printf 'project=%s\nproxy_cpus=%s\nproxy_memory=%s\nconcurrency=%s\nduration_secs=%s\nwarmup_secs=%s\ntokens=%s\nttft_ms=%s\ninter_token_ms=%s\nproxy_target=http://proxy:8080\nbaseline_target=http://mock:8080\n' \
    "$PROJECT" "$PROXY_CPUS" "$PROXY_MEMORY" "$CONCURRENCY" "$DURATION_SECS" "$WARMUP_SECS" \
    "$TOKENS" "$TTFT_MS" "$INTER_TOKEN_MS" >"$METADATA"

echo "=== build and start proxy (${PROXY_CPUS} CPUs, ${PROXY_MEMORY}, no swap) ==="
PERF_OUT_DIR="$OUT_DIR" PROXY_CPUS="$PROXY_CPUS" PROXY_MEMORY="$PROXY_MEMORY" \
TOKENS="$TOKENS" TTFT_MS="$TTFT_MS" INTER_TOKEN_MS="$INTER_TOKEN_MS" \
"${COMPOSE[@]}" up --build --detach mock proxy

echo '=== readiness ==='
MOCK_ID="$(wait_for_healthy mock)"
PROXY_ID="$(wait_for_healthy proxy)"

sample_resources &
SAMPLER_PID=$!

echo "=== proxy overhead (${CONCURRENCY} concurrent streams, ${DURATION_SECS}s per pass) ==="
set +e
PERF_OUT_DIR="$OUT_DIR" PROXY_CPUS="$PROXY_CPUS" PROXY_MEMORY="$PROXY_MEMORY" \
TOKENS="$TOKENS" TTFT_MS="$TTFT_MS" INTER_TOKEN_MS="$INTER_TOKEN_MS" \
"${COMPOSE[@]}" run --rm loadgen \
    --target http://proxy:8080 \
    --baseline-target http://mock:8080 \
    --endpoint chat \
    --model mock-model \
    --max-tokens "$TOKENS" \
    --concurrency "$CONCURRENCY" \
    --duration "$DURATION_SECS" \
    --warmup "$WARMUP_SECS" \
    --rig-sockets-per-stream 1 \
    --out "/reports/$(basename "$REPORT")"
LOADGEN_STATUS=$?
set -e

kill "$SAMPLER_PID" 2>/dev/null || true
wait "$SAMPLER_PID" 2>/dev/null || true
SAMPLER_PID=""

echo
echo "report:            $REPORT"
echo "proxy samples:     $RESOURCE_SAMPLES"
echo "run metadata:      $METADATA"
echo "loadgen exit:      $LOADGEN_STATUS (non-zero means proxy pass had errors)"
exit "$LOADGEN_STATUS"
