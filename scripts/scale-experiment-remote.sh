#!/usr/bin/env bash
# Run the scale-experiment scenarios ON the dedicated host.
#
# This is the half of internal-docs/scale-experiment.md that runs on the
# droplet; scripts/scale-experiment.sh ships it there and starts it detached,
# so a dropped ssh session does not kill a run. It also works on any Linux box
# with release binaries built, which is how it should be pre-flighted before
# the meter runs (S0 and a short S4a at low rate).
#
# Topology: everything on loopback, each process pinned to its own cores
# (taskset) so a replica has a fixed, reportable budget:
#
#   cores 0-3, 4-7, 8-11   proxy replicas 1..3 (--concurrency 4 each)
#   core 12                mock-upstream
#   core 13                redis-server (its own core, so S3 prices Redis alone)
#   cores 14-15            loadgen
#
# Every port is ephemeral (AGENTS.md "Running The Product"); S1 is the one
# exception, because scripts/capacity-sweep.sh hardcodes 18080/18901, which
# is safe on a dedicated host and nowhere else. Teardown runs on every exit
# path and ends with the pgrep check.
set -euo pipefail

SCENARIOS="${*:-all}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
# SCALE_BIN points at a different build directory (a container's
# CARGO_TARGET_DIR in a local pre-flight); the droplet uses the default.
BIN="${SCALE_BIN:-$REPO_ROOT/target/release}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT="$REPO_ROOT/target/scale/$RUN_ID"
mkdir -p "$OUT"

# Core layout. Override on a smaller host, e.g. CORES_PROXY="0-1 2-3 4-5".
read -r -a CORES_PROXY <<<"${CORES_PROXY:-0-3 4-7 8-11}"
CORES_UPSTREAM="${CORES_UPSTREAM:-12}"
CORES_REDIS="${CORES_REDIS:-13}"
CORES_LOADGEN="${CORES_LOADGEN:-14-15}"
PROXY_WORKERS="${PROXY_WORKERS:-4}"

# Extra lines for the mock provider block of every generated config, S1's
# capacity-sweep.sh config included, indented 4 spaces. S1 needs it to raise
# the provider's concurrency ceiling past the 1024 default once the dialect
# has a circuit-breaker field; take the field name from the schema, e.g.
#   PROVIDER_EXTRA_YAML='    <field from schema/llmproxy-v0.schema.json>: ...'
# Strict mode validates it before any load, so a wrong field fails fast.
PROVIDER_EXTRA_YAML="${PROVIDER_EXTRA_YAML:-}"

# S2 target rate ladder (rps), S4 limits. See the plan for why these values.
S2_RATES="${S2_RATES:-1000 2000 5000 10000 20000}"
S4_RPM="${S4_RPM:-6000}"
S4_STREAMS="${S4_STREAMS:-300}"

# LLM-shaped mock defaults, the same as scripts/capacity-sweep.sh.
TOKENS=128 TTFT_MS=250 INTER_TOKEN_MS=25
INTRINSIC_S=3.45

# Throwaway secrets for a throwaway host. Generated per run, kept in a 0600
# file, never printed; the proxy reads them from its environment.
umask 077
LLMPROXY_ADMIN_TOKEN="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
LLMPROXY_SCALE_HMAC="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export LLMPROXY_ADMIN_TOKEN LLMPROXY_SCALE_HMAC
umask 022

ulimit -n 65535 || echo "WARNING: could not raise nofile; S1/S2 may be harness-bound" >&2

# The runner targets Linux. Elsewhere (a macOS pre-flight) pinning and the
# Linux samplers are skipped with a warning, so the functional checks still
# run; numbers from such a run are not evidence.
if ! command -v taskset >/dev/null; then
    echo "WARNING: no taskset; processes run unpinned (not evidence)" >&2
    taskset() { shift 2; "$@"; }
fi
have() { command -v "$1" >/dev/null; }
now() { # epoch seconds with a fraction; macOS date has no %N
    if [[ -n "${EPOCHREALTIME:-}" ]]; then echo "$EPOCHREALTIME"; else python3 -c 'import time; print(time.time())'; fi
}

PIDS=()
cleanup() {
    local status=$?
    for pid in "${PIDS[@]:-}"; do [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null || true; done
    echo
    echo "--- teardown ---"
    local leftover
    # Match the binaries, not every command line that contains the repo
    # path (/root/llm-proxy), which reported this script's own ssh wrapper.
    leftover="$( { pgrep -x mock-upstream; pgrep -x llm-proxy; pgrep -x loadgen; pgrep -f 'redis-server 127.0.0.1'; } || true)"
    if [[ -n "$leftover" ]]; then
        echo "WARNING: processes still running after teardown:"
        ps -o pid,command -p $leftover || true
    else
        echo "clean: no mock-upstream, llm-proxy, loadgen or scale redis remain"
    fi
    exit $status
}
trap cleanup EXIT

free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'
}

# Stop everything a scenario started, so the next one starts from zero.
stop_all() {
    for pid in "${PIDS[@]:-}"; do [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null || true; done
    PIDS=()
}

manifest() {
    {
        echo "run_id: $RUN_ID"
        echo "commit: $(cat REVISION 2>/dev/null || echo unknown)"
        echo "kernel: $(uname -r)"
        echo "cpu: $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ //')"
        echo "nproc: $(nproc 2>/dev/null || sysctl -n hw.ncpu)"
        echo "mem: $(free -g 2>/dev/null | awk '/Mem:/{print $2}') GiB"
        echo "rustc: $(rustc -V 2>/dev/null || echo unknown)"
        echo "ulimit_n: $(ulimit -n)"
        echo "ip_local_port_range: $(cat /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null || echo n/a)"
        echo "loadavg: $(cat /proc/loadavg 2>/dev/null || uptime)"
        echo "provider_extra_yaml: ${PROVIDER_EXTRA_YAML:-none}"
        echo "droplet: $(curl -fsS --max-time 2 http://169.254.169.254/metadata/v1/size 2>/dev/null || echo unknown)" \
             "$(curl -fsS --max-time 2 http://169.254.169.254/metadata/v1/region 2>/dev/null || true)"
    } >"$OUT/manifest.txt"
    cat "$OUT/manifest.txt"
}

# start_mock DIR [mock args...]: sets MOCK_ADDR.
start_mock() {
    local dir="$1"; shift
    taskset -c "$CORES_UPSTREAM" "$BIN/mock-upstream" --listen 127.0.0.1:0 --protocol auto \
        --stats-interval-secs 5 "$@" >"$dir/mock.log" 2>&1 &
    PIDS+=($!)
    MOCK_ADDR=""
    for _ in $(seq 1 100); do
        MOCK_ADDR="$(sed -n 's/^mock-upstream listening on \([^ ]*\).*/\1/p' "$dir/mock.log" | head -1)"
        [[ -n "$MOCK_ADDR" ]] && return 0
        sleep 0.1
    done
    echo "mock never announced an address:" >&2; cat "$dir/mock.log" >&2; exit 1
}

# start_redis DIR [persist]: sets REDIS_PORT, REDIS_PID. With "persist" the
# AOF lives in DIR, so restart_redis brings the keys back (S5b); without it a
# restart comes back empty (S5, which is how an empty store revokes every key).
REDIS_PERSIST=""
redis_server() { # redis_server DIR LOGNAME
    local persist=(--save '' --appendonly no)
    [[ -n "$REDIS_PERSIST" ]] && persist=(--save '' --appendonly yes --appendfsync everysec)
    taskset -c "$CORES_REDIS" redis-server --port "$REDIS_PORT" --bind 127.0.0.1 \
        "${persist[@]}" --protected-mode yes --logfile "$1/$2" \
        --dir "$1" --daemonize no >/dev/null 2>&1 &
    REDIS_PID=$!
    PIDS+=("$REDIS_PID")
}
start_redis() {
    local dir="$1"
    REDIS_PERSIST="${2:-}"
    REDIS_PORT="$(free_port)"
    redis_server "$dir" redis.log
    for _ in $(seq 1 50); do
        redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    echo "redis never answered PING" >&2; exit 1
}

# write_config FILE LISTEN ADMIN STORE: STORE is "none", "in_memory" or "shared".
write_config() {
    local file="$1" listen="$2" admin="$3" store="$4" auth=""
    case "$store" in
        none) ;;
        in_memory)
            auth=$'auth:\n  hmac_secret: "${LLMPROXY_SCALE_HMAC}"\n  store:\n    in_memory: {}' ;;
        shared)
            auth=$'auth:\n  hmac_secret: "${LLMPROXY_SCALE_HMAC}"\n  store:\n    shared: { url: "redis://127.0.0.1:'"$REDIS_PORT"'", namespace: "scale-'"$RUN_ID"'" }' ;;
    esac
    cat >"$file" <<YAML
# Generated by scripts/scale-experiment-remote.sh for run $RUN_ID.
version: 0
listen: 127.0.0.1:$listen
admin: 127.0.0.1:$admin
providers:
  mock:
    base_url: http://$MOCK_ADDR
$UPSTREAM_PROTOCOL_LINE
$PROVIDER_EXTRA_YAML
routes:
  - model: "*"
    provider: mock
$auth
YAML
}

# How the proxy dials the mock; s7 runs both. PROXY_BIN lets s7 profile a
# build with frame pointers without changing the binary the other scenarios
# measure.
UPSTREAM_PROTOCOL="${UPSTREAM_PROTOCOL:-http2}"
PROXY_BIN="${PROXY_BIN:-$BIN/llm-proxy}"
upstream_protocol_line() {
    UPSTREAM_PROTOCOL_LINE=""
    [[ "$UPSTREAM_PROTOCOL" == http2 ]] && UPSTREAM_PROTOCOL_LINE="    protocol: http2"
    return 0
}
upstream_protocol_line

# start_replicas DIR COUNT STORE: sets LISTEN[i], ADMIN[i], PROXY_PID[i].
LISTEN=() ADMIN=() PROXY_PID=()
start_replicas() {
    local dir="$1" count="$2" store="$3" i
    LISTEN=() ADMIN=() PROXY_PID=()
    for ((i = 0; i < count; i++)); do
        LISTEN[i]="$(free_port)"; ADMIN[i]="$(free_port)"
        write_config "$dir/config-r$((i + 1)).yaml" "${LISTEN[i]}" "${ADMIN[i]}" "$store"
        # Validate with the same --service-node the replica runs with: a
        # shared store refuses a config without a node id.
        "$PROXY_BIN" --config "$dir/config-r$((i + 1)).yaml" --mode validate \
            --service-node "scale-r$((i + 1))" >/dev/null
        taskset -c "${CORES_PROXY[i]}" "$PROXY_BIN" --config "$dir/config-r$((i + 1)).yaml" \
            --concurrency "$PROXY_WORKERS" --service-node "scale-r$((i + 1))" \
            >"$dir/proxy-r$((i + 1)).log" 2>&1 &
        PROXY_PID[i]=$!
        PIDS+=("${PROXY_PID[i]}")
    done
    for ((i = 0; i < count; i++)); do
        local ok=""
        for _ in $(seq 1 200); do
            curl -fsS --max-time 2 "http://127.0.0.1:${ADMIN[i]}/ready" >/dev/null 2>&1 && { ok=yes; break; }
            kill -0 "${PROXY_PID[i]}" 2>/dev/null || break
            sleep 0.1
        done
        [[ -n "$ok" ]] || { echo "replica $((i + 1)) never became ready:" >&2; cat "$dir/proxy-r$((i + 1)).log" >&2; exit 1; }
    done
}

admin() { # admin INDEX METHOD PATH BODY
    curl -fsS --max-time 10 -X "$2" -H "authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
        -H 'content-type: application/json' -d "$4" "http://127.0.0.1:${ADMIN[$1]}$3"
}

# mint_tenant_key INDEX: one key for tenant t1, access to every model. Sets KEY.
mint_tenant_key() {
    KEY="$(admin "$1" POST /keys '{"tenant":"t1","key_id":"scale-'"$1"'"}' \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["key"])')"
    admin "$1" PUT /tenants/t1/policy '{"access":"all"}' >/dev/null
}

# A replica learns keys, policy and limits written through another replica on
# its policy poll: 48 s, jittered up to 60 s (the revocation bound in
# auth_filter.rs). Wait out one bound after the last admin write, then prove
# every replica admits KEY, so no scenario measures a replica that has not
# yet seen the limit.
wait_policy_converged() {
    echo "waiting up to 90 s for every replica to load the shared policy..."
    sleep 62
    local i ok
    for ((i = 0; i < ${#LISTEN[@]}; i++)); do
        ok=""
        for _ in $(seq 1 28); do
            if curl -fsS --max-time 10 -o /dev/null -H "authorization: Bearer $KEY" \
                -H 'content-type: application/json' \
                -d '{"model":"mock-model","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}' \
                "http://127.0.0.1:${LISTEN[i]}/v1/chat/completions" 2>/dev/null; then
                ok=yes; break
            fi
            sleep 1
        done
        [[ -n "$ok" ]] || { echo "replica $((i + 1)) never admitted the shared key" >&2; exit 1; }
    done
    echo "policy converged on ${#LISTEN[@]} replicas"
}

scrape_all() { # scrape_all DIR TAG
    local i
    for ((i = 0; i < ${#ADMIN[@]}; i++)); do
        curl -fsS --max-time 5 "http://127.0.0.1:${ADMIN[i]}/stats/prometheus" \
            >"$1/prom-r$((i + 1))-$2.txt" 2>/dev/null || true
    done
    [[ -n "${REDIS_PORT:-}" ]] && redis-cli -p "$REDIS_PORT" info >"$1/redis-$2.txt" 2>/dev/null || true
}

# Background samplers for a scenario: host, per-process, and (for S4b/S5)
# per-replica open streams every 500 ms. Raw samples are kept so the verdict
# can be recomputed.
start_samplers() {
    local dir="$1" pids
    have vmstat && { vmstat 1 >"$dir/vmstat.txt" 2>&1 & PIDS+=($!); }
    pids="$(IFS=,; echo "${PROXY_PID[*]:-}")"
    if [[ -n "$pids" ]] && command -v pidstat >/dev/null; then
        pidstat -r -u -h -p "$pids" 1 >"$dir/pidstat.txt" 2>&1 & PIDS+=($!)
    fi
}
# Fleet in-flight streams every 500 ms, as the upstream sees them:
# mock-upstream's GET /_mock/stats gives the streams it is serving now and
# the peak since the previous poll. A stream the proxy refuses never reaches
# the mock, so this is the ground truth for a fleet ceiling. (The proxy
# exports no in-flight gauge; an earlier sampler read `downstream_cx_active`
# from /stats, which does not exist, and saw 0 for a whole run.) Established
# downstream connections per replica follow as a cross-check, where `ss`
# exists; they overstate, since a refused stream holds its connection until
# the 429 is written. Columns: EPOCH IN_FLIGHT PEAK [SS_R1 SS_R2 SS_R3].
start_stream_sampler() {
    local dir="$1"
    (
        while true; do
            line="$(now) $(curl -fsS --max-time 1 "http://$MOCK_ADDR/_mock/stats" 2>/dev/null \
                | python3 -c 'import json,sys; s=json.load(sys.stdin); print(s["in_flight"], s["peak_in_flight"])' \
                2>/dev/null || echo NA NA)"
            for p in "${LISTEN[@]}"; do
                v=NA
                have ss && v="$(ss -Htn state established "( sport = :$p )" 2>/dev/null | wc -l | tr -d ' ')"
                line="$line ${v:-NA}"
            done
            echo "$line"
            sleep 0.5
        done
    ) >"$dir/streams_active.txt" 2>&1 &
    PIDS+=($!)
}

LOADGEN_PIDS=()
loadgen() { # loadgen ARGS... (pinned)
    taskset -c "$CORES_LOADGEN" "$BIN/loadgen" "$@"
}

# ----------------------------------------------------------------- scenarios

s0() {
    local d="$OUT/s0"; mkdir -p "$d"
    echo "=== S0 pre-flight ==="
    manifest
    "$BIN/loadgen" --self-check | tee "$d/self-check.txt"
    start_mock "$d" --tokens 16
    start_redis "$d"
    start_replicas "$d" 3 shared
    mint_tenant_key 0
    wait_policy_converged
    local i
    for ((i = 0; i < 3; i++)); do
        curl -fsS --max-time 10 -H "authorization: Bearer $KEY" -H 'content-type: application/json' \
            -d '{"model":"mock-model","messages":[{"role":"user","content":"hi"}]}' \
            "http://127.0.0.1:${LISTEN[i]}/v1/chat/completions" >"$d/smoke-r$((i + 1)).json"
        echo "replica $((i + 1)): smoke ok (key minted on replica 1, shared store)"
    done
    # The /proc sampler is unverified on Linux (capacity/README.md caveats):
    # a zero RSS here means S1's resource columns cannot be trusted.
    if [[ -r "/proc/${PROXY_PID[0]}/status" ]]; then
        grep VmRSS "/proc/${PROXY_PID[0]}/status" | tee "$d/rss.txt"
    else
        echo "no /proc: RSS via ps (kB) $(ps -o rss= -p "${PROXY_PID[0]}")" | tee "$d/rss.txt"
    fi
    # The S4b/S5 ground truth: the mock's in-flight gauge must answer.
    curl -fsS --max-time 2 "http://$MOCK_ADDR/_mock/stats" | tee "$d/mock-stats.json"; echo
    stop_all
}

s1() {
    echo "=== S1 streaming capacity, one replica (capacity-sweep.sh) ==="
    # Without PROVIDER_EXTRA_YAML the h2 sweep stops at the default
    # max_requests (1024) with 503 UpstreamOverflow, which is a config
    # ceiling, not the proxy's.
    [[ -n "$PROVIDER_EXTRA_YAML" ]] || echo "NOTE: PROVIDER_EXTRA_YAML unset; the h2 ceiling is the 1024 default" >&2
    for proto in http2 http1; do
        taskset -c "${CORES_PROXY[0]},$CORES_UPSTREAM,$CORES_LOADGEN" \
            ./scripts/capacity-sweep.sh --upstream-protocol "$proto" \
            ${PROVIDER_EXTRA_YAML:+--provider-yaml "$PROVIDER_EXTRA_YAML"} \
            --hold-secs 40 --out-dir "$OUT/s1-$proto" | tee "$OUT/s1-$proto.log" || true
    done
}

s2() {
    local d="$OUT/s2"; mkdir -p "$d"
    echo "=== S2 request-rate ladder, one replica ==="
    start_mock "$d" --tokens 16 --ttft-ms 5 --inter-token-ms 0
    start_replicas "$d" 1 none
    start_samplers "$d"
    local rate
    for rate in $S2_RATES; do
        scrape_all "$d" "before-$rate"
        loadgen --target "http://127.0.0.1:${LISTEN[0]}" --baseline-target "http://$MOCK_ADDR" \
            --endpoint chat --model mock-model --no-stream --rate "$rate" \
            --downstream-mode h1-pool --downstream-h1-pool-size 256 \
            --duration 60 --warmup 5 --out "$d/rate-$rate.json" | tee "$d/rate-$rate.txt" || true
        scrape_all "$d" "after-$rate"
    done
    stop_all
}

s3() {
    local d store rate="${S3_RATE:-3000}"
    echo "=== S3 shared-store cost: 3 replicas, in_memory vs shared, ${rate} rps total ==="
    for store in in_memory shared; do
        d="$OUT/s3-$store"; mkdir -p "$d"
        start_mock "$d" --tokens 16 --ttft-ms 5 --inter-token-ms 0
        [[ "$store" == shared ]] && start_redis "$d"
        start_replicas "$d" 3 "$store"
        local keys=() i
        for ((i = 0; i < 3; i++)); do
            # in_memory: each replica has its own store, so mint on each.
            # shared: minting on each is also fine and keeps the shapes equal.
            mint_tenant_key "$i"; keys[i]="$KEY"
        done
        start_samplers "$d"
        scrape_all "$d" before
        for ((i = 0; i < 3; i++)); do
            loadgen --target "http://127.0.0.1:${LISTEN[i]}" --api-key "${keys[i]}" \
                --endpoint chat --model mock-model --no-stream --rate "$((rate / 3))" \
                --downstream-mode h1-pool --downstream-h1-pool-size 128 \
                --duration 60 --warmup 5 --out "$d/r$((i + 1)).json" >"$d/r$((i + 1)).txt" 2>&1 &
        LOADGEN_PIDS+=($!); PIDS+=($!)
        done
        wait_loadgens
        scrape_all "$d" after
        stop_all; unset REDIS_PORT
    done
}

# Wait for the loadgen children only (samplers run until stop_all).
wait_loadgens() {
    local pid
    for pid in "${LOADGEN_PIDS[@]:-}"; do [[ -n "$pid" ]] && { wait "$pid" || true; }; done
    LOADGEN_PIDS=()
}

s4a() {
    local d="$OUT/s4a"; mkdir -p "$d"
    echo "=== S4a fleet request window: requests_per_minute=$S4_RPM, 3 replicas at 2/3 of it each ==="
    start_mock "$d" --tokens 16 --ttft-ms 5 --inter-token-ms 0
    start_redis "$d"
    start_replicas "$d" 3 shared
    mint_tenant_key 0
    admin 0 PUT /tenants/t1/limits '{"limits":{"requests_per_minute":'"$S4_RPM"'}}' >/dev/null
    wait_policy_converged
    start_samplers "$d"
    # Start 2 s into a minute so the run covers exactly three epoch windows.
    local secs; secs="$(date +%s)"; sleep $(( (60 - secs % 60) + 2 ))
    scrape_all "$d" before
    local per_replica_rps i
    per_replica_rps="$(python3 -c "print(round(2 * $S4_RPM / 3 / 60, 3))")"
    for ((i = 0; i < 3; i++)); do
        loadgen --target "http://127.0.0.1:${LISTEN[i]}" --api-key "$KEY" \
            --endpoint chat --model mock-model --no-stream --rate "$per_replica_rps" \
            --downstream-mode h1-pool --downstream-h1-pool-size 32 \
            --duration 176 --out "$d/r$((i + 1)).json" >"$d/r$((i + 1)).txt" 2>&1 &
        LOADGEN_PIDS+=($!); PIDS+=($!)
    done
    wait_loadgens
    scrape_all "$d" after
    python3 scripts/scale-verdict.py s4a "$d" "$S4_RPM" "$per_replica_rps" | tee "$d/verdict.txt"
    stop_all
}

s4b() {
    local d="$OUT/${1:-s4b}"; mkdir -p "$d"
    local faults="${2:-}" persist="${3:-}" label=""
    [[ -n "$faults" && -n "$persist" ]] && label=" + faults, Redis returns WITH ITS DATA (AOF)"
    [[ -n "$faults" && -z "$persist" ]] && label=" + faults, Redis returns EMPTY (no persistence)"
    echo "=== ${1:-s4b} fleet stream ceiling: concurrent_streams=$S4_STREAMS, offered 2x$label ===" \
        | tee "$d/label.txt"
    start_mock "$d" --tokens "$TOKENS" --ttft-ms "$TTFT_MS" --inter-token-ms "$INTER_TOKEN_MS"
    start_redis "$d" "$persist"
    start_replicas "$d" 3 shared
    mint_tenant_key 0
    admin 0 PUT /tenants/t1/limits '{"limits":{"concurrent_streams":'"$S4_STREAMS"'}}' >/dev/null
    wait_policy_converged
    start_samplers "$d"
    start_stream_sampler "$d"
    scrape_all "$d" before
    # Offered fleet concurrency 2C, by Little's law: rate x stream time.
    # Faults need room after Redis returns (+130 s): one policy poll (60 s),
    # then a stretch of steady state before the last stream time.
    local per_replica_rps i duration=180
    [[ -n "$faults" ]] && duration=300
    per_replica_rps="$(python3 -c "print(round(2 * $S4_STREAMS / 3 / $INTRINSIC_S, 3))")"
    for ((i = 0; i < 3; i++)); do
        loadgen --target "http://127.0.0.1:${LISTEN[i]}" --api-key "$KEY" \
            --endpoint chat --model mock-model --rate "$per_replica_rps" \
            --downstream-mode short --duration "$duration" --warmup 10 \
            --out "$d/r$((i + 1)).json" >"$d/r$((i + 1)).txt" 2>&1 &
        LOADGEN_PIDS+=($!); PIDS+=($!)
    done
    if [[ -n "$faults" ]]; then
        sleep 60
        echo "$(now) SIGKILL replica 3" | tee -a "$d/events.txt"
        kill -9 "${PROXY_PID[2]}"
        sleep 40
        echo "$(now) redis down" | tee -a "$d/events.txt"
        kill "$REDIS_PID"
        sleep 30
        echo "$(now) redis up" | tee -a "$d/events.txt"
        redis_server "$d" redis-2.log
        if [[ -n "$persist" ]]; then
            # Prove the data came back, or S5b is just S5 again.
            sleep 2
            echo "$(now) redis keys after restart: $(redis-cli -p "$REDIS_PORT" dbsize 2>/dev/null)" \
                | tee -a "$d/events.txt"
        fi
    fi
    wait_loadgens
    scrape_all "$d" after
    python3 scripts/scale-verdict.py s4b "$d" "$S4_STREAMS" "$per_replica_rps" "$INTRINSIC_S" \
        "$duration" "$faults" | tee "$d/verdict.txt"
    grep -c -i 'warn' "$d"/proxy-r*.log >"$d/warn-counts.txt" || true
    stop_all; unset REDIS_PORT
}

# S5: Redis returns EMPTY (no persistence). Reproduces the empty-store finding
# in internal-docs/capacity/2026-10-21-digitalocean-shared-rerun.md; expect 401s,
# so a FAIL, until that is fixed. S5b: Redis returns with its AOF, which is
# the case the plan's "limits enforced again after Redis returns" criterion
# means.
s5() { s4b s5 faults; }
s5b() { s4b s5b faults persist; }

# S7: where the proxy-added latency goes, at a rate the proxy serves without
# queueing (S7_RATE, default 1k rps). For each upstream protocol: 70 s of
# open-loop non-streaming load; 20 s in, a 10 s loopback packet capture of
# both hops (headers only), then 15 s of on-CPU perf samples of the proxy
# with call graphs. Point PROXY_BIN at a build with frame pointers
# (RUSTFLAGS="-C force-frame-pointers=yes") or the stacks are one frame
# deep. On-CPU samples cannot show a socket waiting on Nagle or a delayed
# ACK; the packet capture is what shows that.
s7() {
    local d="$OUT/s7" rate="${S7_RATE:-1000}" proto lg mock_port
    mkdir -p "$d"
    for proto in http2 http1; do
        echo "=== S7 latency attribution: ${rate} rps, upstream $proto ==="
        UPSTREAM_PROTOCOL="$proto"; upstream_protocol_line
        mkdir -p "$d/$proto"
        start_mock "$d/$proto" --tokens 16 --ttft-ms 5 --inter-token-ms 0
        mock_port="${MOCK_ADDR##*:}"
        start_replicas "$d/$proto" 1 none
        scrape_all "$d/$proto" before
        local baseline=()
        [[ "$proto" == http1 ]] && baseline=(--baseline-target "http://$MOCK_ADDR")
        loadgen --target "http://127.0.0.1:${LISTEN[0]}" "${baseline[@]}" \
            --endpoint chat --model mock-model --no-stream --rate "$rate" \
            --downstream-mode h1-pool --downstream-h1-pool-size 256 \
            --duration 70 --warmup 5 --out "$d/$proto/loadgen.json" >"$d/$proto/loadgen.txt" 2>&1 &
        lg=$!; LOADGEN_PIDS+=("$lg"); PIDS+=("$lg")
        sleep 20
        timeout 10 tcpdump -i lo -nn -s 160 -w "$d/$proto/hops.pcap" \
            "tcp port $mock_port or tcp port ${LISTEN[0]}" >/dev/null 2>&1 || true
        perf record -F 499 -g -p "${PROXY_PID[0]}" -o "$d/$proto/perf.data" -- sleep 15 \
            >/dev/null 2>&1 || echo "perf record failed" >&2
        wait_loadgens
        scrape_all "$d/$proto" after
        perf report -i "$d/$proto/perf.data" --stdio --no-children --percent-limit 0.5 \
            >"$d/$proto/perf-report.txt" 2>/dev/null || true
        perf script -i "$d/$proto/perf.data" 2>/dev/null | gzip >"$d/$proto/perf-script.txt.gz" || true
        echo "mock port $mock_port, proxy listen ${LISTEN[0]}" >"$d/$proto/ports.txt"
        stop_all
    done
    UPSTREAM_PROTOCOL=http2; upstream_protocol_line
}

s6() {
    local d="$OUT/s6"; mkdir -p "$d"
    local rate="${S6_RATE:-150}" i
    echo "=== S6 soak: 30 min, 3 replicas, shared store, ${rate} streams/s total ==="
    start_mock "$d" --tokens "$TOKENS" --ttft-ms "$TTFT_MS" --inter-token-ms "$INTER_TOKEN_MS"
    start_redis "$d"
    start_replicas "$d" 3 shared
    mint_tenant_key 0
    wait_policy_converged
    start_samplers "$d"
    for ((i = 0; i < 3; i++)); do
        loadgen --target "http://127.0.0.1:${LISTEN[i]}" --api-key "$KEY" \
            --endpoint chat --model mock-model --rate "$((rate / 3))" \
            --downstream-mode h1-pool --downstream-h1-pool-size 512 \
            --duration 1800 --warmup 300 --out "$d/r$((i + 1)).json" >"$d/r$((i + 1)).txt" 2>&1 &
        LOADGEN_PIDS+=($!); PIDS+=($!)
    done
    wait_loadgens
    scrape_all "$d" after
    stop_all; unset REDIS_PORT
}

for s in $SCENARIOS; do
    case "$s" in
        all) manifest; s0; s1; s2; s3; s4a; s4b; s5; s5b; s6; s7 ;;
        s0|s1|s2|s3|s4a|s4b|s5|s5b|s6|s7) "$s" ;;
        *) echo "unknown scenario: $s (s0 s1 s2 s3 s4a s4b s5 s5b s6 s7 all)" >&2; exit 2 ;;
    esac
done
echo "results: $OUT"
