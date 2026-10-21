#!/usr/bin/env bash
# Provision a DigitalOcean droplet, ship one commit, run the scale experiment,
# fetch the results, and tear the droplet down. The plan is
# internal-docs/scale-experiment.md; the scenarios themselves are
# scripts/scale-experiment-remote.sh, which runs on the droplet.
#
# THIS SCRIPT SPENDS MONEY from `up` onward. `plan` and `status` are free.
# `up` refuses to run without --yes-spend and an interactive confirmation of
# the size and hourly price. Droplets bill while they exist, powered off or
# not; only `down` stops billing.
#
# Credentials: doctl uses the context the owner set up with `doctl auth init`.
# This script never reads, writes, or prints an API token, and must not be
# given one as an argument.
#
# Usage:
#   scripts/scale-experiment.sh plan              # sizes and live prices, no spend
#   scripts/scale-experiment.sh up --yes-spend    # create the droplet
#   scripts/scale-experiment.sh ship              # copy HEAD, set up, build release
#   scripts/scale-experiment.sh run [s0 s1 ...]   # start scenarios detached (default: all)
#   scripts/scale-experiment.sh tail              # follow the runner log
#   scripts/scale-experiment.sh fetch             # rsync results to target/scale/
#   scripts/scale-experiment.sh down              # delete every droplet with the run tag
#   scripts/scale-experiment.sh status            # list tagged droplets and their age
#
# Environment:
#   DO_SIZE                 droplet size slug (default c-16)
#   DO_REGION               region slug (default nyc3)
#   DO_IMAGE                image slug (default ubuntu-24-04-x64)
#   DO_SSH_KEY_FINGERPRINT  fingerprint of an SSH key already registered with DO (required for up)
#   SCALE_BUDGET_HOURS      age at which status warns loudly (default 4)
set -euo pipefail

DO_SIZE="${DO_SIZE:-c-16}"
DO_REGION="${DO_REGION:-nyc3}"
DO_IMAGE="${DO_IMAGE:-ubuntu-24-04-x64}"
SCALE_BUDGET_HOURS="${SCALE_BUDGET_HOURS:-4}"
TAG="llmproxy-scale"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
STATE_DIR="$REPO_ROOT/target/scale"
STATE="$STATE_DIR/droplet.env"
KNOWN_HOSTS="$STATE_DIR/known_hosts"
mkdir -p "$STATE_DIR"

die() { echo "error: $*" >&2; exit 1; }

need_doctl() {
    command -v doctl >/dev/null || die "doctl is not installed (brew install doctl), then run 'doctl auth init' yourself"
    doctl account get --format Email --no-header >/dev/null 2>&1 \
        || die "doctl is not authenticated; run 'doctl auth init' yourself (this script never handles the token)"
}

load_state() {
    [[ -r "$STATE" ]] || die "no droplet recorded in $STATE; run 'up' first"
    # shellcheck disable=SC1090
    source "$STATE"
}

# DO_SSH_IDENTITY: a private key file for a droplet whose key is not in the
# ssh agent or ~/.ssh/config (one created outside 'up').
SSH_ID_ARGS=()
[[ -n "${DO_SSH_IDENTITY:-}" ]] && SSH_ID_ARGS=(-i "$DO_SSH_IDENTITY" -o IdentitiesOnly=yes)

ssh_vm() {
    ssh "${SSH_ID_ARGS[@]}" -o UserKnownHostsFile="$KNOWN_HOSTS" -o StrictHostKeyChecking=accept-new \
        -o ServerAliveInterval=30 -o ConnectTimeout=10 "root@$DROPLET_IP" "$@"
}

price_of() {
    doctl compute size list --format Slug,VCPUs,Memory,PriceHourly,PriceMonthly --no-header \
        | awk -v s="$1" '$1 == s'
}

cmd_plan() {
    need_doctl
    echo "Candidate sizes (live list prices from doctl):"
    printf '%-16s %6s %8s %10s %10s\n' SLUG VCPUS MEM_MB USD/HOUR USD/MONTH
    for s in c-16 c-8 s-8vcpu-16gb s-4vcpu-8gb; do
        price_of "$s" | awk '{printf "%-16s %6s %8s %10s %10s\n", $1, $2, $3, $4, $5}'
    done
    local hourly
    hourly="$(price_of "$DO_SIZE" | awk '{print $4}')"
    [[ -n "$hourly" ]] || die "size $DO_SIZE not offered"
    echo
    echo "Selected: $DO_SIZE in $DO_REGION. Budget ${SCALE_BUDGET_HOURS} h ~= \$$(python3 -c "print(round($hourly * $SCALE_BUDGET_HOURS, 2))")"
    echo "Nothing was created."
}

cmd_up() {
    [[ "${1:-}" == "--yes-spend" ]] || die "'up' creates a billed droplet; re-run as: $0 up --yes-spend"
    need_doctl
    [[ -n "${DO_SSH_KEY_FINGERPRINT:-}" ]] || die "set DO_SSH_KEY_FINGERPRINT (doctl compute ssh-key list)"
    [[ ! -e "$STATE" ]] || die "a droplet is already recorded in $STATE; run 'down' first"
    local existing
    existing="$(doctl compute droplet list --tag-name "$TAG" --format ID --no-header)"
    [[ -z "$existing" ]] || die "droplets tagged $TAG already exist ($existing); run 'status' / 'down'"

    local hourly
    hourly="$(price_of "$DO_SIZE" | awk '{print $4}')"
    [[ -n "$hourly" ]] || die "size $DO_SIZE not offered"
    echo "About to create ONE droplet: $DO_SIZE in $DO_REGION at \$$hourly/hour (billed until 'down')."
    read -r -p "Type the size slug to confirm: " answer
    [[ "$answer" == "$DO_SIZE" ]] || die "not confirmed; nothing created"

    local name out id ip
    name="llmproxy-scale-$(date -u +%Y%m%d-%H%M)"
    out="$(doctl compute droplet create "$name" --size "$DO_SIZE" --region "$DO_REGION" \
        --image "$DO_IMAGE" --ssh-keys "$DO_SSH_KEY_FINGERPRINT" --tag-names "$TAG" \
        --wait --format ID,PublicIPv4 --no-header)"
    read -r id ip <<<"$out"
    [[ -n "$id" && -n "$ip" ]] || die "doctl create returned '$out'"
    cat >"$STATE" <<EOF
DROPLET_ID=$id
DROPLET_IP=$ip
DROPLET_NAME=$name
DROPLET_SIZE=$DO_SIZE
DROPLET_CREATED=$(date +%s)
EOF
    echo "created $name ($id) at $ip. Remember: '$0 down' stops billing."
    echo "waiting for ssh..."
    load_state
    for _ in $(seq 1 60); do ssh_vm true 2>/dev/null && { echo "ssh ready"; return 0; }; sleep 5; done
    die "ssh never came up; the droplet still exists and bills: run '$0 down'"
}

cmd_ship() {
    load_state
    [[ -z "$(git status --porcelain)" ]] || die "working tree is dirty; commit first so the report names one commit"
    local rev; rev="$(git rev-parse HEAD)"
    echo "=== shipping $rev ==="
    git archive --format=tar HEAD | ssh_vm 'rm -rf /root/llm-proxy && mkdir -p /root/llm-proxy && tar -x -C /root/llm-proxy'
    ssh_vm "echo $rev > /root/llm-proxy/REVISION"
    echo "=== host setup ==="
    ssh_vm 'cd /root/llm-proxy && scripts/setup-test-machine.sh --user root --install-docker'
    ssh_vm 'DEBIAN_FRONTEND=noninteractive apt-get install -y redis-server redis-tools sysstat python3 rsync \
        && systemctl disable --now redis-server'
    echo "=== release build ==="
    ssh_vm 'cd /root/llm-proxy && . "$HOME/.cargo/env" && cargo build --release -p proxy -p mockupstream -p loadgen'
}

# The runner's knobs that `run` forwards from this shell, when set, e.g.
#   S4_RPM=600 scripts/scale-experiment.sh run s0 s4a
RUNNER_KNOBS="S2_RATES S3_RATE S4_RPM S4_STREAMS S6_RATE S7_RATE CORES_PROXY CORES_UPSTREAM
    CORES_REDIS CORES_LOADGEN PROXY_WORKERS UPSTREAM_PROTOCOL PROVIDER_EXTRA_YAML"

cmd_run() {
    load_state
    local run_id knob env_args=""; run_id="$(date -u +%Y%m%dT%H%M%SZ)"
    for knob in $RUNNER_KNOBS; do
        [[ -n "${!knob:-}" ]] && env_args+=" $knob=$(printf '%q' "${!knob}")"
    done
    # Detached, so a dropped ssh session does not kill the run. The whole
    # backgrounded list is redirected too: otherwise its subshell holds the
    # ssh channel open and this command waits for the whole run.
    ssh_vm "cd /root/llm-proxy && mkdir -p target/scale/$run_id && . \"\$HOME/.cargo/env\" \
        && { RUN_ID=$run_id$env_args setsid nohup scripts/scale-experiment-remote.sh ${*:-all} \
           > target/scale/$run_id/runner.log 2>&1 < /dev/null & } > /dev/null 2>&1 < /dev/null; echo started $run_id"
    echo "RUN_ID=$run_id" >>"$STATE"
    echo "follow with: $0 tail"
}

cmd_tail() {
    load_state
    [[ -n "${RUN_ID:-}" ]] || die "no run recorded"
    ssh_vm "tail -n 50 -f /root/llm-proxy/target/scale/$RUN_ID/runner.log"
}

cmd_fetch() {
    load_state
    mkdir -p "$STATE_DIR/remote"
    rsync -az -e "ssh ${SSH_ID_ARGS[*]} -o UserKnownHostsFile=$KNOWN_HOSTS -o StrictHostKeyChecking=accept-new" \
        "root@$DROPLET_IP:/root/llm-proxy/target/scale/" "$STATE_DIR/remote/"
    echo "results in $STATE_DIR/remote/"
}

cmd_status() {
    need_doctl
    doctl compute droplet list --tag-name "$TAG" --format ID,Name,PublicIPv4,Size,Status,Created
    if [[ -r "$STATE" ]]; then
        load_state
        local age_h
        age_h="$(python3 -c "import time; print(round((time.time() - $DROPLET_CREATED) / 3600, 2))")"
        echo "recorded droplet $DROPLET_NAME: ${age_h} h old (budget ${SCALE_BUDGET_HOURS} h)"
        if python3 -c "import sys; sys.exit(0 if $age_h > $SCALE_BUDGET_HOURS else 1)"; then
            echo "!!! OVER BUDGET: fetch results and run '$0 down' now" >&2
        fi
    fi
}

cmd_down() {
    need_doctl
    local list
    list="$(doctl compute droplet list --tag-name "$TAG" --format ID,Name,PublicIPv4 --no-header)"
    if [[ -z "$list" ]]; then
        echo "no droplets tagged $TAG"
    else
        echo "Will DELETE these droplets (and everything on them; fetch first):"
        echo "$list"
        read -r -p "Type 'delete' to confirm: " answer
        [[ "$answer" == delete ]] || die "not confirmed; nothing deleted"
        doctl compute droplet delete --tag-name "$TAG" --force
    fi
    command rm -f "$STATE" "$KNOWN_HOSTS"
    echo "done. Verify with: $0 status"
}

case "${1:-}" in
    plan)   shift; cmd_plan "$@" ;;
    up)     shift; cmd_up "$@" ;;
    ship)   shift; cmd_ship "$@" ;;
    run)    shift; cmd_run "$@" ;;
    tail)   shift; cmd_tail "$@" ;;
    fetch)  shift; cmd_fetch "$@" ;;
    status) shift; cmd_status "$@" ;;
    down)   shift; cmd_down "$@" ;;
    *) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
