#!/usr/bin/env bash
# Latency lab, Layer 1 driver (internal-docs/latency-lab.md).
#
#   scripts/latency-lab.sh ab --base REV --cand REV [--cand-patch FILE]
#                             [--host USER@IP] [--rounds N] [--scenario "a b"]
#   scripts/latency-lab.sh compare DIR
#
# `ab` builds both revisions on a Linux host, runs them alternately with
# scripts/lab/ab-remote.sh, copies the results to target/lab/<run>/ and
# prints the comparison (scripts/lab/ab_compare.py). ACCESS_LOG=json|text
# turns on an access log (see ab-remote.sh), and then scripts/lab/phases.py
# also prints the per-phase breakdown. REV is anything `git rev-parse` takes;
# uncommitted changes are never shipped, so commit first or pass
# --cand-patch. The same REV for both arms is the self-A/B that
# validates the instrument: it must report no change.
#
# Builds are cached on the host by revision (and patch), in one shared target
# dir, so a rerun with the same base costs only the candidate's build.
# They have frame pointers and line tables, so Layer 2 can profile the same
# binaries; both arms pay that cost equally.
#
# The host needs cargo, taskset, python3, curl and patch. Nothing here
# creates or deletes a machine; see scripts/scale-experiment.sh for that.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

HOST="${LAB_HOST:-}"
KNOWN_HOSTS="${LAB_KNOWN_HOSTS:-$REPO_ROOT/target/scale/known_hosts}"
REMOTE=/root/lab
SSH_OPTS=(-o ConnectTimeout=15 -o ServerAliveInterval=30)
[[ -f "$KNOWN_HOSTS" ]] && SSH_OPTS+=(-o UserKnownHostsFile="$KNOWN_HOSTS")

die() { echo "latency-lab: $*" >&2; exit 1; }
rsh() { ssh "${SSH_OPTS[@]}" "$HOST" "$@"; }

usage() { sed -n '3,9p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

# build_rev REV [PATCH]: prints the label; the host then has
# $REMOTE/bin/<label>/{llm-proxy,loadgen,mock-upstream,REVISION}.
build_rev() {
    local rev="$1" patch="${2:-}" sha label
    sha="$(git rev-parse --verify "$rev^{commit}")" || die "not a revision: $rev"
    label="${sha:0:10}"
    if [[ -n "$patch" ]]; then
        [[ -f "$patch" ]] || die "no such patch: $patch"
        label="$label-p$(shasum -a 256 "$patch" | cut -c1-8)"
    fi
    if rsh "test -x $REMOTE/bin/$label/llm-proxy"; then
        echo "build $label: cached" >&2
        echo "$label"; return
    fi
    echo "build $label: shipping $rev${patch:+ + $(basename "$patch")}" >&2
    # `tar -m` stamps every file with the time of extraction. git archive
    # stamps them with the commit time instead, and cargo, sharing one
    # target dir across revisions, decides freshness by mtime: a revision
    # committed before the last build ran would be taken as already built,
    # and its arm would silently run the previous binary.
    git archive --format=tar "$sha" | rsh "rm -rf $REMOTE/src/$label && mkdir -p $REMOTE/src/$label && tar -xm -C $REMOTE/src/$label"
    if [[ -n "$patch" ]]; then
        rsh "cd $REMOTE/src/$label && patch -p1 --forward --quiet" <"$patch"
    fi
    echo "build $label: compiling (a first build takes about 8 minutes)" >&2
    rsh "set -e; . \$HOME/.cargo/env; cd $REMOTE/src/$label
         CARGO_PROFILE_RELEASE_DEBUG=line-tables-only RUSTFLAGS='-C force-frame-pointers=yes' \
             cargo build --release --locked -p proxy -p loadgen -p mockupstream \
             --target-dir $REMOTE/target 2>&1 | tail -1
         mkdir -p $REMOTE/bin/$label
         cp $REMOTE/target/release/llm-proxy $REMOTE/target/release/loadgen \
            $REMOTE/target/release/mock-upstream $REMOTE/bin/$label/
         echo '$sha${patch:+ + $(basename "$patch")}' > $REMOTE/bin/$label/REVISION" >&2
    echo "$label"
}

cmd_compare() {
    local dir="$1"
    python3 "$REPO_ROOT/scripts/lab/ab_compare.py" "$dir" --json "$dir/result.json" | tee "$dir/summary.txt"
    if compgen -G "$dir/*/*/access.log" >/dev/null; then
        python3 "$REPO_ROOT/scripts/lab/phases.py" "$dir" --json "$dir/phases.json" | tee "$dir/phases.txt"
    fi
}

cmd_ab() {
    local base="" cand="" patch="" rounds="${ROUNDS:-4}" scenarios="${SCENARIOS:-nonstream-1k stream-256}"
    while (($#)); do
        case "$1" in
            --base) base="$2"; shift 2 ;;
            --cand) cand="$2"; shift 2 ;;
            --cand-patch) patch="$2"; shift 2 ;;
            --host) HOST="$2"; shift 2 ;;
            --rounds) rounds="$2"; shift 2 ;;
            --scenario) scenarios="$2"; shift 2 ;;
            *) usage ;;
        esac
    done
    [[ -n "$base" && -n "$cand" ]] || usage
    [[ -n "$HOST" ]] || die "set --host USER@IP or LAB_HOST"

    local base_label cand_label run_id out
    base_label="$(build_rev "$base")"
    cand_label="$(build_rev "$cand" "$patch")"
    # Two different revisions must not produce one binary; if they do, the
    # build cache served a stale build and the A/B would compare a build
    # with itself. (A revision whose change cannot reach the binary, such as
    # a docs-only commit, trips this too; compare against its parent instead.)
    if [[ "$base_label" != "$cand_label" ]] &&
        rsh "cmp -s $REMOTE/bin/$base_label/llm-proxy $REMOTE/bin/$cand_label/llm-proxy"; then
        die "$base_label and $cand_label built the same llm-proxy binary; delete $REMOTE/bin/$cand_label on the host and rerun"
    fi
    run_id="$(date -u +%Y%m%dT%H%M%SZ)-$base_label..$cand_label"
    out="$REPO_ROOT/target/lab/$run_id"

    rsh "mkdir -p $REMOTE/runs/$run_id $REMOTE/scripts"
    scp -q "${SSH_OPTS[@]}" "$REPO_ROOT/scripts/lab/ab-remote.sh" "$HOST:$REMOTE/scripts/"
    # Detached, so a dropped ssh session does not kill the run.
    rsh "cd $REMOTE && (ROUNDS=$rounds SCENARIOS='$scenarios' ${DURATION:+DURATION=$DURATION} \
         ${UPSTREAM:+UPSTREAM=$UPSTREAM} ${CORES_PROXY:+CORES_PROXY=$CORES_PROXY} \
         ${ACCESS_LOG:+ACCESS_LOG=$ACCESS_LOG} ${ACCESS_LOG_ARMS:+ACCESS_LOG_ARMS='$ACCESS_LOG_ARMS'} \
         nohup bash scripts/ab-remote.sh $REMOTE/bin/$base_label $REMOTE/bin/$cand_label \
         $REMOTE/runs/$run_id >$REMOTE/runs/$run_id/runner.log 2>&1 </dev/null & echo \$! >$REMOTE/runs/$run_id/pid)"
    echo "run $run_id: started on $HOST; log at $REMOTE/runs/$run_id/runner.log"
    while rsh "kill -0 \$(cat $REMOTE/runs/$run_id/pid) 2>/dev/null"; do sleep 15; done
    mkdir -p "$out"
    rsync -az -e "ssh ${SSH_OPTS[*]}" "$HOST:$REMOTE/runs/$run_id/" "$out/"
    tail -3 "$out/runner.log"
    [[ -f "$out/DONE" ]] || die "run did not finish; see $out/runner.log"
    cmd_compare "$out"
    echo "results: $out"
}

case "${1:-}" in
    ab) shift; cmd_ab "$@" ;;
    compare) shift; [[ $# -eq 1 ]] || usage; cmd_compare "$1" ;;
    *) usage ;;
esac
