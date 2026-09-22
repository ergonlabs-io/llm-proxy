#!/usr/bin/env bash
# Prepare an Ubuntu capacity/conformance host for llm-proxy.
#
# Installs the native build dependencies observed by the xDS conformance and
# rename-churn drills, installs Rust for one login user, verifies Docker, and
# raises that user's login-session descriptor limit. It deliberately does not
# run a benchmark: a setup success is not test evidence.
set -euo pipefail

MIN_RUST_VERSION="1.78.0"
INSTALL_DOCKER=false
TEST_USER="${SUDO_USER:-${USER:-root}}"

usage() {
    cat <<'USAGE'
Usage: sudo scripts/setup-test-machine.sh [options]

Prepare an Ubuntu host for llm-proxy's Docker-backed xDS conformance test and
the 5k-rps rename-churn acceptance drill.

Options:
  --user NAME        Login user that will run the tests (default: sudo caller)
  --install-docker   Install Ubuntu's docker.io package if Docker is absent
  -h, --help         Show this help

The script configures a 65,535 soft/hard nofile limit for the selected user.
Log out and back in before running the churn drill; an existing shell keeps
its old limit.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --user)
            if [[ $# -lt 2 ]]; then
                echo "--user requires a login name" >&2
                exit 2
            fi
            TEST_USER="$2"
            shift 2
            ;;
        --install-docker)
            INSTALL_DOCKER=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ "$EUID" -ne 0 ]]; then
    echo "run as root (for example: sudo $0)" >&2
    exit 1
fi

if [[ ! -r /etc/os-release ]]; then
    echo "unsupported host: /etc/os-release is missing" >&2
    exit 1
fi

# shellcheck disable=SC1091
source /etc/os-release
if [[ "${ID:-}" != "ubuntu" ]]; then
    echo "unsupported distribution: this setup script currently supports Ubuntu only" >&2
    exit 1
fi

if ! id "$TEST_USER" >/dev/null 2>&1; then
    echo "test user does not exist: $TEST_USER" >&2
    exit 1
fi

TEST_HOME="$(getent passwd "$TEST_USER" | cut -d: -f6)"
if [[ -z "$TEST_HOME" || ! -d "$TEST_HOME" ]]; then
    echo "could not determine a home directory for $TEST_USER" >&2
    exit 1
fi

echo "=== native build dependencies ==="
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    ca-certificates \
    curl \
    git \
    libssl-dev \
    pkg-config \
    protobuf-compiler

if ! command -v docker >/dev/null 2>&1; then
    if [[ "$INSTALL_DOCKER" != true ]]; then
        echo "Docker is required but not installed. Re-run with --install-docker or install Docker first." >&2
        exit 1
    fi
    echo "=== Docker ==="
    DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now docker
fi

if ! docker info >/dev/null 2>&1; then
    echo "Docker is installed but its daemon is unavailable" >&2
    exit 1
fi

if [[ "$TEST_USER" != root ]]; then
    usermod -aG docker "$TEST_USER"
fi

if ! sudo -H -u "$TEST_USER" env PATH="$TEST_HOME/.cargo/bin:$PATH" cargo --version >/dev/null 2>&1; then
    echo "=== Rust ==="
    sudo -H -u "$TEST_USER" sh -c \
        'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal'
fi

RUST_VERSION="$({ sudo -H -u "$TEST_USER" env PATH="$TEST_HOME/.cargo/bin:$PATH" rustc --version; } | awk '{print $2}')"
if [[ "$(printf '%s\n%s\n' "$MIN_RUST_VERSION" "$RUST_VERSION" | sort -V | head -n1)" != "$MIN_RUST_VERSION" ]]; then
    echo "Rust $RUST_VERSION is older than the workspace minimum $MIN_RUST_VERSION" >&2
    exit 1
fi

cat > /etc/security/limits.d/99-llm-proxy-test.conf <<EOF
# The rename-churn drill opens enough concurrent sockets that Ubuntu's default
# 1024-descriptor login limit invalidates the run before it measures capacity.
$TEST_USER soft nofile 65535
$TEST_USER hard nofile 65535
EOF

echo
echo "Setup complete for $TEST_USER. Log out and back in before testing."
echo "Then verify: ulimit -n; docker info >/dev/null; cargo --version; protoc --version"
echo "Conformance: cd <repo> && make xds-conformance"
echo "Churn gate:  cd <repo> && cargo test -p diffrig --test rename_churn -- --ignored --nocapture"
