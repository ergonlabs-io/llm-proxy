#!/usr/bin/env bash
# Run h2spec (HTTP/2 conformance, RFC 7540/7541) against the proxy's downstream
# HTTP/2 listener, over plaintext prior knowledge and over TLS with ALPN.
#
# Opt-in, not part of `make ci`: it downloads h2spec and starts the binary.
# Usage: scripts/h2spec.sh [extra h2spec args, e.g. `http2/6.5`]
#
# h2spec is pinned by its source archive and that archive's SHA-256. v2.6.0 is
# the latest release and publishes no darwin/arm64 binary and no checksum file,
# so the script builds the pinned source with the Go toolchain the QA suite
# already needs; `go build` checks the module dependencies against h2spec's own
# go.sum. The archive and binary live under target/ (git-ignored).
#
# The proxy answers every request with a direct_response, so the run exercises
# the downstream codec and nothing upstream of it. The body is longer than 5
# bytes, or h2spec skips its flow-control cases (6.9.2).
#
# The plaintext listener sets codec_type HTTP2, so every case reaches the h2
# codec. Under AUTO, cleartext detection serves anything that is not the h2
# preface as HTTP/1.1, as Envoy does, and h2spec's invalid-preface case would
# test the h1 codec. The TLS listener keeps AUTO, where ALPN selects h2.
#
# KNOWN_FAILURES lists cases that fail for a recorded reason (see each entry's
# envoy-divergences.md row). The run fails on any other failure, and on a known
# failure that now passes, so the list cannot go stale.
set -euo pipefail

H2SPEC_VERSION=2.6.0
H2SPEC_SHA256=c438130c70c6cec2c20276726a454a9249b64ba48ca89ce37f39aa721867b4f0
H2SPEC_URL="https://github.com/summerwind/h2spec/archive/refs/tags/v${H2SPEC_VERSION}.tar.gz"

# <run>|<package>|<case description>
KNOWN_FAILURES=(
    # hyper's h2 server sends no GOAWAY on a bad preface and closes with the
    # rest of the preface unread, so the kernel resets the connection. Over
    # TLS, rustls has read the whole record, so the close is a clean FIN and
    # the case passes. envoy-divergences.md row 41.
    "plain|http2/3.5|Sends invalid connection preface"
)

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT/target}
WORK="$TARGET_DIR/h2spec"
H2SPEC="$WORK/h2spec-$H2SPEC_VERSION"
PROXY="$TARGET_DIR/debug/llm-proxy"
mkdir -p "$WORK"

# ---- fetch, verify, build h2spec --------------------------------------------
if [[ ! -x "$H2SPEC" ]]; then
    archive="$WORK/h2spec-$H2SPEC_VERSION.tar.gz"
    if [[ ! -f "$archive" ]]; then
        curl -fsSL --max-time 120 -o "$archive.part" "$H2SPEC_URL"
        command mv -f "$archive.part" "$archive"
    fi
    actual=$(shasum -a 256 "$archive" | cut -d' ' -f1)
    if [[ "$actual" != "$H2SPEC_SHA256" ]]; then
        echo "h2spec: checksum mismatch for $archive" >&2
        echo "  expected $H2SPEC_SHA256" >&2
        echo "  actual   $actual" >&2
        command rm -f "$archive"
        exit 1
    fi
    src="$WORK/src"
    command rm -rf "$src"
    mkdir -p "$src"
    tar -xzf "$archive" -C "$src"
    GOFLAGS=-mod=readonly go build -C "$src/h2spec-$H2SPEC_VERSION" -trimpath \
        -ldflags "-X main.VERSION=$H2SPEC_VERSION -X main.COMMIT=v$H2SPEC_VERSION" \
        -o "$H2SPEC" ./cmd/h2spec
fi

# ---- build the proxy ---------------------------------------------------------
cargo build -q -p proxy --bin llm-proxy

# ---- config: one plaintext and one TLS listener, both on free ports ---------
free_port() {
    python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}
PLAIN_PORT=$(free_port)
TLS_PORT=$(free_port)

RUN="$WORK/run"
command rm -rf "$RUN"
mkdir -p "$RUN"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
    -keyout "$RUN/key.pem" -out "$RUN/cert.pem" >/dev/null 2>&1

hcm() {
    cat <<EOF
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: h2spec_$1
          codec_type: $2
          route_config:
            virtual_hosts:
            - name: all
              domains: ["*"]
              routes:
              - match: { prefix: "/" }
                direct_response: { status: 200, body: { inline_string: "h2spec response body, longer than one small flow-control window"  } }
          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
EOF
}

cat >"$RUN/bootstrap.yaml" <<EOF
static_resources:
  listeners:
  - name: h2spec_plain
    address: { socket_address: { address: 127.0.0.1, port_value: $PLAIN_PORT } }
    filter_chains:
    - filters:
$(hcm plain HTTP2)
  - name: h2spec_tls
    address: { socket_address: { address: 127.0.0.1, port_value: $TLS_PORT } }
    filter_chains:
    - transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            alpn_protocols: ["h2", "http/1.1"]
            tls_certificates:
            - certificate_chain: { filename: $RUN/cert.pem }
              private_key: { filename: $RUN/key.pem }
      filters:
$(hcm tls AUTO)
EOF

# ---- start, run, tear down ---------------------------------------------------
"$PROXY" -c "$RUN/bootstrap.yaml" >"$RUN/proxy.log" 2>&1 &
PROXY_PID=$!
trap 'kill "$PROXY_PID" 2>/dev/null; wait "$PROXY_PID" 2>/dev/null || true' EXIT

ready=0
for _ in $(seq 1 100); do
    if curl -sS --max-time 1 --http2-prior-knowledge -o /dev/null "http://127.0.0.1:$PLAIN_PORT/" 2>/dev/null; then
        ready=1
        break
    fi
    kill -0 "$PROXY_PID" 2>/dev/null || break
    sleep 0.1
done
if [[ $ready -ne 1 ]]; then
    echo "h2spec: proxy did not become ready; log:" >&2
    cat "$RUN/proxy.log" >&2
    exit 1
fi

echo "== h2spec $H2SPEC_VERSION, plaintext prior knowledge, 127.0.0.1:$PLAIN_PORT"
"$H2SPEC" -h 127.0.0.1 -p "$PLAIN_PORT" -o 2 -j "$RUN/plain.xml" "$@" || true
echo "== h2spec $H2SPEC_VERSION, TLS + ALPN h2, 127.0.0.1:$TLS_PORT"
"$H2SPEC" -h 127.0.0.1 -p "$TLS_PORT" -t -k -o 2 -j "$RUN/tls.xml" "$@" || true
echo "JUnit reports: $RUN/plain.xml $RUN/tls.xml; proxy log: $RUN/proxy.log"

# Compare the failures in both reports with KNOWN_FAILURES. A case filtered out
# by an h2spec argument is absent from the report, so it is not a stale entry.
python3 -I - "$RUN" "${KNOWN_FAILURES[@]}" <<'PY'
import sys
import xml.etree.ElementTree as ET

run_dir, known = sys.argv[1], set(sys.argv[2:])
failed, passed, total = set(), set(), 0
for run in ("plain", "tls"):
    for case in ET.parse(f"{run_dir}/{run}.xml").iter("testcase"):
        total += 1
        key = f"{run}|{case.get('package')}|{case.get('classname')}"
        if case.find("failure") is not None or case.find("error") is not None:
            failed.add(key)
        elif case.find("skipped") is None:
            passed.add(key)
print(f"h2spec: {total} cases, {len(passed)} passed, {len(failed)} failed, "
      f"{total - len(passed) - len(failed)} skipped (plaintext + TLS)")
for key in sorted(failed & known):
    print(f"  known failure: {key}")
unexpected = sorted(failed - known)
fixed = sorted(known & passed)
for key in unexpected:
    print(f"  UNEXPECTED failure: {key}")
for key in fixed:
    print(f"  known failure now passes, remove it from KNOWN_FAILURES: {key}")
sys.exit(1 if unexpected or fixed else 0)
PY
