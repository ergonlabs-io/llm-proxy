#!/usr/bin/env bash
# WP-02: vendor the pinned Envoy API protos + their proto dependencies into
# crates/proxy-api/vendor/. The pins below mirror envoy v1.38.0's
# api/bazel/repository_locations.bzl exactly — bump them only via a dedicated
# proto-upgrade change (IMPLEMENTATION_PLAN.md ground rule #1).
set -euo pipefail

ENVOY_VERSION=1.38.0
PGV_VERSION=1.3.3
XDS_COMMIT=8bfbf64dc13ee1a570be4fbdcfccbdd8532463f0
GOOGLEAPIS_COMMIT=fd52b5754b2b268bc3a22a10f29844f206abb327
CEL_SPEC_VERSION=0.25.1
OTEL_PROTO_VERSION=1.10.0
CLIENT_MODEL_VERSION=0.6.2

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR="$ROOT/crates/proxy-api/vendor"
CACHE="${PROTO_CACHE:-${TMPDIR:-/tmp}/llm-proxy-proto-cache}"
mkdir -p "$CACHE"

fetch() { # fetch <filename> <url> -> prints cached path
  local out="$CACHE/$1"
  [ -f "$out" ] || curl -sSfL -o "$out" "$2"
  echo "$out"
}

extract() { # extract <tarball> <paths...>
  tar -xzf "$1" -C "$CACHE" "${@:2}"
}

rm -rf "$VENDOR"
mkdir -p "$VENDOR" "$VENDOR/google"

t=$(fetch "envoy-$ENVOY_VERSION.tar.gz" "https://github.com/envoyproxy/envoy/archive/refs/tags/v$ENVOY_VERSION.tar.gz")
extract "$t" "envoy-$ENVOY_VERSION/api/envoy"
cp -R "$CACHE/envoy-$ENVOY_VERSION/api/envoy" "$VENDOR/envoy"

t=$(fetch "pgv-$PGV_VERSION.tar.gz" "https://github.com/bufbuild/protoc-gen-validate/archive/refs/tags/v$PGV_VERSION.tar.gz")
extract "$t" "protoc-gen-validate-$PGV_VERSION/validate"
cp -R "$CACHE/protoc-gen-validate-$PGV_VERSION/validate" "$VENDOR/validate"

t=$(fetch "xds-$XDS_COMMIT.tar.gz" "https://github.com/cncf/xds/archive/$XDS_COMMIT.tar.gz")
extract "$t" "xds-$XDS_COMMIT/xds" "xds-$XDS_COMMIT/udpa"
cp -R "$CACHE/xds-$XDS_COMMIT/xds" "$VENDOR/xds"
cp -R "$CACHE/xds-$XDS_COMMIT/udpa" "$VENDOR/udpa"

t=$(fetch "googleapis-$GOOGLEAPIS_COMMIT.tar.gz" "https://github.com/googleapis/googleapis/archive/$GOOGLEAPIS_COMMIT.tar.gz")
extract "$t" "googleapis-$GOOGLEAPIS_COMMIT/google/api" "googleapis-$GOOGLEAPIS_COMMIT/google/rpc"
cp -R "$CACHE/googleapis-$GOOGLEAPIS_COMMIT/google/api" "$VENDOR/google/api"
cp -R "$CACHE/googleapis-$GOOGLEAPIS_COMMIT/google/rpc" "$VENDOR/google/rpc"

t=$(fetch "cel-spec-$CEL_SPEC_VERSION.tar.gz" "https://github.com/google/cel-spec/archive/v$CEL_SPEC_VERSION.tar.gz")
extract "$t" "cel-spec-$CEL_SPEC_VERSION/proto/cel"
cp -R "$CACHE/cel-spec-$CEL_SPEC_VERSION/proto/cel" "$VENDOR/cel"

t=$(fetch "otel-proto-$OTEL_PROTO_VERSION.tar.gz" "https://github.com/open-telemetry/opentelemetry-proto/archive/v$OTEL_PROTO_VERSION.tar.gz")
extract "$t" "opentelemetry-proto-$OTEL_PROTO_VERSION/opentelemetry"
cp -R "$CACHE/opentelemetry-proto-$OTEL_PROTO_VERSION/opentelemetry" "$VENDOR/opentelemetry"

t=$(fetch "client-model-$CLIENT_MODEL_VERSION.tar.gz" "https://github.com/prometheus/client_model/archive/v$CLIENT_MODEL_VERSION.tar.gz")
extract "$t" "client_model-$CLIENT_MODEL_VERSION/io"
cp -R "$CACHE/client_model-$CLIENT_MODEL_VERSION/io" "$VENDOR/io"

# Protos only — drop bazel build files that came along.
find "$VENDOR" \( -name 'BUILD' -o -name 'BUILD.bazel' -o -name '*.bzl' \) -delete

echo "Vendored into $VENDOR:"
du -sh "$VENDOR"
find "$VENDOR" -name '*.proto' | wc -l | xargs echo "proto files:"
