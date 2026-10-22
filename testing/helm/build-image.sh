#!/usr/bin/env bash
# Builds a local llm-proxy container image for the chart test, from the same
# Dockerfile the release workflow uses (deploy/container/Dockerfile).
#
# The release workflow copies the release binary into the image. On a laptop
# there is no Linux release binary, so this script first compiles one inside a
# rust container for the Docker host's architecture. It also builds
# mock-upstream, the provider the chart test runs in the cluster.
#
# Usage: testing/helm/build-image.sh [image-tag]
# Env:   LLMPROXY_HELM_CARGO_VOLUME  named volume for the Linux target/ dir
#                                    (default llm-proxy-helm-e2e-target)
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
tag="${1:-llm-proxy:helm-e2e}"
mock_tag="${MOCK_IMAGE:-llm-proxy-mock-upstream:helm-e2e}"
volume="${LLMPROXY_HELM_CARGO_VOLUME:-llm-proxy-helm-e2e-target}"
arch="$(docker version --format '{{.Server.Arch}}')"
case "$arch" in
  amd64 | arm64) ;;
  aarch64) arch=arm64 ;;
  x86_64) arch=amd64 ;;
  *) echo "unsupported docker host architecture: $arch" >&2; exit 1 ;;
esac

# A named volume keeps the Linux target/ dir out of the source tree and apart
# from the host build, and makes a second run incremental.
echo "==> compiling linux/$arch binaries (cargo, release profile)"
docker run --rm \
  -v "$repo:/src:ro" \
  -v "$volume:/work" \
  -e CARGO_TARGET_DIR=/work/target \
  -e CARGO_HOME=/work/cargo-home \
  -e RUSTUP_HOME=/work/rustup-home \
  -w /src \
  rust:1.99 \
  sh -c '
    set -e
    command -v protoc >/dev/null || { apt-get update -qq && apt-get install -y -qq protobuf-compiler >/dev/null; }
    rustup show active-toolchain >/dev/null 2>&1 || rustup toolchain install 1.99.0 --profile minimal
    cargo build --locked --release -p proxy -p mockupstream
  '

stage="$(mktemp -d)"
trap 'command rm -rf "$stage"' EXIT
mkdir -p "$stage/dist/linux-$arch/admin-ui-dist"
# Copy out of the volume through a throwaway container.
docker run --rm -v "$volume:/work:ro" -v "$stage:/out" alpine:3 \
  sh -c "cp /work/target/release/llm-proxy /out/dist/linux-$arch/llm-proxy && cp /work/target/release/mock-upstream /out/mock-upstream"
# The UI bundle is optional here: without it the admin server logs that /ui is
# not loaded and serves the API. Use a local build when one exists.
if [ -d "$repo/admin-ui/dist" ]; then
  cp -R "$repo/admin-ui/dist/." "$stage/dist/linux-$arch/admin-ui-dist/"
fi

echo "==> building $tag"
docker build --platform "linux/$arch" -f "$repo/deploy/container/Dockerfile" -t "$tag" "$stage"

echo "==> building $mock_tag"
cat >"$stage/Dockerfile.mock" <<'EOF'
FROM gcr.io/distroless/cc-debian13:nonroot
COPY --chmod=0755 mock-upstream /usr/local/bin/mock-upstream
ENTRYPOINT ["/usr/local/bin/mock-upstream"]
EOF
docker build --platform "linux/$arch" -f "$stage/Dockerfile.mock" -t "$mock_tag" "$stage"
