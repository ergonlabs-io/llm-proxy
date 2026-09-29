#!/usr/bin/env bash
set -euo pipefail

# Install a published llm-proxy release on macOS or Linux.
# Override LLM_PROXY_VERSION (for example, v0.2.0),
# LLM_PROXY_INSTALL_DIR, or LLM_PROXY_DOWNLOAD_URL when needed.

REPO="${LLM_PROXY_REPO:-ergonlabs-io/llm-proxy}"
INSTALL_DIR="${LLM_PROXY_INSTALL_DIR:-${HOME}/.local/bin}"

command -v curl >/dev/null 2>&1 || {
  echo "error: curl is required" >&2
  exit 1
}
command -v tar >/dev/null 2>&1 || {
  echo "error: tar is required" >&2
  exit 1
}

case "$(uname -s)" in
  Darwin) os="darwin" ;;
  Linux) os="linux" ;;
  *) echo "error: unsupported operating system: $(uname -s)" >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) echo "error: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

version="${LLM_PROXY_VERSION:-}"
if [[ -z "$version" ]]; then
  version="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -n 1)"
fi
[[ -n "$version" ]] || {
  echo "error: could not determine the latest release; set LLM_PROXY_VERSION" >&2
  exit 1
}

asset="llm-proxy-${os}-${arch}.tar.gz"
url="${LLM_PROXY_DOWNLOAD_URL:-https://github.com/${REPO}/releases/download/${version}/${asset}}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

echo "Downloading llm-proxy ${version} for ${os}/${arch}..."
curl -fL --retry 3 --retry-delay 1 "$url" -o "${tmp_dir}/${asset}"
tar -xzf "${tmp_dir}/${asset}" -C "$tmp_dir"

binary="${tmp_dir}/llm-proxy"
[[ -f "$binary" ]] || {
  echo "error: release archive does not contain llm-proxy" >&2
  exit 1
}

mkdir -p "$INSTALL_DIR"
install -m 0755 "$binary" "${INSTALL_DIR}/llm-proxy"
echo "Installed ${INSTALL_DIR}/llm-proxy"

case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *) echo "Add ${INSTALL_DIR} to PATH to run llm-proxy." ;;
esac
