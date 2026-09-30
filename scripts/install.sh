#!/usr/bin/env bash
set -euo pipefail

# Install a published llm-proxy release on macOS or Linux.
# Override LLM_PROXY_VERSION (for example, v0.2.0),
# LLM_PROXY_INSTALL_DIR, or LLM_PROXY_DOWNLOAD_URL when needed.

REPO="${LLM_PROXY_REPO:-ergonlabs-io/llm-proxy}"
INSTALL_DIR="${LLM_PROXY_INSTALL_DIR:-${HOME}/.local/bin}"
DATA_DIR="${LLM_PROXY_DATA_DIR:-${HOME}/.config/llm-proxy}"
INIT=false
START=false

for arg in "$@"; do
  case "$arg" in
    --init) INIT=true ;;
    --start) INIT=true; START=true ;;
    --help|-h)
      echo "Usage: install.sh [--init] [--start]"
      echo "  --init   create the starter config under ${DATA_DIR}"
      echo "  --start  initialize if needed and start on ports 53421/53422"
      exit 0
      ;;
    *) echo "error: unknown option: $arg" >&2; exit 1 ;;
  esac
done

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
  x86_64|amd64)
    if [[ "$os" == "darwin" ]]; then
      echo "error: Intel macOS is not supported; use an Apple Silicon Mac" >&2
      exit 1
    fi
    arch="amd64"
    ;;
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

ui_dir="${DATA_DIR}/admin-ui-dist"
if [[ -d "${tmp_dir}/admin-ui-dist" ]]; then
  mkdir -p "$DATA_DIR"
  rm -rf "$ui_dir"
  cp -R "${tmp_dir}/admin-ui-dist" "$ui_dir"
fi

if [[ "$INIT" == true ]]; then
  mkdir -p "$DATA_DIR"
  if [[ ! -f "$DATA_DIR/llmproxy.yaml" ]]; then
    (cd "$DATA_DIR" && "${INSTALL_DIR}/llm-proxy" init .)
  else
    echo "Using existing ${DATA_DIR}/llmproxy.yaml"
  fi
fi

if [[ "$START" == true ]]; then
  [[ -f "$DATA_DIR/llmproxy.yaml" ]] || {
    echo "error: ${DATA_DIR}/llmproxy.yaml is missing; rerun with --init" >&2
    exit 1
  }
  log_file="${DATA_DIR}/llm-proxy.log"
  pid_file="${DATA_DIR}/llm-proxy.pid"
  if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
    echo "llm-proxy is already running (PID $(cat "$pid_file"))"
  else
    nohup env LLMPROXY_ADMIN_UI_DIR="$ui_dir" \
      "${INSTALL_DIR}/llm-proxy" --config "$DATA_DIR/llmproxy.yaml" \
      >"$log_file" 2>&1 < /dev/null &
    echo $! > "$pid_file"
    echo "Started llm-proxy (proxy: http://127.0.0.1:53421, admin UI: http://127.0.0.1:53422/ui/)"
  fi
fi

case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *) echo "Add ${INSTALL_DIR} to PATH to run llm-proxy." ;;
esac
