#!/bin/sh
# Install llm-proxy on macOS or Linux, run it as a service, and print the
# admin UI address:
#
#   curl -fsSL https://raw.githubusercontent.com/ergonlabs-io/llm-proxy/main/scripts/install.sh | sh
#
# POSIX sh, not bash: `curl | sh` runs dash on Debian and Ubuntu.
# Run with --help for options. Re-running upgrades the binary in place and
# keeps the existing configuration, secrets, and admin token.

# Everything lives in functions and runs from the last line, so a download
# cut off part way through executes nothing.

set -eu

REPO="${LLM_PROXY_REPO:-ergonlabs-io/llm-proxy}"
SERVICE_NAME="llm-proxy"
LAUNCHD_LABEL="io.ergonlabs.llm-proxy"

say() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
has() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat <<EOF
Install llm-proxy, start it as a service, and print the admin UI address.

Usage: install.sh [options]

Options:
  --version TAG     install this release (default: latest), e.g. v0.3.1
  --port N          proxy port for a new configuration (default: 53421)
  --admin-port N    admin and UI port for a new configuration (default: 53422)
  --admin-address HOST:PORT
                    admin and UI address for a new configuration, for example
                    0.0.0.0:53422 to reach the UI from other machines. The
                    admin API is plain HTTP: use this only on a network you
                    trust, because the admin token crosses it unencrypted.
  --no-start        install the binary and configuration only
  --no-service      start a background process instead of a service
  --uninstall       stop and remove the service and binary; keep data
  --purge           with --uninstall, also delete the data directory
  -h, --help        show this help

Environment:
  LLM_PROXY_VERSION, LLM_PROXY_INSTALL_DIR, LLM_PROXY_DATA_DIR,
  LLM_PROXY_DOWNLOAD_URL (tarball URL; <url>.sha256 is fetched beside it),
  LLM_PROXY_REPO (default: ergonlabs-io/llm-proxy)

Run as a normal user, the service is a launchd agent (macOS) or a systemd user
unit (Linux). Run as root on Linux, it is a system unit that runs as the
llm-proxy system user. Without systemd, it is a background process.
EOF
}

parse_args() {
  VERSION="${LLM_PROXY_VERSION:-}"
  PORT=""
  ADMIN_PORT=""
  ADMIN_ADDRESS=""
  START=true
  SERVICE=auto
  UNINSTALL=false
  PURGE=false
  while [ $# -gt 0 ]; do
    case "$1" in
      --version) [ $# -ge 2 ] || die "--version needs a value"; VERSION="$2"; shift ;;
      --version=*) VERSION="${1#*=}" ;;
      --port) [ $# -ge 2 ] || die "--port needs a value"; PORT="$2"; shift ;;
      --port=*) PORT="${1#*=}" ;;
      --admin-port) [ $# -ge 2 ] || die "--admin-port needs a value"; ADMIN_PORT="$2"; shift ;;
      --admin-port=*) ADMIN_PORT="${1#*=}" ;;
      --admin-address) [ $# -ge 2 ] || die "--admin-address needs a value"; ADMIN_ADDRESS="$2"; shift ;;
      --admin-address=*) ADMIN_ADDRESS="${1#*=}" ;;
      --no-start) START=false ;;
      --no-service) SERVICE=none ;;
      --uninstall) UNINSTALL=true ;;
      --purge) PURGE=true ;;
      # Accepted for compatibility with the previous installer, which only
      # started when asked. Starting is now the default.
      --init|--start) ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown option: $1 (see --help)" ;;
    esac
    shift
  done
  for p in "$PORT" "$ADMIN_PORT"; do
    case "$p" in
      "") ;;
      *[!0-9]*) die "port must be a number: $p" ;;
    esac
  done
  if [ -n "$ADMIN_ADDRESS" ]; then
    [ -z "$ADMIN_PORT" ] || die "use --admin-address or --admin-port, not both"
    case "${ADMIN_ADDRESS##*:}" in
      ""|*[!0-9]*) die "--admin-address must be HOST:PORT, for example 0.0.0.0:53422" ;;
    esac
    case "$ADMIN_ADDRESS" in
      *:*) ;;
      *) die "--admin-address must be HOST:PORT, for example 0.0.0.0:53422" ;;
    esac
    case "${ADMIN_ADDRESS%:*}" in
      ""|*[!0-9A-Za-z.:\[\]-]*) die "--admin-address must be HOST:PORT, for example 0.0.0.0:53422" ;;
    esac
  fi
  if [ "$PURGE" = true ] && [ "$UNINSTALL" = false ]; then
    die "--purge only applies with --uninstall"
  fi
}

detect_platform() {
  case "$(uname -s)" in
    Darwin) OS=darwin ;;
    Linux) OS=linux ;;
    *) die "unsupported operating system: $(uname -s)" ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    arm64|aarch64) ARCH=arm64 ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
  if [ "$OS" = darwin ] && [ "$ARCH" = amd64 ]; then
    # Rosetta reports x86_64 for a translated shell on Apple Silicon.
    if [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
      ARCH=arm64
    else
      die "Intel macOS has no prebuilt release; build from source with cargo"
    fi
  fi

  if [ "$(id -u)" -eq 0 ]; then
    [ "$OS" = linux ] || die "on macOS, run the installer as your own user, not root"
    SYSTEM_WIDE=true
    INSTALL_DIR="${LLM_PROXY_INSTALL_DIR:-/usr/local/bin}"
    DATA_DIR="${LLM_PROXY_DATA_DIR:-/var/lib/llm-proxy}"
  else
    SYSTEM_WIDE=false
    INSTALL_DIR="${LLM_PROXY_INSTALL_DIR:-${HOME}/.local/bin}"
    DATA_DIR="${LLM_PROXY_DATA_DIR:-${HOME}/.config/llm-proxy}"
  fi
  BIN="${INSTALL_DIR}/llm-proxy"
  UI_DIR="${DATA_DIR}/admin-ui-dist"
  RUNNER="${DATA_DIR}/run.sh"
  ENV_FILE="${DATA_DIR}/service.env"
  LOG_FILE="${DATA_DIR}/llm-proxy.log"
  PID_FILE="${DATA_DIR}/llm-proxy.pid"
  PLIST="${HOME}/Library/LaunchAgents/${LAUNCHD_LABEL}.plist"
  if [ "$SYSTEM_WIDE" = true ]; then
    UNIT="/etc/systemd/system/${SERVICE_NAME}.service"
    SYSTEMCTL="systemctl"
    JOURNAL="journalctl -u ${SERVICE_NAME}"
  else
    UNIT="${XDG_CONFIG_HOME:-${HOME}/.config}/systemd/user/${SERVICE_NAME}.service"
    SYSTEMCTL="systemctl --user"
    JOURNAL="journalctl --user -u ${SERVICE_NAME}"
  fi
}

# Picks how the proxy runs: launchd, systemd, or a plain background process.
detect_service_manager() {
  if [ "$SERVICE" = none ]; then
    MANAGER=none
  elif [ "$OS" = darwin ]; then
    MANAGER=launchd
  elif [ -d /run/systemd/system ] && has systemctl && $SYSTEMCTL show-environment >/dev/null 2>&1; then
    MANAGER=systemd
  else
    MANAGER=none
  fi
}

sha256_of() {
  if has sha256sum; then
    sha256sum "$1" | cut -d' ' -f1
  elif has shasum; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    die "sha256sum or shasum is required to verify the download"
  fi
}

resolve_version() {
  [ -n "${LLM_PROXY_DOWNLOAD_URL:-}" ] && return 0
  [ -n "$VERSION" ] && return 0
  VERSION="$(curl -fsSL --max-time 30 "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -n 1)" || true
  [ -n "$VERSION" ] || die "could not find the latest release of ${REPO}; set LLM_PROXY_VERSION"
}

download() {
  asset="llm-proxy-${OS}-${ARCH}.tar.gz"
  url="${LLM_PROXY_DOWNLOAD_URL:-https://github.com/${REPO}/releases/download/${VERSION}/${asset}}"
  say "Downloading llm-proxy ${VERSION:-from ${url}} for ${OS}/${ARCH}"
  curl -fsSL --retry 3 --retry-delay 1 --max-time 600 "$url" -o "${TMP}/${asset}" \
    || die "download failed: ${url}
  There may be no ${OS}/${ARCH} build in this release."
  curl -fsSL --retry 3 --retry-delay 1 --max-time 60 "${url}.sha256" -o "${TMP}/${asset}.sha256" \
    || die "checksum download failed: ${url}.sha256"
  expected="$(cut -d' ' -f1 <"${TMP}/${asset}.sha256")"
  actual="$(sha256_of "${TMP}/${asset}")"
  [ "$expected" = "$actual" ] || die "checksum mismatch for ${asset}: expected ${expected}, got ${actual}"

  mkdir "${TMP}/pkg"
  tar -xzf "${TMP}/${asset}" -C "${TMP}/pkg"
  [ -f "${TMP}/pkg/llm-proxy" ] || die "release archive does not contain llm-proxy"
  # Run it before installing it, so a binary this system cannot load (for
  # example, a too-old glibc) fails here and leaves any existing install alone.
  "${TMP}/pkg/llm-proxy" --version >/dev/null 2>"${TMP}/run-check" \
    || die "the downloaded binary does not run on this system:
$(cat "${TMP}/run-check")"
}

# Only a system unit drops privileges; a root background process (typically
# in a container) keeps running as root.
uses_system_user() {
  [ "$SYSTEM_WIDE" = true ] && [ "$MANAGER" = systemd ]
}

ensure_system_user() {
  uses_system_user || return 0
  id llm-proxy >/dev/null 2>&1 && return 0
  if has useradd; then
    useradd --system --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin llm-proxy
  elif has adduser; then
    adduser -S -H -h "$DATA_DIR" -s /sbin/nologin llm-proxy
  else
    die "cannot create the llm-proxy system user: useradd and adduser are missing"
  fi
}

install_files() {
  mkdir -p "$INSTALL_DIR" "$DATA_DIR"
  chmod 0700 "$DATA_DIR"
  # Copy then rename, so a running process keeps its old inode and a reader
  # never sees a half-written binary.
  cp "${TMP}/pkg/llm-proxy" "${BIN}.new"
  chmod 0755 "${BIN}.new"
  mv -f "${BIN}.new" "$BIN"
  if [ -f "${TMP}/pkg/llm-capture-agent" ]; then
    cp "${TMP}/pkg/llm-capture-agent" "${INSTALL_DIR}/llm-capture-agent.new"
    chmod 0755 "${INSTALL_DIR}/llm-capture-agent.new"
    mv -f "${INSTALL_DIR}/llm-capture-agent.new" "${INSTALL_DIR}/llm-capture-agent"
  fi
  if [ -d "${TMP}/pkg/admin-ui-dist" ]; then
    rm -rf "$UI_DIR"
    cp -R "${TMP}/pkg/admin-ui-dist" "$UI_DIR"
  fi
  say "Installed ${BIN} ($("$BIN" --version))"
}

# `llm-proxy init` writes the starter config and API key; it refuses to
# overwrite, so an existing install keeps its configuration on upgrade.
init_config() {
  CONFIG="${DATA_DIR}/llmproxy.yaml"
  INIT_OUTPUT=""
  if [ -f "$CONFIG" ]; then
    say "Keeping existing ${CONFIG}"
    [ -z "$PORT$ADMIN_PORT$ADMIN_ADDRESS" ] || warn "--port, --admin-port, and --admin-address apply only to a new configuration; edit ${CONFIG} instead"
  else
    INIT_OUTPUT="$("$BIN" init "$DATA_DIR")" || die "llm-proxy init failed"
    if [ -n "$PORT" ]; then
      sed "s/^listen: 0\.0\.0\.0:53421$/listen: 0.0.0.0:${PORT}/" "$CONFIG" >"${CONFIG}.tmp"
      mv -f "${CONFIG}.tmp" "$CONFIG"
    fi
    if [ -n "$ADMIN_PORT" ]; then
      ADMIN_ADDRESS="127.0.0.1:${ADMIN_PORT}"
    fi
    if [ -n "$ADMIN_ADDRESS" ]; then
      sed "s/^admin: 127\.0\.0\.1:53422$/admin: ${ADMIN_ADDRESS}/" "$CONFIG" >"${CONFIG}.tmp"
      mv -f "${CONFIG}.tmp" "$CONFIG"
    fi
  fi

  # Without LLMPROXY_ADMIN_TOKEN the admin API refuses every write, and the UI
  # cannot manage anything. Generate one per install and keep it.
  NEW_TOKEN=false
  if [ ! -f "$ENV_FILE" ]; then
    token="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
    [ "${#token}" -eq 64 ] || die "could not generate an admin token"
    (umask 077 && printf 'LLMPROXY_ADMIN_TOKEN=%s\n' "$token" >"$ENV_FILE")
    NEW_TOKEN=true
  fi
  chmod 0600 "$ENV_FILE"
  ADMIN_TOKEN="$(sed -n 's/^LLMPROXY_ADMIN_TOKEN=//p' "$ENV_FILE" | head -n 1)"

  # The starter config names its secret and access log relative to the
  # working directory, so every service manager runs the proxy from here.
  cat >"$RUNNER" <<EOF
#!/bin/sh
# Written by the llm-proxy installer. Every service manager starts the proxy
# through this file.
set -eu
cd '${DATA_DIR}'
set -a
. '${ENV_FILE}'
set +a
export LLMPROXY_ADMIN_UI_DIR='${UI_DIR}'
exec '${BIN}' --config '${CONFIG}'
EOF
  chmod 0700 "$RUNNER"

  if uses_system_user; then
    chown -R llm-proxy: "$DATA_DIR"
  fi

  (cd "$DATA_DIR" && "$BIN" --config "$CONFIG" --mode validate) >"${TMP}/validate" 2>&1 \
    || { cat "${TMP}/validate" >&2; die "${CONFIG} is not valid"; }

  ADMIN_ADDR="$(sed -n 's/^admin:[[:space:]]*\([^[:space:]#]*\).*/\1/p' "$CONFIG" | head -n 1)"
  LISTEN_ADDR="$(sed -n 's/^listen:[[:space:]]*\([^[:space:]#]*\).*/\1/p' "$CONFIG" | head -n 1)"

  # A wildcard bind is reachable on loopback; any other host must be dialled
  # as written.
  admin_host="${ADMIN_ADDR%:*}"
  ADMIN_PORT_BOUND="${ADMIN_ADDR##*:}"
  case "$admin_host" in
    0.0.0.0|"[::]"|"") PROBE_ADDR="127.0.0.1:${ADMIN_PORT_BOUND}"; ADMIN_LOOPBACK=false ;;
    127.*|localhost|"[::1]") PROBE_ADDR="$ADMIN_ADDR"; ADMIN_LOOPBACK=true ;;
    *) PROBE_ADDR="$ADMIN_ADDR"; ADMIN_LOOPBACK=false ;;
  esac
}

# First non-loopback IPv4 address, for printing a URL another machine can open.
host_ip() {
  ip=""
  if [ "$OS" = darwin ]; then
    for ifc in en0 en1 en2; do
      ip="$(ipconfig getifaddr "$ifc" 2>/dev/null || true)"
      [ -z "$ip" ] || break
    done
  elif has hostname; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')" || ip=""
  fi
  printf '%s' "${ip:-<this-host>}"
}

stop_background() {
  if [ -f "$PID_FILE" ]; then
    pid="$(cat "$PID_FILE")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      i=0
      while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 50 ]; do sleep 0.2; i=$((i + 1)); done
    fi
    rm -f "$PID_FILE"
  fi
}

stop_service() {
  if [ "$OS" = darwin ] && [ -f "$PLIST" ]; then
    launchctl bootout "gui/$(id -u)/${LAUNCHD_LABEL}" 2>/dev/null || true
    # bootout returns before the job is gone; bootstrapping the same label
    # too early fails with "Input/output error".
    i=0
    while launchctl print "gui/$(id -u)/${LAUNCHD_LABEL}" >/dev/null 2>&1 && [ "$i" -lt 50 ]; do
      sleep 0.2
      i=$((i + 1))
    done
  fi
  if [ "$OS" = linux ] && [ -f "$UNIT" ] && has systemctl; then
    $SYSTEMCTL disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
  fi
  stop_background
}

xml_escape() {
  printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

start_launchd() {
  mkdir -p "$(dirname "$PLIST")"
  cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array><string>/bin/sh</string><string>$(xml_escape "$RUNNER")</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>$(xml_escape "$LOG_FILE")</string>
  <key>StandardErrorPath</key><string>$(xml_escape "$LOG_FILE")</string>
</dict>
</plist>
EOF
  launchctl bootstrap "gui/$(id -u)" "$PLIST" || die "launchctl could not load ${PLIST}"
}

start_systemd() {
  mkdir -p "$(dirname "$UNIT")"
  if [ "$SYSTEM_WIDE" = true ]; then
    cat >"$UNIT" <<EOF
[Unit]
Description=llm-proxy
Documentation=https://github.com/${REPO}
Wants=network-online.target
After=network-online.target

[Service]
User=llm-proxy
Group=llm-proxy
ExecStart=/bin/sh ${RUNNER}
Restart=on-failure
RestartSec=2
LimitNOFILE=65536
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=yes
ReadWritePaths=${DATA_DIR}

[Install]
WantedBy=multi-user.target
EOF
  else
    cat >"$UNIT" <<EOF
[Unit]
Description=llm-proxy
Documentation=https://github.com/${REPO}

[Service]
ExecStart=/bin/sh ${RUNNER}
Restart=on-failure
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=default.target
EOF
  fi
  $SYSTEMCTL daemon-reload
  $SYSTEMCTL enable --now "$SERVICE_NAME" >/dev/null 2>&1 \
    || die "could not start ${SERVICE_NAME}; see: ${JOURNAL} -n 50"

  # A user unit stops at logout unless the account lingers. On a server
  # reached over SSH that is the common case.
  if [ "$SYSTEM_WIDE" = false ] && has loginctl; then
    if [ "$(loginctl show-user "$(id -un)" -p Linger --value 2>/dev/null)" != yes ]; then
      loginctl enable-linger "$(id -un)" 2>/dev/null \
        || warn "llm-proxy stops when you log out; to keep it running, run: sudo loginctl enable-linger $(id -un)"
    fi
  fi
}

start_background() {
  nohup /bin/sh "$RUNNER" >>"$LOG_FILE" 2>&1 </dev/null &
  echo $! >"$PID_FILE"
}

wait_ready() {
  i=0
  while [ "$i" -lt 60 ]; do
    if curl -fsS --max-time 2 "http://${PROBE_ADDR}/ready" >/dev/null 2>&1; then
      return 0
    fi
    if [ "$MANAGER" = none ] && ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
      break
    fi
    sleep 0.5
    i=$((i + 1))
  done
  warn "llm-proxy did not become ready on http://${ADMIN_ADDR}/ready"
  case "$MANAGER" in
    systemd) $JOURNAL -n 30 --no-pager >&2 2>/dev/null || true ;;
    *) [ -f "$LOG_FILE" ] && tail -n 30 "$LOG_FILE" >&2 ;;
  esac
  exit 1
}

start() {
  [ -n "$ADMIN_ADDR" ] || die "${CONFIG} has no admin address, so the admin UI is disabled; add 'admin: 127.0.0.1:53422'"
  stop_service
  # Something else answering here would make the readiness check below pass
  # against the wrong process.
  if curl -fsS --max-time 2 "http://${PROBE_ADDR}/ready" >/dev/null 2>&1; then
    die "another process already serves http://${ADMIN_ADDR}; stop it or choose another port with --admin-port"
  fi
  if [ "$MANAGER" = none ] && [ "$SERVICE" = auto ]; then
    warn "systemd is not available; llm-proxy runs as a background process and does not start at boot"
  fi
  case "$MANAGER" in
    launchd) start_launchd ;;
    systemd) start_systemd ;;
    none) start_background ;;
  esac
  wait_ready
}

print_summary() {
  ui_port="$ADMIN_PORT_BOUND"
  case "$ADMIN_ADDR" in
    0.0.0.0:*|"[::]":*) ui_host="$(host_ip)" ;;
    *) ui_host="${ADMIN_ADDR%:*}" ;;
  esac
  listen_port="${LISTEN_ADDR##*:}"
  say ""
  if [ "$START" = true ]; then
    say "llm-proxy is running."
    say ""
    say "  Admin UI:   http://${ui_host}:${ui_port}/ui/"
    say "  Proxy API:  http://127.0.0.1:${listen_port}/v1"
  else
    say "llm-proxy is installed but not started. Start it with:"
    say "  /bin/sh ${RUNNER}"
  fi
  say "  Config:     ${CONFIG}"
  if [ "$NEW_TOKEN" = true ]; then
    say ""
    say "Admin token (paste it into the admin UI to make changes):"
    say ""
    say "  ${ADMIN_TOKEN}"
  else
    say "  Admin token: in ${ENV_FILE}"
  fi
  if [ -n "$INIT_OUTPUT" ]; then
    key="$(printf '%s\n' "$INIT_OUTPUT" | sed -n '/^Key (shown once/,/^Run:/p' | sed -n 's/^  \([^[:space:]].*\)$/\1/p' | head -n 1)"
    if [ -n "$key" ]; then
      say ""
      say "API key for the proxy (shown once; store it now):"
      say ""
      say "  ${key}"
    fi
  fi
  say ""
  say "The starter config routes every model to Ollama at 127.0.0.1:11434."
  say "Edit ${CONFIG} to add providers, then restart:"
  case "$MANAGER" in
    launchd)
      say "  launchctl kickstart -k gui/$(id -u)/${LAUNCHD_LABEL}"
      say "Logs: ${LOG_FILE}" ;;
    systemd)
      say "  ${SYSTEMCTL} restart ${SERVICE_NAME}"
      say "Logs: ${JOURNAL} -f" ;;
    none)
      say "  re-run this installer"
      say "Logs: ${LOG_FILE}" ;;
  esac
  if [ "$ADMIN_LOOPBACK" = false ]; then
    # Said on every run, not only at first install: the exposure lasts as long
    # as the config does.
    say ""
    warn "the admin UI and API listen on ${ADMIN_ADDR} over plain HTTP. The admin token crosses the network unencrypted, and anyone who can reach the port can read /config_dump, /stats, and /clusters without it. Use this only on a network you trust, or put an HTTPS reverse proxy in front."
  elif [ -n "${SSH_CONNECTION:-}" ]; then
    say ""
    say "The admin UI listens on loopback only. From your workstation, run:"
    say "  ssh -L ${ui_port}:127.0.0.1:${ui_port} $(id -un)@<this-host>"
    say "and open http://127.0.0.1:${ui_port}/ui/"
    say "On a trusted network, set 'admin: 0.0.0.0:${ui_port}' in ${CONFIG} and restart to reach it directly."
  fi
  case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *) say ""; say "Add ${INSTALL_DIR} to PATH to run llm-proxy from a shell." ;;
  esac
}

uninstall() {
  stop_service
  rm -f "$PLIST" "$UNIT"
  if [ "$OS" = linux ] && has systemctl; then
    $SYSTEMCTL daemon-reload >/dev/null 2>&1 || true
  fi
  rm -f "$BIN" "${INSTALL_DIR}/llm-capture-agent"
  say "Removed the llm-proxy service and ${BIN}"
  if [ "$PURGE" = true ]; then
    rm -rf "$DATA_DIR"
    say "Deleted ${DATA_DIR}"
  else
    say "Kept ${DATA_DIR} (configuration, secrets, logs); re-run with --uninstall --purge to delete it"
  fi
}

main() {
  parse_args "$@"
  detect_platform
  detect_service_manager
  if [ "$UNINSTALL" = true ]; then
    uninstall
    return 0
  fi
  for tool in curl tar od sed; do
    has "$tool" || die "${tool} is required"
  done
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  trap 'exit 1' INT TERM

  resolve_version
  download
  ensure_system_user
  install_files
  init_config
  if [ "$START" = true ]; then
    start
  fi
  print_summary
}

main "$@"
