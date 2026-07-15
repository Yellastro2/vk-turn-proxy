#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# vk-turn-proxy systemd installer.
#
# Does:
#   - clone https://github.com/Yellastro2/vk-turn-proxy.git
#   - install official Go if missing/too old for go.mod
#   - build ./server into vk-turn-server
#   - detect Amnezia Docker UDP port
#   - create /etc/vk-turn-proxy.env
#   - create systemd service with Restart=always
#   - service auto-adds iptables redirect UDP 30000-30200 -> 56000 on start
#   - enable + start service
#
# Rollback:
#   - restores service/env/repo/Go changes made by this script
#   - DOES NOT remove iptables redirect rules
#
# Required:
#   WRAP_KEY="<64 hex wrap key>" bash install-vk-turn-proxy-service.sh
#
# Optional:
#   GH_TOKEN="<github token>"       # used only for clone auth, not saved into git remote URL
#   REPO_DIR="/opt/vk-turn-proxy"
#   AMNEZIA_CONTAINER="amnezia-awg2"
#   AMNEZIA_PORT="48605"            # overrides Docker detection
#   LISTEN_PORT="56000"
#   REDIRECT_RANGE="30000:30200"
#   SERVICE_NAME="vk-turn-proxy"
#   REPO_URL="https://github.com/Yellastro2/vk-turn-proxy.git"

REPO_URL="${REPO_URL:-https://github.com/Yellastro2/vk-turn-proxy.git}"
REPO_DIR="${REPO_DIR:-/opt/vk-turn-proxy}"
AMNEZIA_CONTAINER="${AMNEZIA_CONTAINER:-amnezia-awg2}"
AMNEZIA_PORT="${AMNEZIA_PORT:-}"
LISTEN_PORT="${LISTEN_PORT:-56000}"
REDIRECT_RANGE="${REDIRECT_RANGE:-30000:30200}"
SERVICE_NAME="${SERVICE_NAME:-vk-turn-proxy}"
WRAP_KEY="${WRAP_KEY:-}"

GO_ROOT="/usr/local/go"
GO_BACKUP=""
INSTALLED_GO=0

SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
ENV_FILE="/etc/${SERVICE_NAME}.env"

BACKUP_SUFFIX="$(date +%Y%m%d-%H%M%S)"
SERVICE_BACKUP=""
ENV_BACKUP=""
REPO_BACKUP=""

CREATED_REPO_DIR=0
CREATED_SERVICE=0
CREATED_ENV=0
SERVICE_WAS_ACTIVE=0
SERVICE_WAS_ENABLED=0
OLD_SERVICE_EXISTED=0
OLD_ENV_EXISTED=0

die() {
  echo "ERROR: $*" >&2
  exit 1
}

log() {
  echo "==> $*"
}

is_active() {
  systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null
}

is_enabled() {
  systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null
}

iptables_bin() {
  if command -v iptables >/dev/null 2>&1; then
    command -v iptables
  elif [[ -x /usr/sbin/iptables ]]; then
    echo /usr/sbin/iptables
  else
    return 1
  fi
}

rollback() {
  local code=$?
  if [[ "$code" -eq 0 ]]; then
    return 0
  fi

  echo
  echo "ROLLBACK: error detected, reverting file/service changes..." >&2
  echo "ROLLBACK: iptables rules are intentionally left untouched." >&2

  systemctl stop "$SERVICE_NAME" 2>/dev/null || true

  if [[ "$SERVICE_WAS_ENABLED" -eq 0 ]]; then
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
  fi

  if [[ "$CREATED_SERVICE" -eq 1 ]]; then
    rm -f "$SERVICE_FILE" || true
  fi

  if [[ -n "$SERVICE_BACKUP" && -f "$SERVICE_BACKUP" ]]; then
    mv "$SERVICE_BACKUP" "$SERVICE_FILE" || true
    echo "ROLLBACK: restored previous service file" >&2
  elif [[ "$OLD_SERVICE_EXISTED" -eq 0 ]]; then
    rm -f "$SERVICE_FILE" || true
  fi

  if [[ "$CREATED_ENV" -eq 1 ]]; then
    rm -f "$ENV_FILE" || true
  fi

  if [[ -n "$ENV_BACKUP" && -f "$ENV_BACKUP" ]]; then
    mv "$ENV_BACKUP" "$ENV_FILE" || true
    chmod 600 "$ENV_FILE" || true
    echo "ROLLBACK: restored previous env file" >&2
  elif [[ "$OLD_ENV_EXISTED" -eq 0 ]]; then
    rm -f "$ENV_FILE" || true
  fi

  if [[ -n "$REPO_BACKUP" && -d "$REPO_BACKUP" ]]; then
    rm -rf "$REPO_DIR" || true
    mv "$REPO_BACKUP" "$REPO_DIR" || true
    echo "ROLLBACK: restored previous repo dir" >&2
  elif [[ "$CREATED_REPO_DIR" -eq 1 && -d "$REPO_DIR" ]]; then
    rm -rf "$REPO_DIR" || true
    echo "ROLLBACK: removed repo dir $REPO_DIR" >&2
  fi

  if [[ "$INSTALLED_GO" -eq 1 ]]; then
    rm -rf "$GO_ROOT" || true
    if [[ -n "$GO_BACKUP" && -d "$GO_BACKUP" ]]; then
      mv "$GO_BACKUP" "$GO_ROOT" || true
      echo "ROLLBACK: restored previous Go from $GO_BACKUP" >&2
    else
      echo "ROLLBACK: removed installed Go from $GO_ROOT" >&2
    fi
  elif [[ -n "$GO_BACKUP" && -d "$GO_BACKUP" ]]; then
    rm -rf "$GO_ROOT" || true
    mv "$GO_BACKUP" "$GO_ROOT" || true
    echo "ROLLBACK: restored previous Go from $GO_BACKUP" >&2
  fi

  systemctl daemon-reload 2>/dev/null || true

  if [[ "$SERVICE_WAS_ENABLED" -eq 1 ]]; then
    systemctl enable "$SERVICE_NAME" 2>/dev/null || true
  fi
  if [[ "$SERVICE_WAS_ACTIVE" -eq 1 ]]; then
    systemctl start "$SERVICE_NAME" 2>/dev/null || true
  fi

  echo "ROLLBACK: done" >&2
  exit "$code"
}

trap rollback EXIT
trap 'die "interrupted"' INT TERM

require_root() {
  [[ "${EUID}" -eq 0 ]] || die "run as root"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

fetch_to_file() {
  local url="$1"
  local out="$2"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$out"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
  else
    die "missing curl or wget"
  fi
}

fetch_stdout() {
  local url="$1"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "$url"
  else
    die "missing curl or wget"
  fi
}

version_lt() {
  local a="${1#go}"
  local b="${2#go}"
  local smallest
  smallest="$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n1)"
  [[ "$smallest" == "$a" && "$a" != "$b" ]]
}

go_current_version() {
  if command -v go >/dev/null 2>&1; then
    go version | awk '{print $3}' | sed 's/^go//'
  fi
}

install_official_go() {
  local goversion archive
  goversion="$(fetch_stdout "https://go.dev/VERSION?m=text" | head -n1)"
  [[ "$goversion" =~ ^go[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || die "cannot detect latest Go version, got: $goversion"

  archive="/tmp/${goversion}.linux-amd64.tar.gz"

  log "installing official $goversion into $GO_ROOT"
  fetch_to_file "https://go.dev/dl/${goversion}.linux-amd64.tar.gz" "$archive"

  if [[ -d "$GO_ROOT" ]]; then
    GO_BACKUP="${GO_ROOT}.backup-${SERVICE_NAME}-${BACKUP_SUFFIX}"
    mv "$GO_ROOT" "$GO_BACKUP"
    log "backed up existing $GO_ROOT to $GO_BACKUP"
  fi

  tar -C /usr/local -xzf "$archive"
  INSTALLED_GO=1
  export PATH="$GO_ROOT/bin:$PATH"
  go version
}

ensure_go_for_repo() {
  local required_go current_go

  required_go="$(awk '/^go / {print $2; exit}' "$REPO_DIR/go.mod" || true)"
  [[ -n "$required_go" ]] || required_go="1.22"

  current_go="$(go_current_version || true)"

  if [[ -z "$current_go" ]]; then
    install_official_go
    return
  fi

  log "found Go $current_go"
  if version_lt "$current_go" "$required_go"; then
    log "Go $current_go is older than go.mod requirement $required_go"
    install_official_go
  else
    export PATH="$GO_ROOT/bin:$PATH"
  fi
}

validate_inputs() {
  [[ -n "$WRAP_KEY" ]] || die "WRAP_KEY is empty. Run: WRAP_KEY='<64 hex>' bash $0"
  [[ "$WRAP_KEY" =~ ^[0-9a-fA-F]{64}$ ]] || die "WRAP_KEY must be exactly 64 hex chars"
  [[ "$LISTEN_PORT" =~ ^[0-9]+$ ]] || die "LISTEN_PORT must be numeric"
  [[ "$REDIRECT_RANGE" =~ ^[0-9]+:[0-9]+$ ]] || die "REDIRECT_RANGE must look like 30000:30200"
}

clone_or_update_repo() {
  if [[ -d "$REPO_DIR" ]]; then
    if [[ ! -d "$REPO_DIR/.git" ]]; then
      die "REPO_DIR exists but is not a git repo: $REPO_DIR"
    fi

    REPO_BACKUP="${REPO_DIR}.backup-${SERVICE_NAME}-${BACKUP_SUFFIX}"
    log "backing up existing repo dir to $REPO_BACKUP"
    cp -a "$REPO_DIR" "$REPO_BACKUP"

    log "updating existing repo in $REPO_DIR"
    cd "$REPO_DIR"
    git remote set-url origin "$REPO_URL" || true
    git fetch origin
    local branch
    branch="$(git symbolic-ref --short refs/remotes/origin/HEAD 2>/dev/null | sed 's#^origin/##' || true)"
    [[ -n "$branch" ]] || branch="main"
    git checkout "$branch" || git checkout -B "$branch" "origin/$branch"
    git reset --hard "origin/$branch"
    git clean -fd
    return
  fi

  log "cloning $REPO_URL -> $REPO_DIR"
  mkdir -p "$(dirname "$REPO_DIR")"

  if [[ -n "${GH_TOKEN:-}" ]]; then
    local askpass
    askpass="$(mktemp)"
    chmod 700 "$askpass"
    cat > "$askpass" <<'EOF'
#!/usr/bin/env sh
case "$1" in
  *Username*) printf '%s\n' 'x-access-token' ;;
  *Password*) printf '%s\n' "$GH_TOKEN" ;;
  *) printf '\n' ;;
esac
EOF
    GIT_ASKPASS="$askpass" GIT_TERMINAL_PROMPT=0 git clone "$REPO_URL" "$REPO_DIR"
    rm -f "$askpass"
  else
    git clone "$REPO_URL" "$REPO_DIR"
  fi

  CREATED_REPO_DIR=1
  cd "$REPO_DIR"
  git remote set-url origin "$REPO_URL" || true
}

detect_amnezia_port() {
  if [[ -n "$AMNEZIA_PORT" ]]; then
    log "using AMNEZIA_PORT=$AMNEZIA_PORT from env"
    return
  fi

  require_cmd docker

  local ports
  ports="$(docker ps --filter "name=^/${AMNEZIA_CONTAINER}$" --format "{{.Ports}}" || true)"
  [[ -n "$ports" ]] || die "docker container not found/running: $AMNEZIA_CONTAINER. Or set AMNEZIA_PORT manually."

  AMNEZIA_PORT="$(printf '%s\n' "$ports" | sed -nE 's/.*0\.0\.0\.0:([0-9]+)->[0-9]+\/udp.*/\1/p' | head -n1)"
  [[ -n "$AMNEZIA_PORT" ]] || AMNEZIA_PORT="$(printf '%s\n' "$ports" | sed -nE 's/.*\[::\]:([0-9]+)->[0-9]+\/udp.*/\1/p' | head -n1)"
  [[ -n "$AMNEZIA_PORT" ]] || die "cannot parse UDP port from Docker ports: $ports. Set AMNEZIA_PORT manually."

  log "detected Amnezia host UDP port: $AMNEZIA_PORT"
}

build_server() {
  cd "$REPO_DIR"
  [[ -d server ]] || die "repo has no ./server directory"
  log "building ./server into ./vk-turn-server"
  go build -o vk-turn-server ./server
  [[ -x ./vk-turn-server ]] || die "build finished but ./vk-turn-server is not executable"
}

backup_current_systemd_files() {
  if is_active; then
    SERVICE_WAS_ACTIVE=1
  fi
  if is_enabled; then
    SERVICE_WAS_ENABLED=1
  fi

  if [[ -f "$SERVICE_FILE" ]]; then
    OLD_SERVICE_EXISTED=1
    SERVICE_BACKUP="${SERVICE_FILE}.backup-${BACKUP_SUFFIX}"
    cp -a "$SERVICE_FILE" "$SERVICE_BACKUP"
    log "backed up existing service file to $SERVICE_BACKUP"
  fi

  if [[ -f "$ENV_FILE" ]]; then
    OLD_ENV_EXISTED=1
    ENV_BACKUP="${ENV_FILE}.backup-${BACKUP_SUFFIX}"
    cp -a "$ENV_FILE" "$ENV_BACKUP"
    log "backed up existing env file to $ENV_BACKUP"
  fi
}

write_env_file() {
  log "writing $ENV_FILE"
  cat > "$ENV_FILE" <<EOF
LISTEN_PORT=${LISTEN_PORT}
AMNEZIA_PORT=${AMNEZIA_PORT}
WRAP_KEY=${WRAP_KEY}
REDIRECT_RANGE=${REDIRECT_RANGE}
EOF
  chmod 600 "$ENV_FILE"
  CREATED_ENV=1
}

write_service_file() {
  local ipt
  ipt="$(iptables_bin)" || die "missing iptables"

  log "writing $SERVICE_FILE"

  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=VK TURN Proxy server
Wants=network-online.target docker.service
After=network-online.target docker.service

[Service]
Type=simple
WorkingDirectory=${REPO_DIR}
EnvironmentFile=${ENV_FILE}
ExecStartPre=/bin/sh -c '${ipt} -t nat -C PREROUTING -p udp --dport "\${REDIRECT_RANGE}" -j REDIRECT --to-ports "\${LISTEN_PORT}" 2>/dev/null || ${ipt} -t nat -A PREROUTING -p udp --dport "\${REDIRECT_RANGE}" -j REDIRECT --to-ports "\${LISTEN_PORT}"'
ExecStart=${REPO_DIR}/vk-turn-server -listen 0.0.0.0:\${LISTEN_PORT} -connect 127.0.0.1:\${AMNEZIA_PORT} -wrap-key \${WRAP_KEY}
Restart=always
RestartSec=3
KillSignal=SIGTERM
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
EOF

  chmod 644 "$SERVICE_FILE"
  CREATED_SERVICE=1
  systemctl daemon-reload
}

start_and_verify_service() {
  log "enabling and starting ${SERVICE_NAME}.service"
  systemctl enable "$SERVICE_NAME"
  systemctl restart "$SERVICE_NAME"

  sleep 2

  if ! is_active; then
    systemctl status "$SERVICE_NAME" --no-pager || true
    journalctl -u "$SERVICE_NAME" -n 80 --no-pager || true
    die "service failed to start"
  fi

  if ! ss -lunp | grep -E "[:.]${LISTEN_PORT}\b" >/dev/null 2>&1; then
    ss -lunp | grep "$LISTEN_PORT" || true
    systemctl status "$SERVICE_NAME" --no-pager || true
    journalctl -u "$SERVICE_NAME" -n 80 --no-pager || true
    die "service is active but UDP $LISTEN_PORT is not visible"
  fi

  echo
  echo "OK: ${SERVICE_NAME}.service is active and listens on UDP ${LISTEN_PORT}"
  echo
  systemctl status "$SERVICE_NAME" --no-pager --lines=20
  echo
  echo "Logs:"
  echo "  journalctl -u ${SERVICE_NAME} -f"
  echo
  echo "Restart:"
  echo "  systemctl restart ${SERVICE_NAME}"
  echo
  echo "Stop:"
  echo "  systemctl stop ${SERVICE_NAME}"
}

main() {
  require_root
  validate_inputs

  require_cmd git
  require_cmd tar
  require_cmd sort
  require_cmd awk
  require_cmd sed
  require_cmd ss
  require_cmd systemctl

  clone_or_update_repo
  ensure_go_for_repo
  detect_amnezia_port
  build_server
  backup_current_systemd_files
  write_env_file
  write_service_file
  start_and_verify_service

  trap - EXIT
}

main "$@"
