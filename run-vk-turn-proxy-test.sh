#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# vk-turn-proxy one-shot test runner.
# Goal: clone repo, build server binary, add UDP redirect 30000-30200 -> 56000,
# detect Amnezia Docker UDP port, verify start, then run server in this terminal.
#
# Required:
#   WRAP_KEY="<64 hex wrap key>" bash run-vk-turn-proxy-test.sh
#
# Optional:
#   GH_TOKEN="<github token>"       # used only for clone auth, not saved into git remote URL
#   REPO_DIR="/tmp/vk-turn-proxy-test"
#   AMNEZIA_CONTAINER="amnezia-awg2"
#   AMNEZIA_PORT="48605"            # overrides Docker detection
#   LISTEN_PORT="56000"
#   REDIRECT_RANGE="30000:30200"
#   REPO_URL="https://github.com/Yellastro2/vk-turn-proxy.git"

REPO_URL="${REPO_URL:-https://github.com/Yellastro2/vk-turn-proxy.git}"
REPO_DIR="${REPO_DIR:-/tmp/vk-turn-proxy-test}"
AMNEZIA_CONTAINER="${AMNEZIA_CONTAINER:-amnezia-awg2}"
AMNEZIA_PORT="${AMNEZIA_PORT:-}"
LISTEN_PORT="${LISTEN_PORT:-56000}"
REDIRECT_RANGE="${REDIRECT_RANGE:-30000:30200}"
WRAP_KEY="${WRAP_KEY:-}"
GO_ROOT="/usr/local/go"
GO_BACKUP=""
ADDED_IPTABLES_RULE=0
INSTALLED_GO=0
CREATED_REPO_DIR=0
STARTED_TEST_PID=""

die() {
  echo "ERROR: $*" >&2
  exit 1
}

log() {
  echo "==> $*"
}

cleanup_test_pid() {
  if [[ -n "${STARTED_TEST_PID}" ]] && kill -0 "${STARTED_TEST_PID}" 2>/dev/null; then
    kill "${STARTED_TEST_PID}" 2>/dev/null || true
    wait "${STARTED_TEST_PID}" 2>/dev/null || true
  fi
}

rollback() {
  local code=$?
  if [[ "$code" -eq 0 ]]; then
    return 0
  fi

  echo
  echo "ROLLBACK: error detected, reverting changes..." >&2

  cleanup_test_pid

  if [[ "$ADDED_IPTABLES_RULE" -eq 1 ]]; then
    while iptables -t nat -C PREROUTING -p udp --dport "$REDIRECT_RANGE" -j REDIRECT --to-ports "$LISTEN_PORT" 2>/dev/null; do
      iptables -t nat -D PREROUTING -p udp --dport "$REDIRECT_RANGE" -j REDIRECT --to-ports "$LISTEN_PORT" || true
    done
    echo "ROLLBACK: removed iptables redirect $REDIRECT_RANGE -> $LISTEN_PORT" >&2
  fi

  if [[ "$CREATED_REPO_DIR" -eq 1 && -d "$REPO_DIR" ]]; then
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

  echo "ROLLBACK: done" >&2
  exit "$code"
}

trap rollback EXIT
trap 'die "interrupted"' INT TERM

require_root() {
  [[ "${EUID}" -eq 0 ]] || die "run as root, because iptables and /usr/local/go need root"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1. Install it first, then rerun. Example: apt update && apt install -y $1"
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
  # returns 0 if $1 < $2 for Go-like versions: 1.22.3, 1.23
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
  local stamp
  local goversion
  local archive

  stamp="$(date +%Y%m%d-%H%M%S)"
  goversion="$(fetch_stdout "https://go.dev/VERSION?m=text" | head -n1)"
  [[ "$goversion" =~ ^go[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || die "cannot detect latest Go version, got: $goversion"

  archive="/tmp/${goversion}.linux-amd64.tar.gz"

  log "installing official $goversion into $GO_ROOT"
  fetch_to_file "https://go.dev/dl/${goversion}.linux-amd64.tar.gz" "$archive"

  if [[ -d "$GO_ROOT" ]]; then
    GO_BACKUP="${GO_ROOT}.backup-vk-turn-${stamp}"
    mv "$GO_ROOT" "$GO_BACKUP"
    log "backed up existing $GO_ROOT to $GO_BACKUP"
  fi

  tar -C /usr/local -xzf "$archive"
  INSTALLED_GO=1
  export PATH="$GO_ROOT/bin:$PATH"
  go version
}

ensure_go_for_repo() {
  local required_go
  local current_go

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

clone_repo() {
  [[ -n "$WRAP_KEY" ]] || die "WRAP_KEY is empty. Run: WRAP_KEY='<64 hex>' bash $0"
  [[ "$WRAP_KEY" =~ ^[0-9a-fA-F]{64}$ ]] || die "WRAP_KEY must be exactly 64 hex chars"

  if [[ -e "$REPO_DIR" ]]; then
    die "REPO_DIR already exists: $REPO_DIR. Use another REPO_DIR or remove it manually."
  fi

  log "cloning $REPO_URL -> $REPO_DIR"

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

setup_iptables_redirect() {
  require_cmd iptables

  if iptables -t nat -C PREROUTING -p udp --dport "$REDIRECT_RANGE" -j REDIRECT --to-ports "$LISTEN_PORT" 2>/dev/null; then
    log "iptables redirect already exists: UDP $REDIRECT_RANGE -> $LISTEN_PORT"
  else
    log "adding iptables redirect: UDP $REDIRECT_RANGE -> $LISTEN_PORT"
    iptables -t nat -A PREROUTING -p udp --dport "$REDIRECT_RANGE" -j REDIRECT --to-ports "$LISTEN_PORT"
    ADDED_IPTABLES_RULE=1
  fi
}

build_server() {
  cd "$REPO_DIR"
  [[ -d server ]] || die "repo has no ./server directory"
  log "building ./server into ./vk-turn-server"
  go build -o vk-turn-server ./server
  [[ -x ./vk-turn-server ]] || die "build finished but ./vk-turn-server is not executable"
}

port_free_or_fail() {
  if ss -lunp | grep -E "[:.]${LISTEN_PORT}\b" >/dev/null 2>&1; then
    ss -lunp | grep -E "[:.]${LISTEN_PORT}\b" || true
    die "UDP port $LISTEN_PORT is already in use"
  fi
}

verify_server_start() {
  cd "$REPO_DIR"

  log "test-starting server once"
  ./vk-turn-server \
    -listen "0.0.0.0:${LISTEN_PORT}" \
    -connect "127.0.0.1:${AMNEZIA_PORT}" \
    -wrap-key "$WRAP_KEY" &
  STARTED_TEST_PID="$!"

  sleep 1

  if ! kill -0 "$STARTED_TEST_PID" 2>/dev/null; then
    wait "$STARTED_TEST_PID" || true
    STARTED_TEST_PID=""
    die "server exited during startup"
  fi

  if ! ss -lunp | grep -E "[:.]${LISTEN_PORT}\b" >/dev/null 2>&1; then
    ss -lunp | grep "$LISTEN_PORT" || true
    die "server process is alive but UDP $LISTEN_PORT is not visible"
  fi

  log "server startup verified on UDP $LISTEN_PORT"

  cleanup_test_pid
  STARTED_TEST_PID=""
}

run_server_foreground() {
  cd "$REPO_DIR"

  echo
  echo "OK: setup completed."
  echo "Running vk-turn-server in this terminal."
  echo "Press Ctrl+C to stop it."
  echo

  trap - EXIT
  exec ./vk-turn-server \
    -listen "0.0.0.0:${LISTEN_PORT}" \
    -connect "127.0.0.1:${AMNEZIA_PORT}" \
    -wrap-key "$WRAP_KEY"
}

main() {
  require_root

  require_cmd git
  require_cmd tar
  require_cmd sort
  require_cmd awk
  require_cmd sed
  require_cmd ss

  clone_repo
  ensure_go_for_repo
  detect_amnezia_port
  port_free_or_fail
  setup_iptables_redirect
  build_server
  verify_server_start
  run_server_foreground
}

main "$@"
