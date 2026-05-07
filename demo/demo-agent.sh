#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
STATE_ROOT="${AGENT_GATEWAY_DEMO_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/agent-gateway/demo-agents}"
DEFAULT_VALID_DAYS="${AGENT_GATEWAY_PERMISSION_VALID_DAYS:-30}"
DEFAULT_GATEWAY="${AGENT_GATEWAY_DEMO_GATEWAY:-127.0.0.1:8443}"
DEFAULT_GATEWAY_CA="${AGENT_GATEWAY_DEMO_GATEWAY_CA:-$REPO_ROOT/certs/server-ca.pem}"
DEFAULT_MOCK_CA="${AGENT_GATEWAY_DEMO_MOCK_CA:-$REPO_ROOT/certs/mock-ca.pem}"
DEFAULT_SIDECAR_BIN="${AGENT_GATEWAY_DEMO_SIDECAR_BIN:-}"
DEFAULT_LISTEN_HOST="${AGENT_GATEWAY_DEMO_LISTEN_HOST:-127.0.0.1}"
DEFAULT_LISTEN_PORT="${AGENT_GATEWAY_DEMO_LISTEN_PORT:-3128}"
DEFAULT_SWTPM_PORT="${AGENT_GATEWAY_DEMO_SWTPM_PORT:-2321}"
DEFAULT_TPM_HANDLE="${AGENT_GATEWAY_DEMO_TPM_HANDLE:-0x81010004}"
SWTPM_HOST="127.0.0.1"
TPM2_PKCS11_STORE="${TPM2_PKCS11_STORE:-$HOME/.tpm2_pkcs11}"
TOKEN_LABEL="${AGENT_GATEWAY_TPM_TOKEN_LABEL:-agent-gateway}"
USER_PIN="${AGENT_GATEWAY_TPM_USER_PIN:-}"
export TPM2_PKCS11_STORE

usage() {
  cat >&2 <<'EOF'
Usage:
  demo-agent.sh create --identity AGENT_ID [--handle AGENT_HANDLE] --grant DESTINATION [--grant DESTINATION ...]
  demo-agent.sh grant AGENT_HANDLE --grant DESTINATION [--grant DESTINATION ...]
  demo-agent.sh prompt AGENT_HANDLE --prompt TEXT
  demo-agent.sh delete AGENT_HANDLE

Environment:
  AGENT_GATEWAY_DATABASE_URL or DATABASE_URL is required for create, grant, and delete.
  AGENT_GATEWAY_DEMO_GATEWAY defaults to 127.0.0.1:8443.
  AGENT_GATEWAY_DEMO_GATEWAY_CA defaults to certs/server-ca.pem.
  AGENT_GATEWAY_DEMO_MOCK_CA defaults to certs/mock-ca.pem for Claude HTTPS requests.
  AGENT_GATEWAY_DEMO_SIDECAR_BIN can pin the sidecar binary.
  AGENT_GATEWAY_DEMO_STATE_DIR overrides the local agent handle directory.
  AGENT_GATEWAY_DEMO_SWTPM_PORT defaults to 2321.
  AGENT_GATEWAY_DEMO_TPM_HANDLE defaults to 0x81010004.
  AGENT_GATEWAY_PERMISSION_VALID_DAYS defaults to 30.
  TPM2_PKCS11_STORE defaults to $HOME/.tpm2_pkcs11.
  AGENT_GATEWAY_TPM_TOKEN_LABEL defaults to agent-gateway.
  AGENT_GATEWAY_TPM_USER_PIN avoids the PIN prompt.
EOF
}

need_arg() { [[ $# -ge 2 ]] || { echo "error: $1 requires a value" >&2; exit 2; }; }

log() {
  echo "==> $*" >&2
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: required command not found: $1" >&2
    exit 1
  }
}

sanitize_handle() {
  printf '%s' "$1" | tr -cs 'A-Za-z0-9_.-' '-'
}

state_dir() {
  printf '%s/%s\n' "$STATE_ROOT" "$1"
}

prompt_secret() {
  local prompt="$1"
  local value
  read -r -s -p "$prompt" value
  echo >&2
  printf '%s\n' "$value"
}

discover_pkcs11_module() {
  if [[ -n "${TPM2_PKCS11_MODULE:-}" ]]; then
    printf '%s\n' "$TPM2_PKCS11_MODULE"
    return
  fi

  local candidate
  for candidate in \
    /usr/lib/libtpm2_pkcs11.so.0 \
    /usr/lib/libtpm2_pkcs11.so \
    /usr/lib/*/libtpm2_pkcs11.so.0 \
    /usr/lib/*/libtpm2_pkcs11.so \
    /usr/lib/*/pkcs11/libtpm2_pkcs11.so \
    /usr/local/lib/pkcs11/libtpm2_pkcs11.so \
    /usr/local/lib/libtpm2_pkcs11.so; do
    if [[ -e "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done

  echo "Set TPM2_PKCS11_MODULE to the path of libtpm2_pkcs11.so" >&2
  exit 2
}

run_pkcs11_tool() {
  pkcs11-tool "$@" 2> >(
    grep -v \
      -e '^WARNING:fapi:' \
      -e '^ERROR:fapi:.*Fapi_List' \
      -e '^ERROR:fapi:.*Entities_List' \
      -e '^WARNING: Listing FAPI token objects failed:' \
      -e '^Please see https://github.com/tpm2-software/tpm2-pkcs11/blob/.*/docs/FAPI.md' \
      -e '^WARNING: Getting tokens from fapi backend failed\.' >&2
  )
}

discover_principal() {
  command -v pkcs11-tool >/dev/null || { echo "pkcs11-tool is required" >&2; exit 1; }
  local module labels count
  module="$(discover_pkcs11_module)"
  if [[ -z "$USER_PIN" ]]; then
    USER_PIN="$(prompt_secret "TPM token user PIN: ")"
    export AGENT_GATEWAY_TPM_USER_PIN="$USER_PIN"
  fi
  labels="$(
    run_pkcs11_tool --module "$module" --token-label "$TOKEN_LABEL" --login --pin "$USER_PIN" --list-objects \
      | awk '
        /Private Key Object/ { in_private = 1; next }
        /Public Key Object/ { in_private = 0; next }
        in_private && /^[[:space:]]*label:/ {
          sub(/^[[:space:]]*label:[[:space:]]*/, "")
          if ($0 != "") print
        }
      ' \
      | sort -u
  )"
  count="$(printf '%s\n' "$labels" | sed '/^$/d' | wc -l | tr -d ' ')"
  if [[ "$count" -ne 1 ]]; then
    echo "expected exactly one TPM principal key label in token '$TOKEN_LABEL', found $count" >&2
    echo "hint: run ./registry-cli/register-principal-key.sh KEY_ID first on this machine" >&2
    [[ -n "$labels" ]] && printf '%s\n' "$labels" >&2
    exit 1
  fi
  printf '%s\n' "$labels"
}

read_state() {
  local dir="$1"
  [[ -d "$dir" ]] || { echo "error: unknown agent handle: ${dir##*/}" >&2; exit 1; }
  PRINCIPAL="$(<"$dir/principal")"
  IDENTITY="$(<"$dir/identity")"
  VALID_DAYS="$(<"$dir/valid_days")"
  GATEWAY="$(<"$dir/gateway")"
  GATEWAY_CA="$(<"$dir/gateway_ca")"
  LISTEN="$(<"$dir/listen")"
  SWTPM_PORT="$(<"$dir/swtpm_port")"
  TPM_HANDLE="$(<"$dir/tpm_handle")"
  SUBJECT_PUBLIC_KEY_SPKI_DER="$dir/client/machine-client-spki.der"
}

write_state() {
  local dir="$1"
  mkdir -p "$dir/work"
  printf '%s\n' "$PRINCIPAL" > "$dir/principal"
  printf '%s\n' "$IDENTITY" > "$dir/identity"
  printf '%s\n' "$VALID_DAYS" > "$dir/valid_days"
  printf '%s\n' "$GATEWAY" > "$dir/gateway"
  printf '%s\n' "$GATEWAY_CA" > "$dir/gateway_ca"
  printf '%s\n' "$LISTEN" > "$dir/listen"
  printf '%s\n' "$SWTPM_PORT" > "$dir/swtpm_port"
  printf '%s\n' "$TPM_HANDLE" > "$dir/tpm_handle"
}

tpm2() {
  TPM2TOOLS_TCTI="$TPM_TCTI" "$@"
}

set_runtime_paths() {
  local dir="$1"
  CERT_DIR="$dir/client"
  SWTPM_DIR="$CERT_DIR/swtpm"
  SWTPM_CTRL_PORT=$((SWTPM_PORT + 1))
  TPM_TCTI="swtpm:host=$SWTPM_HOST,port=$SWTPM_PORT"
}

der_utf8string() {
  local val="$1"
  local len=${#val}
  local result
  result=$(printf '0c:%02x' "$len")
  for ((i = 0; i < len; i++)); do
    result=$(printf '%s:%02x' "$result" "'${val:$i:1}")
  done
  printf '%s' "$result"
}

generate_certs() {
  if [[ ! -f "$CERT_DIR/machine-client-cert-signer-key.pem" ]]; then
    log "Generating local certificate signer key"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -keyout "$CERT_DIR/machine-client-cert-signer-key.pem" \
      -out "$CERT_DIR/machine-client-cert-signer.pem" \
      -days 365 -nodes -subj "/CN=agent-gateway local cert signer" 2>/dev/null
  fi

  log "Preparing subject client certificate for simulated TPM key (identity=$IDENTITY)"
  local der_hex extfile
  der_hex="$(der_utf8string "$IDENTITY")"
  extfile="$CERT_DIR/machine-client.ext"
  {
    printf 'keyUsage=digitalSignature\n'
    printf 'extendedKeyUsage=clientAuth\n'
    printf '1.3.6.1.4.1.57264.1.1=DER:%s\n' "$der_hex"
  } > "$extfile"
  openssl x509 -new -force_pubkey "$CERT_DIR/machine-client-public.pem" \
    -subj "/CN=machine-client" \
    -key "$CERT_DIR/machine-client-cert-signer-key.pem" \
    -out "$CERT_DIR/machine-client.pem" -days 365 -extfile "$extfile" 2>/dev/null
  rm -f "$extfile"
}

port_open() {
  (echo > "/dev/tcp/$1/$2") >/dev/null 2>&1
}

parse_listen_addr() {
  local addr="$1"
  if [[ "$addr" == \[* ]]; then
    LISTEN_HOST="${addr%%\]:*}"
    LISTEN_HOST="${LISTEN_HOST#\[}"
    LISTEN_PORT="${addr##*\]:}"
  else
    LISTEN_HOST="${addr%:*}"
    LISTEN_PORT="${addr##*:}"
  fi
}

process_matches() {
  local pid="$1"
  local pattern="$2"
  local command_line
  [[ -r "/proc/$pid/cmdline" ]] || return 1
  command_line="$(tr '\0' ' ' < "/proc/$pid/cmdline")"
  [[ "$command_line" == *"$pattern"* ]]
}

stop_recorded_process() {
  local name="$1"
  local pid_file="$2"
  local pattern="$3"

  [[ -f "$pid_file" ]] || return 0

  local pid
  pid="$(<"$pid_file")"
  if [[ ! "$pid" =~ ^[0-9]+$ ]]; then
    echo "warning: removing invalid $name pid file: $pid_file" >&2
    rm -f "$pid_file"
    return 0
  fi

  if ! kill -0 "$pid" 2>/dev/null; then
    log "$name already stopped"
    rm -f "$pid_file"
    return 0
  fi

  if ! process_matches "$pid" "$pattern"; then
    echo "warning: not stopping $name pid $pid because it no longer looks like $pattern" >&2
    rm -f "$pid_file"
    return 0
  fi

  log "Stopping $name (pid $pid)"
  kill -TERM "$pid" 2>/dev/null || true
  for _ in $(seq 1 50); do
    if ! kill -0 "$pid" 2>/dev/null; then
      rm -f "$pid_file"
      return 0
    fi
    sleep 0.1
  done

  echo "warning: $name did not stop after SIGTERM; sending SIGKILL" >&2
  kill -KILL "$pid" 2>/dev/null || true

  for _ in $(seq 1 10); do
    ! kill -0 "$pid" 2>/dev/null && break
    sleep 0.1
  done
  rm -f "$pid_file"
}

stop_runtime() {
  local dir="$1"
  stop_recorded_process "sidecar" "$dir/sidecar_pid" "agent_gateway_sidecar"
  stop_recorded_process "swtpm" "$dir/swtpm_pid" "swtpm socket"
  rm -f "$dir/proxy_url"
}

sidecar_running() {
  local dir="$1"
  local pid
  [[ -f "$dir/sidecar_pid" ]] || return 1
  pid="$(<"$dir/sidecar_pid")"
  if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null && process_matches "$pid" "agent_gateway_sidecar"; then
    return 0
  fi
  rm -f "$dir/sidecar_pid" "$dir/proxy_url"
  return 1
}

start_swtpm() {
  local dir="$1"
  SWTPM_PID=""
  mkdir -p "$SWTPM_DIR"
  if port_open "$SWTPM_HOST" "$SWTPM_PORT"; then
    log "Using existing swtpm at $TPM_TCTI"
    return
  fi

  log "Starting swtpm at $TPM_TCTI"
  nohup swtpm socket \
    --tpm2 \
    --tpmstate "dir=$SWTPM_DIR" \
    --server "type=tcp,bindaddr=$SWTPM_HOST,port=$SWTPM_PORT" \
    --ctrl "type=tcp,bindaddr=$SWTPM_HOST,port=$SWTPM_CTRL_PORT" \
    --flags startup-clear > "$dir/swtpm.log" 2>&1 &
  SWTPM_PID=$!

  for _ in $(seq 1 50); do
    port_open "$SWTPM_HOST" "$SWTPM_PORT" && return
    if ! kill -0 "$SWTPM_PID" 2>/dev/null; then
      echo "error: swtpm exited unexpectedly" >&2
      wait "$SWTPM_PID" 2>/dev/null || true
      SWTPM_PID=""
      exit 1
    fi
    sleep 0.1
  done

  echo "error: swtpm did not become ready within 5 seconds" >&2
  exit 1
}

ensure_tpm_key() {
  if tpm2 tpm2_readpublic -Q -c "$TPM_HANDLE" -f pem -o "$CERT_DIR/machine-client-public.pem" 2>/dev/null; then
    log "Using simulated TPM key $TPM_HANDLE"
    return
  fi

  log "Creating simulated TPM P-256 signing key at $TPM_HANDLE"
  tpm2 tpm2_createprimary -Q -C o -g sha256 -G ecc256:ecdsa \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign" \
    -c "$CERT_DIR/tpm-signing-key.ctx"
  tpm2 tpm2_evictcontrol -Q -C o -c "$CERT_DIR/tpm-signing-key.ctx" "$TPM_HANDLE"
  tpm2 tpm2_readpublic -Q -c "$TPM_HANDLE" -f pem -o "$CERT_DIR/machine-client-public.pem"
  rm -f "$CERT_DIR/tpm-signing-key.ctx"
}

write_verified_subject_spki_der() {
  openssl pkey -pubin -in "$CERT_DIR/machine-client-public.pem" -outform DER \
    > "$CERT_DIR/machine-client-public.der"
  openssl x509 -in "$CERT_DIR/machine-client.pem" -pubkey -noout \
    | openssl pkey -pubin -outform DER > "$CERT_DIR/machine-client-spki.der"
  if ! cmp -s "$CERT_DIR/machine-client-public.der" "$CERT_DIR/machine-client-spki.der"; then
    echo "error: machine-client.pem public key does not match simulated TPM key $TPM_HANDLE" >&2
    exit 1
  fi
}

prepare_subject_certificate() {
  local dir="$1"
  mkdir -p "$CERT_DIR"
  for cmd in openssl swtpm tpm2_createprimary tpm2_evictcontrol tpm2_readpublic; do
    require_cmd "$cmd"
  done

  start_swtpm "$dir"
  ensure_tpm_key
  generate_certs
  write_verified_subject_spki_der

  if [[ -n "$SWTPM_PID" ]]; then
    printf '%s\n' "$SWTPM_PID" > "$dir/swtpm_pid"
  fi
  SUBJECT_PUBLIC_KEY_SPKI_DER="$CERT_DIR/machine-client-spki.der"
}

find_sidecar() {
  if [[ -n "$DEFAULT_SIDECAR_BIN" ]]; then
    if [[ ! -x "$DEFAULT_SIDECAR_BIN" ]]; then
      echo "error: sidecar binary not found or not executable: $DEFAULT_SIDECAR_BIN" >&2
      exit 1
    fi
    printf '%s' "$DEFAULT_SIDECAR_BIN"
    return
  fi

  if command -v agent_gateway_sidecar >/dev/null 2>&1; then
    command -v agent_gateway_sidecar
    return
  fi

  local candidate
  for candidate in \
    "$REPO_ROOT/target/release/agent_gateway_sidecar" \
    "$REPO_ROOT/target/debug/agent_gateway_sidecar"; do
    if [[ -x "$candidate" ]]; then
      printf '%s' "$candidate"
      return
    fi
  done

  echo "error: could not find agent_gateway_sidecar binary" >&2
  echo "hint: build with 'cargo build -p agent_gateway_sidecar' or set AGENT_GATEWAY_DEMO_SIDECAR_BIN" >&2
  exit 1
}

start_sidecar() {
  local dir="$1"
  [[ -f "$GATEWAY_CA" ]] || { echo "error: gateway CA file not found: $GATEWAY_CA" >&2; exit 1; }
  if sidecar_running "$dir"; then
    return
  fi

  local sidecar sidecar_pid
  sidecar="$(find_sidecar)"
  nohup "$sidecar" \
    --listen "$LISTEN" \
    --gateway "$GATEWAY" \
    --client-cert "$CERT_DIR/machine-client.pem" \
    --tpm-tcti "$TPM_TCTI" \
    --tpm-key-handle "$TPM_HANDLE" \
    --ca-cert "$GATEWAY_CA" > "$dir/sidecar.log" 2>&1 &
  sidecar_pid=$!

  parse_listen_addr "$LISTEN"
  echo "Waiting for sidecar on $LISTEN..." >&2
  for _ in $(seq 1 50); do
    if port_open "$LISTEN_HOST" "$LISTEN_PORT"; then
      break
    fi
    if ! kill -0 "$sidecar_pid" 2>/dev/null; then
      echo "error: sidecar exited unexpectedly" >&2
      wait "$sidecar_pid" 2>/dev/null || true
      exit 1
    fi
    sleep 0.1
  done

  if ! port_open "$LISTEN_HOST" "$LISTEN_PORT"; then
    echo "error: sidecar did not become ready within 5 seconds" >&2
    exit 1
  fi

  log "Sidecar ready on $LISTEN"
  printf '%s\n' "http://$LISTEN" > "$dir/proxy_url"
  printf '%s\n' "$sidecar_pid" > "$dir/sidecar_pid"
}

ensure_runtime() {
  local dir="$1"
  if sidecar_running "$dir"; then
    return
  fi
  set_runtime_paths "$dir"
  prepare_subject_certificate "$dir"
  start_sidecar "$dir"
}

run_prompt() {
  local dir="$1"
  require_cmd claude
  local proxy_file="$dir/proxy_url"
  [[ -f "$proxy_file" ]] || { echo "error: sidecar state missing proxy_url: $proxy_file" >&2; exit 1; }

  local proxy_url work_dir
  proxy_url="$(<"$proxy_file")"
  work_dir="$dir/work"
  mkdir -p "$work_dir"
  local claude_args=(
    --allowedTools "Bash(curl *)"
  )
  local first_prompt=false

  if [[ -f "$dir/claude_started" ]]; then
    claude_args+=(-c)
  else
    first_prompt=true
  fi
  (
    cd "$work_dir"
    HTTP_PROXY="$proxy_url" HTTPS_PROXY="$proxy_url" CURL_CA_BUNDLE="${CURL_CA_BUNDLE:-}" SSL_CERT_FILE="${SSL_CERT_FILE:-}" claude "${claude_args[@]}" -p "$PROMPT"
  )
  [[ "$first_prompt" == "false" ]] || : > "$dir/claude_started"
}

grant_permissions() {
  local destination
  for destination in "${GRANTS[@]}"; do
    "$REPO_ROOT/registry-cli/agent-permissions.sh" grant \
      "$PRINCIPAL" \
      "$IDENTITY" \
      "$SUBJECT_PUBLIC_KEY_SPKI_DER" \
      "$destination" \
      "$VALID_DAYS" >&2
  done
}

cmd_create() {
  local dir
  PRINCIPAL="$(discover_principal)"
  IDENTITY="agent-alpha"
  VALID_DAYS="$DEFAULT_VALID_DAYS"
  GATEWAY="$DEFAULT_GATEWAY"
  GATEWAY_CA="$DEFAULT_GATEWAY_CA"
  SWTPM_PORT="$DEFAULT_SWTPM_PORT"
  TPM_HANDLE="$DEFAULT_TPM_HANDLE"
  HANDLE=""
  GRANTS=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --identity) need_arg "$@"; IDENTITY="$2"; shift 2 ;;
      --grant) need_arg "$@"; GRANTS+=("$2"); shift 2 ;;
      --handle) need_arg "$@"; HANDLE="$2"; shift 2 ;;
      --valid-days) need_arg "$@"; VALID_DAYS="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    esac
  done

  [[ ${#GRANTS[@]} -gt 0 ]] || { echo "error: create requires at least one --grant" >&2; exit 2; }

  HANDLE="${HANDLE:-$(sanitize_handle "$IDENTITY")}"
  dir="$(state_dir "$HANDLE")"
  LISTEN="$DEFAULT_LISTEN_HOST:$DEFAULT_LISTEN_PORT"
  mkdir -p "$dir"
  write_state "$dir"
  set_runtime_paths "$dir"
  prepare_subject_certificate "$dir"
  grant_permissions
  start_sidecar "$dir"

  echo "$HANDLE"
}

cmd_grant() {
  [[ $# -ge 1 ]] || { echo "error: grant requires AGENT_HANDLE" >&2; usage; exit 2; }
  local dir
  HANDLE="$1"
  shift
  dir="$(state_dir "$HANDLE")"
  read_state "$dir"
  GRANTS=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --grant) need_arg "$@"; GRANTS+=("$2"); shift 2 ;;
      --valid-days) need_arg "$@"; VALID_DAYS="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    esac
  done

  [[ ${#GRANTS[@]} -gt 0 ]] || { echo "error: grant requires at least one --grant" >&2; exit 2; }
  grant_permissions
}

cmd_prompt() {
  [[ $# -ge 1 ]] || { echo "error: prompt requires AGENT_HANDLE" >&2; usage; exit 2; }
  local dir
  HANDLE="$1"
  shift
  dir="$(state_dir "$HANDLE")"
  read_state "$dir"
  PROMPT=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --prompt) need_arg "$@"; PROMPT="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    esac
  done

  [[ -n "$PROMPT" ]] || { echo "error: prompt requires --prompt" >&2; exit 2; }
  ensure_runtime "$dir"
  [[ -f "$DEFAULT_MOCK_CA" ]] || {
    echo "error: mock service CA file not found: $DEFAULT_MOCK_CA" >&2
    echo "hint: run ./demo/generate-server-certs.sh or ./demo/setup.sh first" >&2
    exit 1
  }
  export NODE_EXTRA_CA_CERTS="$DEFAULT_MOCK_CA"
  export CURL_CA_BUNDLE="$DEFAULT_MOCK_CA"
  export SSL_CERT_FILE="$DEFAULT_MOCK_CA"
  export CLAUDE_CODE_PROXY_RESOLVES_HOSTS="${CLAUDE_CODE_PROXY_RESOLVES_HOSTS:-1}"
  run_prompt "$dir"
}

cmd_delete() {
  [[ $# -ge 1 ]] || { echo "error: delete requires AGENT_HANDLE" >&2; usage; exit 2; }
  local dir
  HANDLE="$1"
  shift
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    esac
  done

  dir="$(state_dir "$HANDLE")"
  [[ -d "$dir" ]] || { echo "error: unknown agent handle: $HANDLE" >&2; exit 1; }
  read_state "$dir"
  stop_runtime "$dir"
  "$REPO_ROOT/registry-cli/agent-permissions.sh" delete "$IDENTITY" "$SUBJECT_PUBLIC_KEY_SPKI_DER" >&2
  rm -rf -- "$dir"
  log "Deleted demo agent $HANDLE"
}

[[ $# -gt 0 ]] || { usage; exit 2; }
COMMAND="$1"
shift

case "$COMMAND" in
  create) cmd_create "$@" ;;
  grant) cmd_grant "$@" ;;
  prompt) cmd_prompt "$@" ;;
  delete) cmd_delete "$@" ;;
  -h|--help) usage ;;
  *) echo "Unknown command: $COMMAND" >&2; usage; exit 2 ;;
esac
