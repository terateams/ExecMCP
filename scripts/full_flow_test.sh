#!/usr/bin/env bash
set -euo pipefail

# Comprehensive MCP interface test script focusing on the SSE transport.
# It starts the server, opens an SSE stream, and exercises key JSON-RPC methods.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${CONFIG_PATH:-$ROOT_DIR/config.test.yaml}"
SERVER_BIN="${SERVER_BIN:-$ROOT_DIR/bin/mcpserver}"
SSE_URL="${SSE_URL:-http://127.0.0.1:8081/mcp/sse}"
CACHE_DIR="${ROOT_DIR}/.cache"
TMP_DIR="$(mktemp -d)"
SERVER_LOG="${TMP_DIR}/server.log"
SSE_BODY_FILE="${TMP_DIR}/sse_stream.log"
SSE_CURL_LOG="${TMP_DIR}/sse_curl.log"
MIN_GO_VERSION="1.23.0"
START_SERVER="${START_SERVER:-0}"

cleanup() {
  if [[ -n ${SSE_CURL_PID:-} ]] && kill -0 "${SSE_CURL_PID}" 2>/dev/null; then
    kill "${SSE_CURL_PID}" 2>/dev/null || true
    wait "${SSE_CURL_PID}" 2>/dev/null || true
  fi
  if [[ -n ${SERVER_PID:-} ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

supports_color() {
  [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ $(tput colors 2>/dev/null || echo 0) -ge 8 ]]
}

if supports_color; then
  COLOR_BLUE=$(tput setaf 4)
  COLOR_GREEN=$(tput setaf 2)
  COLOR_YELLOW=$(tput setaf 3)
  COLOR_RESET=$(tput sgr0)
else
  COLOR_BLUE=""
  COLOR_GREEN=""
  COLOR_YELLOW=""
  COLOR_RESET=""
fi

print_divider() {
  printf '%s\n' "------------------------------------------------------------"
}

log_step() {
  echo
  print_divider
  printf '%s==> %s%s\n' "${COLOR_BLUE}" "$1" "${COLOR_RESET}"
  print_divider
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command not found: $1" >&2
    exit 1
  fi
}

version_ge() {
  local IFS=.
  local -a a=($1) b=($2)
  for ((i=0; i<3; i++)); do
    local av=${a[i]:-0}
    local bv=${b[i]:-0}
    if (( av > bv )); then
      return 0
    fi
    if (( av < bv )); then
      return 1
    fi
  done
  return 0
}

check_go_version() {
  local goversion
  goversion=$(go env GOVERSION 2>/dev/null | sed 's/^go//')
  if [[ -z ${goversion} ]]; then
    echo "Unable to determine Go toolchain version." >&2
    exit 1
  fi
  if ! version_ge "${goversion}" "${MIN_GO_VERSION}"; then
    echo "Go ${MIN_GO_VERSION}+ required to build server, found ${goversion}." >&2
    echo "Install a newer Go toolchain or provide SERVER_BIN/SERVER_CMD." >&2
    exit 1
  fi
}

wait_for_sse_pattern() {
  local pattern="$1"
  local timeout="${2:-20}"
  for ((i=0; i<timeout*5; i++)); do
    if grep -Fq "${pattern}" "${SSE_BODY_FILE}" 2>/dev/null; then
      return 0
    fi
    if [[ -n ${SSE_CURL_PID:-} ]] && ! kill -0 "${SSE_CURL_PID}" 2>/dev/null; then
      echo "SSE stream ended unexpectedly while waiting for pattern: ${pattern}" >&2
      if [[ -s ${SSE_CURL_LOG} ]]; then
        echo "curl log:" >&2
        sed 's/^/  /' "${SSE_CURL_LOG}" >&2
      fi
      return 1
    fi
    sleep 0.2
  done

  echo "Timed out waiting for SSE data containing: ${pattern}" >&2
  if [[ -s ${SSE_BODY_FILE} ]]; then
    echo "Last SSE payloads:" >&2
    tail -n 40 "${SSE_BODY_FILE}" >&2
  fi
  return 1
}

format_json() {
  local raw="$1"
  if [[ -z ${raw} ]]; then
    return 1
  fi
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "${raw}" | jq . 2>/dev/null
    return $?
  fi
  if command -v python3 >/dev/null 2>&1; then
    printf '%s' "${raw}" | python3 - <<'PY' 2>/dev/null
import json, sys
try:
    obj = json.load(sys.stdin)
except json.JSONDecodeError:
    sys.exit(1)
json.dump(obj, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write("\n")
PY
    return $?
  fi
  return 1
}

highlight() {
  printf '%s%s%s\n' "${COLOR_GREEN}" "$1" "${COLOR_RESET}"
}

print_sse_payload() {
  local pattern="$1"
  local header="${2:-Captured SSE payload}"
  local output event data json_payload
  output=$(tr -d '\r' < "${SSE_BODY_FILE}" | awk -v pat="$pattern" 'BEGIN{RS="\n\n"; ORS="\n\n"} index($0, pat){print; exit}') || true
  if [[ -n ${output} ]]; then
    event=$(printf '%s' "${output}" | grep '^event:' | head -n 1 | cut -d' ' -f2-)
    data=$(printf '%s' "${output}" | sed -n 's/^data: //p')
    echo
    highlight "${header}"
    print_divider
    if [[ -n ${event} ]]; then
      printf '%sEvent:%s %s\n' "${COLOR_YELLOW}" "${COLOR_RESET}" "${event}"
    fi
    if [[ -n ${data} ]]; then
      if json_payload=$(format_json "${data}"); then
        printf '%sData:%s\n' "${COLOR_YELLOW}" "${COLOR_RESET}"
        echo "${json_payload}" | sed 's/^/  /'
      else
        printf '%sData:%s\n' "${COLOR_YELLOW}" "${COLOR_RESET}"
        printf '%s\n' "${data}" | sed 's/^/  /'
      fi
    else
      printf '%sRaw frame:%s\n' "${COLOR_YELLOW}" "${COLOR_RESET}"
      printf '%s\n' "${output}" | sed 's/^/  /'
    fi
  else
    echo "No SSE payload matched pattern: ${pattern}" >&2
  fi
}

show_request_payload() {
  local file="$1"
  local label="${2:-Request body}"
  echo
  highlight "${label}"
  print_divider
  local formatted
  if formatted=$(format_json "$(<"${file}")"); then
    printf '%s\n' "${formatted}" | sed 's/^/  /'
  else
    sed 's/^/  /' "${file}"
  fi
}

send_jsonrpc_request() {
  local payload_file="$1"
  local label="$2"
  local expected_code="${3:-202}"
  local response_file="${TMP_DIR}/response_${label// /_}.txt"

  local http_code
  http_code=$(curl -sS -o "${response_file}" -w '%{http_code}' \
    -X POST \
    -H 'Content-Type: application/json' \
    --data-binary "@${payload_file}" \
    "${MESSAGE_URL}")

  if [[ "${http_code}" != "${expected_code}" ]]; then
    echo "${label} request failed (HTTP ${http_code})." >&2
    if [[ -s "${response_file}" ]]; then
      echo "Response body:" >&2
      sed 's/^/  /' "${response_file}" >&2
    fi
    if [[ -f "${SERVER_LOG}" ]]; then
      echo "Server logs:" >&2
      tail -n 40 "${SERVER_LOG}" >&2
    else
      echo "Server logs not available (server not started by script)." >&2
    fi
    exit 1
  fi
  rm -f "${response_file}"
}

# --- Pre-flight checks ---
require_cmd curl
if [[ "${START_SERVER}" -eq 1 ]]; then
  declare -a SERVER_CMD_ARR
  if [[ -n ${SERVER_CMD:-} ]]; then
    read -r -a SERVER_CMD_ARR <<< "${SERVER_CMD}"
  else
    if [[ -x ${SERVER_BIN} ]]; then
      SERVER_CMD_ARR=("${SERVER_BIN}" "-c" "${CONFIG_PATH}")
    else
      require_cmd go
      check_go_version
      mkdir -p "${CACHE_DIR}/go-build" "${CACHE_DIR}/go-mod"
      export GOCACHE="${CACHE_DIR}/go-build"
      export GOMODCACHE="${CACHE_DIR}/go-mod"
      log_step "Building ExecMCP server binary"
      go build -o "${SERVER_BIN}" .
      SERVER_CMD_ARR=("${SERVER_BIN}" "-c" "${CONFIG_PATH}")
    fi
  fi

  log_step "Starting ExecMCP server"
  "${SERVER_CMD_ARR[@]}" >"${SERVER_LOG}" 2>&1 &
  SERVER_PID=$!

  sleep 0.5
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "Server failed to start." >&2
    sed 's/^/  /' "${SERVER_LOG}" >&2
    exit 1
  fi

  echo "Server PID: ${SERVER_PID} (logs: ${SERVER_LOG})"
else
  echo "Skipping server startup. Using existing endpoint at ${SSE_URL}" 
  SERVER_PID=""
fi

log_step "Opening SSE stream at ${SSE_URL}"
for attempt in {1..10}; do
  : >"${SSE_BODY_FILE}"
  : >"${SSE_CURL_LOG}"
  curl -sS -N -H 'Accept: text/event-stream' "${SSE_URL}" \
    >"${SSE_BODY_FILE}" 2>"${SSE_CURL_LOG}" &
  SSE_CURL_PID=$!

  if wait_for_sse_pattern "sessionId=" 10; then
    break
  fi

  # Retry if the stream did not initialize
  wait "${SSE_CURL_PID}" 2>/dev/null || true
  SSE_CURL_PID=""
  if (( attempt == 10 )); then
    echo "Failed to establish SSE stream." >&2
    if [[ -s ${SSE_CURL_LOG} ]]; then
      echo "curl log:" >&2
      sed 's/^/  /' "${SSE_CURL_LOG}" >&2
    fi
    tail -n 40 "${SERVER_LOG}" >&2
    exit 1
  fi
  sleep 0.5
done

MESSAGE_LINE=""
for _ in {1..10}; do
  MESSAGE_LINE=$(grep -F 'sessionId=' "${SSE_BODY_FILE}" | head -n 1 | tr -d '\r')
  if [[ -n ${MESSAGE_LINE} ]]; then
    break
  fi
  sleep 0.2
done

if [[ -z ${MESSAGE_LINE} ]]; then
  echo "Unable to extract message endpoint from SSE stream." >&2
  tail -n 40 "${SSE_BODY_FILE}" >&2
  exit 1
fi

MESSAGE_ENDPOINT=${MESSAGE_LINE#data: }
MESSAGE_ENDPOINT=$(echo "${MESSAGE_ENDPOINT}" | xargs)

SERVER_ORIGIN=$(echo "${SSE_URL}" | sed -E 's|(https?://[^/]+).*|\1|')
if [[ ${MESSAGE_ENDPOINT} =~ ^https?:// ]]; then
  MESSAGE_URL="${MESSAGE_ENDPOINT}"
else
  MESSAGE_URL="${SERVER_ORIGIN}${MESSAGE_ENDPOINT}"
fi
SESSION_ID=${MESSAGE_ENDPOINT##*sessionId=}
SESSION_ID=${SESSION_ID%%&*}

if [[ -z ${SESSION_ID} ]]; then
  echo "Failed to parse sessionId from message endpoint." >&2
  exit 1
fi

echo "SSE session established. sessionId=${SESSION_ID}"
print_sse_payload "sessionId=" "Initial SSE frame"

# --- JSON-RPC exercises ---
INIT_REQUEST="${TMP_DIR}/req_initialize.json"
cat <<'JSON' >"${INIT_REQUEST}"
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "clientInfo": {
      "name": "interface-test-script",
      "version": "0.1.0"
    }
  }
}
JSON

log_step "Sending initialize request"
show_request_payload "${INIT_REQUEST}"
send_jsonrpc_request "${INIT_REQUEST}" "initialize"
wait_for_sse_pattern "\"id\":1" 10
print_sse_payload "\"id\":1" "Initialize response"

TOOLS_LIST_REQUEST="${TMP_DIR}/req_tools_list.json"
cat <<'JSON' >"${TOOLS_LIST_REQUEST}"
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list",
  "params": {}
}
JSON

log_step "Requesting tools/list"
show_request_payload "${TOOLS_LIST_REQUEST}"
send_jsonrpc_request "${TOOLS_LIST_REQUEST}" "tools_list"
wait_for_sse_pattern "\"id\":2" 10
print_sse_payload "\"id\":2" "tools/list response"
print_sse_payload "\"exec_command\"" "Available tools"

LIST_COMMANDS_REQUEST="${TMP_DIR}/req_tools_call_list_commands.json"
cat <<'JSON' >"${LIST_COMMANDS_REQUEST}"
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "list_commands",
    "arguments": {}
  }
}
JSON

log_step "Calling list_commands tool"
show_request_payload "${LIST_COMMANDS_REQUEST}"
send_jsonrpc_request "${LIST_COMMANDS_REQUEST}" "tools_call_list_commands"
wait_for_sse_pattern "\"id\":3" 10
print_sse_payload "\"id\":3" "tools/call (list_commands) response"
print_sse_payload 'allowed_commands' "List commands payload"

PING_REQUEST="${TMP_DIR}/req_ping.json"
cat <<'JSON' >"${PING_REQUEST}"
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "ping",
  "params": {}
}
JSON

log_step "Sending ping request"
show_request_payload "${PING_REQUEST}"
send_jsonrpc_request "${PING_REQUEST}" "ping"
wait_for_sse_pattern "\"id\":4" 10
print_sse_payload "\"id\":4" "Ping response"

log_step "Interface tests completed"
echo "All interface checks passed successfully."
