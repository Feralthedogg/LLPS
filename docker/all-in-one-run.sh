#!/bin/sh
set -eu

SERVER_PID=""
LLPS_PID=""

cleanup() {
    if [ -n "$LLPS_PID" ]; then
        kill "$LLPS_PID" 2>/dev/null || true
        wait "$LLPS_PID" 2>/dev/null || true
    fi
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}

wait_tcp() {
    python3 - "$1" "$2" "$3" <<'PY'
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
timeout = float(sys.argv[3])
deadline = time.monotonic() + timeout
last_error = None

while time.monotonic() < deadline:
    try:
        with socket.create_connection((host, port), timeout=1.0):
            raise SystemExit(0)
    except OSError as exc:
        last_error = exc
        time.sleep(0.1)

print(f"tcp endpoint did not open: {host}:{port}: {last_error}", file=sys.stderr)
raise SystemExit(1)
PY
}

trap cleanup EXIT INT TERM

LISTEN_HOST="${LLPS_LISTEN_HOST:-0.0.0.0}"
LISTEN_PORT="${LLPS_LISTEN_PORT:-25565}"
LISTEN_CHECK_HOST="${LLPS_LISTEN_CHECK_HOST:-127.0.0.1}"
TARGET_BIND_HOST="${LLPS_TARGET_BIND_HOST:-127.0.0.1}"
TARGET_HOST="${LLPS_TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${LLPS_TARGET_PORT:-25566}"
CONFIG_PATH="${LLPS_CONFIG:-/tmp/llps-all-in-one.yml}"
AUDIT_PATH="${LLPS_IP_AUDIT_PATH:-/tmp/llps-ip-audit.pxf}"
TIMEOUT="${LLPS_STARTUP_TIMEOUT:-10}"

python3 /opt/llps-tools/chat_server.py \
    --host "$TARGET_BIND_HOST" \
    --port "$TARGET_PORT" &
SERVER_PID="$!"
wait_tcp "$TARGET_HOST" "$TARGET_PORT" "$TIMEOUT"

cat > "$CONFIG_PATH" <<EOF_CONFIG
max_clients: ${LLPS_MAX_CLIENTS:-256}
buffer_size: ${LLPS_BUFFER_SIZE:-4096}
listen_host: $LISTEN_HOST
listen_port: $LISTEN_PORT
target_host: $TARGET_HOST
target_port: $TARGET_PORT
listen_backlog: ${LLPS_LISTEN_BACKLOG:-256}
accept_batch_max: ${LLPS_ACCEPT_BATCH_MAX:-32}
session_idle_timeout_ms: ${LLPS_SESSION_IDLE_TIMEOUT_MS:-30000}
max_sessions_per_client_ip: ${LLPS_MAX_SESSIONS_PER_CLIENT_IP:-0}
max_new_sessions_per_client_ip_per_window: ${LLPS_MAX_NEW_SESSIONS_PER_CLIENT_IP_PER_WINDOW:-0}
client_ip_rate_window_ms: ${LLPS_CLIENT_IP_RATE_WINDOW_MS:-1000}
client_preface_timeout_ms: ${LLPS_CLIENT_PREFACE_TIMEOUT_MS:-0}
protocol_handshake_gate_enabled: ${LLPS_PROTOCOL_HANDSHAKE_GATE_ENABLED:-0}
payload_ecc_enabled: ${LLPS_PAYLOAD_ECC_ENABLED:-1}
ip_audit_enabled: ${LLPS_IP_AUDIT_ENABLED:-1}
ip_audit_path: $AUDIT_PATH
audit_mac_enabled: ${LLPS_AUDIT_MAC_ENABLED:-0}
audit_mac_key_path: ${LLPS_AUDIT_MAC_KEY_PATH:-/run/llps-secrets/llps-audit.key}
require_readiness: 0
platform_safety_flags: 7
platform_safety_evidence_id: 42424242
platform_attestation_fingerprint: 1519046679
platform_observation_digest: 0
platform_evidence_mode: synthetic
phys_mem_domain0: 11
phys_mem_domain1: 22
phys_mem_domain2: 33
hw_tmr_domain0: 0
hw_tmr_domain1: 0
hw_tmr_domain2: 0
hw_tmr_voter_domain: 0
software_ecc_enabled: 1
software_ecc_controller_count: 1
software_ecc_dimm_count: 8
software_ecc_scrub_rate: 4096
software_ecc_controller_corrected_error_count: 0
software_ecc_controller_uncorrected_error_count: 0
software_ecc_dimm_corrected_error_count: 0
software_ecc_dimm_uncorrected_error_count: 0
software_numa_enabled: 1
software_numa_memtotal_kib: 1048576
software_numa_local_distance: 10
software_numa_remote_distance: 20
software_fault_injection_mode: full
evidence_mac_enabled: 0
evidence_mac_key_path: /run/llps-secrets/llps-evidence.key
EOF_CONFIG

/opt/llps/llps -c "$CONFIG_PATH" &
LLPS_PID="$!"
wait_tcp "$LISTEN_CHECK_HOST" "$LISTEN_PORT" "$TIMEOUT"

printf '%s\n' \
    "LLPS all-in-one server is running on ${LISTEN_HOST}:${LISTEN_PORT}" \
    "Dummy target server is running on ${TARGET_BIND_HOST}:${TARGET_PORT}" \
    "Audit log: ${AUDIT_PATH}"

while :; do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        printf '%s\n' "dummy target server stopped" >&2
        exit 70
    fi
    if ! kill -0 "$LLPS_PID" 2>/dev/null; then
        set +e
        wait "$LLPS_PID"
        STATUS="$?"
        set -e
        LLPS_PID=""
        exit "$STATUS"
    fi
    sleep 1
done
