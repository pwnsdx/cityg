#!/bin/bash
set -euo pipefail

# Repeated membership/message soak runner with artifact capture.
# Starts one API instance by default, then exercises fresh rooms in a loop.
#
# Usage:
#   ./scripts/soak_membership_campaign.sh
#
# Optional environment overrides:
# - CITYG_SOAK_SERVER_BIND (default: 127.0.0.1:18080)
# - CITYG_SOAK_SERVER_URL (default derived from CITYG_SOAK_SERVER_BIND)
# - CITYG_SOAK_MANAGE_SERVER (default: 1; set to 0 to use an already-running server)
# - CITYG_SOAK_ITERATIONS (default: 10)
# - CITYG_SOAK_WATCH_COUNT (default: 2)
# - CITYG_SOAK_SLEEP_SECS (default: 2)
# - CITYG_SOAK_WINDOW_TTL_SECS (default: 120)
# - CITYG_SOAK_MAX_CONCURRENT_HEADS (default: 2)
# - CITYG_SOAK_USE_BUILT_BINARIES (default: 1; set to 0 to force cargo run)
# - CITYG_SOAK_ARTIFACT_DIR (default: /tmp/cityg-soak-<timestamp>)
# - CITYG_SOAK_REQUIRE_METRICS (default: 1; fail if /metrics cannot be collected)
# - CITYG_SOAK_FINAL_CAPACITY (default: 0; set to 1 to run window_full_rest_api_freeze once at the end)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SERVER_BIND="${CITYG_SOAK_SERVER_BIND:-127.0.0.1:18080}"
SERVER_URL="${CITYG_SOAK_SERVER_URL:-http://${SERVER_BIND}}"
MANAGE_SERVER="${CITYG_SOAK_MANAGE_SERVER:-1}"
ITERATIONS="${CITYG_SOAK_ITERATIONS:-10}"
WATCH_COUNT="${CITYG_SOAK_WATCH_COUNT:-2}"
SLEEP_SECS="${CITYG_SOAK_SLEEP_SECS:-2}"
WINDOW_TTL_SECS="${CITYG_SOAK_WINDOW_TTL_SECS:-120}"
MAX_HEADS="${CITYG_SOAK_MAX_CONCURRENT_HEADS:-2}"
USE_BUILT_BINARIES="${CITYG_SOAK_USE_BUILT_BINARIES:-1}"
REQUIRE_METRICS="${CITYG_SOAK_REQUIRE_METRICS:-1}"
FINAL_CAPACITY="${CITYG_SOAK_FINAL_CAPACITY:-0}"
ARTIFACT_DIR="${CITYG_SOAK_ARTIFACT_DIR:-${TMPDIR:-/tmp}/cityg-soak-$(date +%Y%m%d-%H%M%S)}"
ADMIN_TOKEN="${CITYG_CLIENT_ADMIN_TOKEN:-join-leave-admin-token}"
MESSAGE_TOKEN="${CITYG_CLIENT_MESSAGE_AUTH_TOKEN:-join-leave-message-token}"

for pair in \
    "CITYG_SOAK_MANAGE_SERVER:$MANAGE_SERVER:^[01]$" \
    "CITYG_SOAK_ITERATIONS:$ITERATIONS:^[0-9]+$" \
    "CITYG_SOAK_WATCH_COUNT:$WATCH_COUNT:^[0-9]+$" \
    "CITYG_SOAK_SLEEP_SECS:$SLEEP_SECS:^[0-9]+$" \
    "CITYG_SOAK_WINDOW_TTL_SECS:$WINDOW_TTL_SECS:^[0-9]+$" \
    "CITYG_SOAK_MAX_CONCURRENT_HEADS:$MAX_HEADS:^[0-9]+$" \
    "CITYG_SOAK_REQUIRE_METRICS:$REQUIRE_METRICS:^[01]$" \
    "CITYG_SOAK_FINAL_CAPACITY:$FINAL_CAPACITY:^[01]$"; do
    IFS=: read -r name value pattern <<<"$pair"
    if ! [[ "$value" =~ $pattern ]]; then
        echo "error: $name has invalid value '$value'" >&2
        exit 2
    fi
done

if [ "$ITERATIONS" -lt 1 ]; then
    echo "error: CITYG_SOAK_ITERATIONS must be >= 1" >&2
    exit 2
fi

if [ "$WATCH_COUNT" -lt 2 ]; then
    echo "error: CITYG_SOAK_WATCH_COUNT must be >= 2" >&2
    exit 2
fi

if [ "$MAX_HEADS" -lt 1 ] || [ "$WINDOW_TTL_SECS" -lt 1 ]; then
    echo "error: CITYG_SOAK_MAX_CONCURRENT_HEADS and CITYG_SOAK_WINDOW_TTL_SECS must be >= 1" >&2
    exit 2
fi

mkdir -p "$ARTIFACT_DIR"
SERVER_LOG="$ARTIFACT_DIR/server.log"
SUMMARY_FILE="$ARTIFACT_DIR/summary.txt"
SERVER_PID=""
PASSED=0
FAILED=0
START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SECONDS=0

make_room_id() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
        return
    fi
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
}

run_api() {
    if [ "$USE_BUILT_BINARIES" = "1" ] && [ -x "$REPO_ROOT/target/debug/cityg-api" ]; then
        "$REPO_ROOT/target/debug/cityg-api"
    else
        cargo run -p cityg-api
    fi
}

run_join_leave() {
    if [ "$USE_BUILT_BINARIES" = "1" ] && [ -x "$REPO_ROOT/target/debug/join_leave" ]; then
        "$REPO_ROOT/target/debug/join_leave" "$@"
    else
        cargo run -p cityg-gui --features native-app --bin join_leave -- "$@"
    fi
}

write_summary() {
    {
        echo "started_at=${START_TS}"
        echo "finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "server_url=${SERVER_URL}"
        echo "iterations_requested=${ITERATIONS}"
        echo "iterations_passed=${PASSED}"
        echo "iterations_failed=${FAILED}"
        echo "artifact_dir=${ARTIFACT_DIR}"
        echo "elapsed_seconds=${SECONDS}"
        echo "manage_server=${MANAGE_SERVER}"
        echo "final_capacity=${FINAL_CAPACITY}"
    } >"$SUMMARY_FILE"
}

cleanup() {
    write_summary
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then
        kill "$SERVER_PID" >/dev/null 2>&1 || true
        wait "$SERVER_PID" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

capture_observability() {
    local prefix="$1"
    local health_file="$ARTIFACT_DIR/${prefix}-health.json"
    local metrics_file="$ARTIFACT_DIR/${prefix}-metrics.txt"

    curl -fsS --max-time 5 "${SERVER_URL%/}/health/detailed" >"$health_file"
    if ! curl -fsS --max-time 5 "${SERVER_URL%/}/metrics" >"$metrics_file"; then
        if [ "$REQUIRE_METRICS" = "1" ]; then
            return 1
        fi
        echo "warn: could not capture /metrics for ${prefix}" >&2
        rm -f "$metrics_file"
    fi
}

if [ "$MANAGE_SERVER" = "1" ]; then
    echo "starting cityg-api on ${SERVER_URL}"
    export CITYG_SERVER_ROOMS_ADMIN_TOKEN="$ADMIN_TOKEN"
    export CITYG_SERVER_WINDOW_ADMIN_TOKEN="$ADMIN_TOKEN"
    export CITYG_SERVER_MESSAGE_AUTH_TOKEN="$MESSAGE_TOKEN"
    export CITYG_CLIENT_ADMIN_TOKEN="$ADMIN_TOKEN"
    export CITYG_CLIENT_MESSAGE_AUTH_TOKEN="$MESSAGE_TOKEN"
    CITYG_SERVER_ADDRESS="$SERVER_BIND" \
    CITYG_SERVER_WINDOW_TTL_SECS="$WINDOW_TTL_SECS" \
    CITYG_PROTOCOL_WINDOW_DURATION_SECS="$WINDOW_TTL_SECS" \
    CITYG_PROTOCOL_MAX_CONCURRENT_HEADS="$MAX_HEADS" \
    RUST_LOG=warn \
    run_api >"$SERVER_LOG" 2>&1 &
    SERVER_PID="$!"

    ./scripts/healthcheck_api.sh "${SERVER_URL%/}/health/ready" 45 1 >/dev/null
else
    echo "using existing server at ${SERVER_URL}"
fi

capture_observability "initial"

for i in $(seq 1 "$ITERATIONS"); do
    ROOM_ID="$(make_room_id)"
    ITER_LOG="$ARTIFACT_DIR/iteration-$(printf '%03d' "$i").log"
    echo "iteration ${i}/${ITERATIONS}: room=${ROOM_ID}"
    {
        echo "room_id=${ROOM_ID}"
        date -u +%Y-%m-%dT%H:%M:%SZ
        ./scripts/bootstrap_room.sh "$SERVER_URL" "$ROOM_ID"
        run_join_leave "$SERVER_URL" "$ROOM_ID" "soak-${i}" --watch --count="$WATCH_COUNT" --verbose
    } >"$ITER_LOG" 2>&1 || {
        FAILED=$((FAILED + 1))
        capture_observability "failure-$(printf '%03d' "$i")" || true
        echo "error: iteration ${i} failed; see $ITER_LOG" >&2
        exit 1
    }

    PASSED=$((PASSED + 1))
    capture_observability "iteration-$(printf '%03d' "$i")"
    if [ "$i" -lt "$ITERATIONS" ] && [ "$SLEEP_SECS" -gt 0 ]; then
        sleep "$SLEEP_SECS"
    fi
done

if [ "$FINAL_CAPACITY" = "1" ]; then
    echo "running final capacity freeze check"
    cargo test -p cityg-api window_full_rest_api_freeze -- --exact \
        >"$ARTIFACT_DIR/final-capacity.log" 2>&1
fi

echo "soak campaign passed: ${PASSED}/${ITERATIONS} iterations"
echo "artifacts: ${ARTIFACT_DIR}"
