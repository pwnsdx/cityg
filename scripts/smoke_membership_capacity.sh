#!/bin/bash
set -euo pipefail

# Runtime smoke for server + GUI join/leave path and deterministic capacity freeze coverage.
# Usage: ./scripts/smoke_membership_capacity.sh
#
# Optional environment overrides:
# - CITYG_SMOKE_SERVER_BIND (default: 127.0.0.1:18080)
# - CITYG_SMOKE_WATCH_COUNT (default: 2, must be >= 2)
# - CITYG_SMOKE_MAX_CONCURRENT_HEADS (default: 2; used for watch-flow server config)
# - CITYG_SMOKE_WINDOW_TTL_SECS (default: 120)
# - CITYG_SMOKE_USE_BUILT_BINARIES (default: 1; if set to 0, forces cargo run)
# - CITYG_SMOKE_SKIP_CAPACITY (default: 0; if set to 1, skips the final capacity freeze test)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SERVER_BIND="${CITYG_SMOKE_SERVER_BIND:-127.0.0.1:18080}"
SERVER_URL="http://${SERVER_BIND}"
WATCH_COUNT="${CITYG_SMOKE_WATCH_COUNT:-2}"
MAX_HEADS="${CITYG_SMOKE_MAX_CONCURRENT_HEADS:-2}"
WINDOW_TTL_SECS="${CITYG_SMOKE_WINDOW_TTL_SECS:-120}"
USE_BUILT_BINARIES="${CITYG_SMOKE_USE_BUILT_BINARIES:-1}"
SKIP_CAPACITY="${CITYG_SMOKE_SKIP_CAPACITY:-0}"
ADMIN_TOKEN="${CITYG_CLIENT_ADMIN_TOKEN:-join-leave-admin-token}"
MESSAGE_TOKEN="${CITYG_CLIENT_MESSAGE_AUTH_TOKEN:-join-leave-message-token}"

if ! [[ "$WATCH_COUNT" =~ ^[0-9]+$ ]] || [ "$WATCH_COUNT" -lt 2 ]; then
    echo "error: CITYG_SMOKE_WATCH_COUNT must be an integer >= 2 (got '$WATCH_COUNT')" >&2
    exit 2
fi

if ! [[ "$MAX_HEADS" =~ ^[0-9]+$ ]] || [ "$MAX_HEADS" -lt 1 ]; then
    echo "error: CITYG_SMOKE_MAX_CONCURRENT_HEADS must be an integer >= 1 (got '$MAX_HEADS')" >&2
    exit 2
fi

if ! [[ "$WINDOW_TTL_SECS" =~ ^[0-9]+$ ]] || [ "$WINDOW_TTL_SECS" -lt 1 ]; then
    echo "error: CITYG_SMOKE_WINDOW_TTL_SECS must be an integer >= 1 (got '$WINDOW_TTL_SECS')" >&2
    exit 2
fi

if ! [[ "$SKIP_CAPACITY" =~ ^[01]$ ]]; then
    echo "error: CITYG_SMOKE_SKIP_CAPACITY must be 0 or 1 (got '$SKIP_CAPACITY')" >&2
    exit 2
fi

SERVER_LOG="$(mktemp)"
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then
        kill "$SERVER_PID" >/dev/null 2>&1 || true
        wait "$SERVER_PID" >/dev/null 2>&1 || true
    fi
    rm -f "$SERVER_LOG"
}
trap cleanup EXIT

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

fail() {
    echo "error: $1" >&2
    if [ -f "$SERVER_LOG" ]; then
        echo "---- cityg-api log tail ----" >&2
        tail -n 120 "$SERVER_LOG" >&2 || true
        echo "----------------------------" >&2
    fi
    exit 1
}

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

./scripts/healthcheck_api.sh "${SERVER_URL}/health/ready" 45 1 >/dev/null \
    || fail "cityg-api did not become ready"

echo "join/leave watch smoke (count=${WATCH_COUNT})"
ROOM_WATCH="$(make_room_id)"
./scripts/bootstrap_room.sh "$SERVER_URL" "$ROOM_WATCH" \
    || fail "room bootstrap failed"
run_join_leave "$SERVER_URL" "$ROOM_WATCH" "smoke-w" --watch --count="$WATCH_COUNT" \
    --verbose || fail "watch-mode join/leave smoke failed"

if [ "$SKIP_CAPACITY" = "0" ]; then
    echo "capacity smoke (window_full_rest_api_freeze)"
    cargo test -p cityg-api window_full_rest_api_freeze -- --exact \
        || fail "capacity freeze integration test failed"
else
    echo "capacity smoke skipped (CITYG_SMOKE_SKIP_CAPACITY=1)"
fi

echo "smoke passed: membership flow works and capacity freeze path is enforced"
