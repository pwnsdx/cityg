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

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SERVER_BIND="${CITYG_SMOKE_SERVER_BIND:-127.0.0.1:18080}"
SERVER_URL="http://${SERVER_BIND}"
WATCH_COUNT="${CITYG_SMOKE_WATCH_COUNT:-2}"
MAX_HEADS="${CITYG_SMOKE_MAX_CONCURRENT_HEADS:-2}"
WINDOW_TTL_SECS="${CITYG_SMOKE_WINDOW_TTL_SECS:-120}"

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

fail() {
    echo "error: $1" >&2
    if [ -f "$SERVER_LOG" ]; then
        echo "---- cityg-api log tail ----" >&2
        tail -n 120 "$SERVER_LOG" >&2 || true
        echo "----------------------------" >&2
    fi
    exit 1
}

make_room_id() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
        return
    fi
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
}

echo "starting cityg-api on ${SERVER_URL}"
CITYG_SERVER_ADDRESS="$SERVER_BIND" \
CITYG_SERVER_WINDOW_TTL_SECS="$WINDOW_TTL_SECS" \
CITYG_PROTOCOL_WINDOW_DURATION_SECS="$WINDOW_TTL_SECS" \
CITYG_PROTOCOL_MAX_CONCURRENT_HEADS="$MAX_HEADS" \
RUST_LOG=warn \
cargo run -p cityg-api >"$SERVER_LOG" 2>&1 &
SERVER_PID="$!"

./scripts/healthcheck_api.sh "${SERVER_URL}/health/ready" 45 1 >/dev/null \
    || fail "cityg-api did not become ready"

echo "join/leave watch smoke (count=${WATCH_COUNT})"
ROOM_WATCH="$(make_room_id)"
cargo run -p cityg-gui --features native-app --bin join_leave -- \
    "$SERVER_URL" "$ROOM_WATCH" "smoke-w" --watch --count="$WATCH_COUNT" \
    || fail "watch-mode join/leave smoke failed"

echo "capacity smoke (window_full_rest_api_freeze)"
cargo test -p cityg-api window_full_rest_api_freeze -- --exact \
    || fail "capacity freeze integration test failed"

echo "smoke passed: membership flow works and capacity freeze path is enforced"
