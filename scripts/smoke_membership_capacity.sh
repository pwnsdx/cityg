#!/bin/bash
set -euo pipefail

# Deprecated wrapper around cityg-stress.
# Runtime smoke for server + GUI join/leave path with optional deterministic
# capacity freeze coverage.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SERVER_BIND="${CITYG_SMOKE_SERVER_BIND:-127.0.0.1:18080}"
SERVER_URL="http://${SERVER_BIND}"
WATCH_COUNT="${CITYG_SMOKE_WATCH_COUNT:-2}"
MAX_HEADS="${CITYG_SMOKE_MAX_CONCURRENT_HEADS:-2}"
WINDOW_TTL_SECS="${CITYG_SMOKE_WINDOW_TTL_SECS:-120}"
USE_BUILT_BINARIES="${CITYG_SMOKE_USE_BUILT_BINARIES:-0}"
SKIP_CAPACITY="${CITYG_SMOKE_SKIP_CAPACITY:-0}"
MESSAGE_BURST_COUNT="${CITYG_SMOKE_MESSAGE_BURST_COUNT:-1}"
MESSAGE_BURST_INTERVAL_MS="${CITYG_SMOKE_MESSAGE_BURST_INTERVAL_MS:-0}"
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

ensure_stress_binary() {
    if [ "$USE_BUILT_BINARIES" = "1" ] && [ -x "$REPO_ROOT/target/debug/cityg-stress" ]; then
        return 0
    fi
    cargo build -p cityg-api -p cityg-gui --features native-app --bin join_leave -p cityg-stress >/dev/null
}

ensure_stress_binary

export CITYG_SERVER_ROOMS_ADMIN_TOKEN="$ADMIN_TOKEN"
export CITYG_SERVER_WINDOW_ADMIN_TOKEN="$ADMIN_TOKEN"
export CITYG_SERVER_MESSAGE_AUTH_TOKEN="$MESSAGE_TOKEN"
export CITYG_CLIENT_ADMIN_TOKEN="$ADMIN_TOKEN"
export CITYG_CLIENT_MESSAGE_AUTH_TOKEN="$MESSAGE_TOKEN"

echo "deprecated: forwarding smoke campaign to cityg-stress" >&2

cmd=(
    "$REPO_ROOT/target/debug/cityg-stress"
    --plain
    --server-bind "$SERVER_BIND"
    --server-url "$SERVER_URL"
    --workers 1
    --rounds-per-worker 1
    --min-count "$WATCH_COUNT"
    --max-count "$WATCH_COUNT"
    --leaves-per-room "$WATCH_COUNT"
    --watch-percent 100
    --jitter-max-secs 0
    --round-delay-secs 0
    --message-burst-count "$MESSAGE_BURST_COUNT"
    --message-burst-interval-ms "$MESSAGE_BURST_INTERVAL_MS"
    --window-ttl-secs "$WINDOW_TTL_SECS"
    --max-concurrent-heads "$MAX_HEADS"
)
if [ "$SKIP_CAPACITY" = "0" ]; then
    cmd+=(--final-capacity-check)
fi

exec "${cmd[@]}"
