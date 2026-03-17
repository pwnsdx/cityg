#!/bin/bash
set -euo pipefail

# Deprecated wrapper around cityg-stress.
# Repeated membership/message soak runner with artifact capture.

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
USE_BUILT_BINARIES="${CITYG_SOAK_USE_BUILT_BINARIES:-0}"
FINAL_CAPACITY="${CITYG_SOAK_FINAL_CAPACITY:-0}"
ARTIFACT_DIR="${CITYG_SOAK_ARTIFACT_DIR:-${TMPDIR:-/tmp}/cityg-soak-$(date +%Y%m%d-%H%M%S)}"
MESSAGE_BURST_COUNT="${CITYG_SOAK_MESSAGE_BURST_COUNT:-1}"
MESSAGE_BURST_INTERVAL_MS="${CITYG_SOAK_MESSAGE_BURST_INTERVAL_MS:-0}"
ADMIN_TOKEN="${CITYG_CLIENT_ADMIN_TOKEN:-join-leave-admin-token}"
MESSAGE_TOKEN="${CITYG_CLIENT_MESSAGE_AUTH_TOKEN:-join-leave-message-token}"

for pair in \
    "CITYG_SOAK_MANAGE_SERVER:$MANAGE_SERVER:^[01]$" \
    "CITYG_SOAK_ITERATIONS:$ITERATIONS:^[0-9]+$" \
    "CITYG_SOAK_WATCH_COUNT:$WATCH_COUNT:^[0-9]+$" \
    "CITYG_SOAK_SLEEP_SECS:$SLEEP_SECS:^[0-9]+$" \
    "CITYG_SOAK_WINDOW_TTL_SECS:$WINDOW_TTL_SECS:^[0-9]+$" \
    "CITYG_SOAK_MAX_CONCURRENT_HEADS:$MAX_HEADS:^[0-9]+$" \
    "CITYG_SOAK_FINAL_CAPACITY:$FINAL_CAPACITY:^[01]$"; do
    IFS=: read -r name value pattern <<<"$pair"
    if ! [[ "$value" =~ $pattern ]]; then
        echo "error: $name has invalid value '$value'" >&2
        exit 2
    fi
done
if [ "$ITERATIONS" -lt 1 ] || [ "$WATCH_COUNT" -lt 2 ]; then
    echo "error: CITYG_SOAK_ITERATIONS must be >= 1 and CITYG_SOAK_WATCH_COUNT must be >= 2" >&2
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

echo "deprecated: forwarding soak campaign to cityg-stress" >&2

cmd=(
    "$REPO_ROOT/target/debug/cityg-stress"
    --plain
    --server-bind "$SERVER_BIND"
    --server-url "$SERVER_URL"
    --workers 1
    --rounds-per-worker "$ITERATIONS"
    --min-count "$WATCH_COUNT"
    --max-count "$WATCH_COUNT"
    --leaves-per-room "$WATCH_COUNT"
    --watch-percent 100
    --jitter-max-secs 0
    --round-delay-secs "$SLEEP_SECS"
    --message-burst-count "$MESSAGE_BURST_COUNT"
    --message-burst-interval-ms "$MESSAGE_BURST_INTERVAL_MS"
    --require-metrics
    --window-ttl-secs "$WINDOW_TTL_SECS"
    --max-concurrent-heads "$MAX_HEADS"
    --artifact-dir "$ARTIFACT_DIR"
)
if [ "$MANAGE_SERVER" = "0" ]; then
    cmd+=(--no-manage-server)
fi
if [ "$FINAL_CAPACITY" = "1" ]; then
    cmd+=(--final-capacity-check)
fi

exec "${cmd[@]}"
