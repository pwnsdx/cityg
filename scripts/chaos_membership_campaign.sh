#!/bin/bash
set -euo pipefail

# Deprecated wrapper around cityg-stress.
# Concurrent multi-room chaos runner with optional restarts.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SERVER_BIND="${CITYG_CHAOS_SERVER_BIND:-127.0.0.1:18080}"
SERVER_URL="${CITYG_CHAOS_SERVER_URL:-http://${SERVER_BIND}}"
MANAGE_SERVER="${CITYG_CHAOS_MANAGE_SERVER:-1}"
WORKERS="${CITYG_CHAOS_WORKERS:-4}"
ROUNDS_PER_WORKER="${CITYG_CHAOS_ROUNDS_PER_WORKER:-5}"
MIN_COUNT="${CITYG_CHAOS_MIN_COUNT:-2}"
MAX_COUNT="${CITYG_CHAOS_MAX_COUNT:-4}"
LEAVES_PER_ROOM="${CITYG_CHAOS_LEAVES_PER_ROOM:-1}"
WATCH_PERCENT="${CITYG_CHAOS_WATCH_PERCENT:-60}"
JITTER_MAX_SECS="${CITYG_CHAOS_JITTER_MAX_SECS:-3}"
WINDOW_TTL_SECS="${CITYG_CHAOS_WINDOW_TTL_SECS:-120}"
MAX_HEADS="${CITYG_CHAOS_MAX_CONCURRENT_HEADS:-4}"
USE_BUILT_BINARIES="${CITYG_CHAOS_USE_BUILT_BINARIES:-0}"
API_BIN="${CITYG_CHAOS_API_BIN:-}"
JOIN_LEAVE_BIN="${CITYG_CHAOS_JOIN_LEAVE_BIN:-}"
RESTART_EVERY_SECS="${CITYG_CHAOS_RESTART_EVERY_SECS:-0}"
ARTIFACT_DIR="${CITYG_CHAOS_ARTIFACT_DIR:-${TMPDIR:-/tmp}/cityg-chaos-$(date +%Y%m%d-%H%M%S)}"
MESSAGE_BURST_COUNT="${CITYG_CHAOS_MESSAGE_BURST_COUNT:-1}"
MESSAGE_BURST_INTERVAL_MS="${CITYG_CHAOS_MESSAGE_BURST_INTERVAL_MS:-0}"
ADMIN_TOKEN="${CITYG_CLIENT_ADMIN_TOKEN:-join-leave-admin-token}"
MESSAGE_TOKEN="${CITYG_CLIENT_MESSAGE_AUTH_TOKEN:-join-leave-message-token}"

for pair in \
    "CITYG_CHAOS_MANAGE_SERVER:$MANAGE_SERVER:^[01]$" \
    "CITYG_CHAOS_WORKERS:$WORKERS:^[0-9]+$" \
    "CITYG_CHAOS_ROUNDS_PER_WORKER:$ROUNDS_PER_WORKER:^[0-9]+$" \
    "CITYG_CHAOS_MIN_COUNT:$MIN_COUNT:^[0-9]+$" \
    "CITYG_CHAOS_MAX_COUNT:$MAX_COUNT:^[0-9]+$" \
    "CITYG_CHAOS_LEAVES_PER_ROOM:$LEAVES_PER_ROOM:^[0-9]+$" \
    "CITYG_CHAOS_WATCH_PERCENT:$WATCH_PERCENT:^[0-9]+$" \
    "CITYG_CHAOS_JITTER_MAX_SECS:$JITTER_MAX_SECS:^[0-9]+$" \
    "CITYG_CHAOS_WINDOW_TTL_SECS:$WINDOW_TTL_SECS:^[0-9]+$" \
    "CITYG_CHAOS_MAX_CONCURRENT_HEADS:$MAX_HEADS:^[0-9]+$" \
    "CITYG_CHAOS_RESTART_EVERY_SECS:$RESTART_EVERY_SECS:^[0-9]+$"; do
    IFS=: read -r name value pattern <<<"$pair"
    if ! [[ "$value" =~ $pattern ]]; then
        echo "error: $name has invalid value '$value'" >&2
        exit 2
    fi
done
if [ "$WORKERS" -lt 1 ] || [ "$ROUNDS_PER_WORKER" -lt 1 ]; then
    echo "error: CITYG_CHAOS_WORKERS and CITYG_CHAOS_ROUNDS_PER_WORKER must be >= 1" >&2
    exit 2
fi
if [ "$MIN_COUNT" -lt 1 ] || [ "$MAX_COUNT" -lt "$MIN_COUNT" ]; then
    echo "error: CITYG_CHAOS_MIN_COUNT/MAX_COUNT are inconsistent" >&2
    exit 2
fi
if [ "$LEAVES_PER_ROOM" -lt 1 ] || [ "$WATCH_PERCENT" -gt 100 ]; then
    echo "error: CITYG_CHAOS_LEAVES_PER_ROOM must be >= 1 and CITYG_CHAOS_WATCH_PERCENT must be <= 100" >&2
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

echo "deprecated: forwarding chaos campaign to cityg-stress" >&2

cmd=(
    "$REPO_ROOT/target/debug/cityg-stress"
    --plain
    --server-bind "$SERVER_BIND"
    --server-url "$SERVER_URL"
    --workers "$WORKERS"
    --rounds-per-worker "$ROUNDS_PER_WORKER"
    --min-count "$MIN_COUNT"
    --max-count "$MAX_COUNT"
    --leaves-per-room "$LEAVES_PER_ROOM"
    --watch-percent "$WATCH_PERCENT"
    --jitter-max-secs "$JITTER_MAX_SECS"
    --round-delay-secs 0
    --message-burst-count "$MESSAGE_BURST_COUNT"
    --message-burst-interval-ms "$MESSAGE_BURST_INTERVAL_MS"
    --require-metrics
    --window-ttl-secs "$WINDOW_TTL_SECS"
    --max-concurrent-heads "$MAX_HEADS"
    --restart-every-secs "$RESTART_EVERY_SECS"
    --artifact-dir "$ARTIFACT_DIR"
)
if [ "$MANAGE_SERVER" = "0" ]; then
    cmd+=(--no-manage-server)
fi
if [ -n "$API_BIN" ]; then
    cmd+=(--api-bin "$API_BIN")
fi
if [ -n "$JOIN_LEAVE_BIN" ]; then
    cmd+=(--join-leave-bin "$JOIN_LEAVE_BIN")
fi

exec "${cmd[@]}"
