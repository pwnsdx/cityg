#!/bin/bash
set -euo pipefail

# Concurrent multi-room chaos runner.
# Mixes watch/batch membership flows on fresh rooms, with optional API restarts.
#
# Usage:
#   ./scripts/chaos_membership_campaign.sh
#
# Optional environment overrides:
# - CITYG_CHAOS_SERVER_BIND (default: 127.0.0.1:18080)
# - CITYG_CHAOS_SERVER_URL (default derived from CITYG_CHAOS_SERVER_BIND)
# - CITYG_CHAOS_MANAGE_SERVER (default: 1; set to 0 for an already-running server)
# - CITYG_CHAOS_WORKERS (default: 4)
# - CITYG_CHAOS_ROUNDS_PER_WORKER (default: 5)
# - CITYG_CHAOS_MIN_COUNT (default: 2)
# - CITYG_CHAOS_MAX_COUNT (default: 4)
# - CITYG_CHAOS_WATCH_PERCENT (default: 60; 0..100)
# - CITYG_CHAOS_JITTER_MAX_SECS (default: 3)
# - CITYG_CHAOS_WINDOW_TTL_SECS (default: 120)
# - CITYG_CHAOS_MAX_CONCURRENT_HEADS (default: 4)
# - CITYG_CHAOS_USE_BUILT_BINARIES (default: 1)
# - CITYG_CHAOS_RESTART_EVERY_SECS (default: 0; if > 0 and managing server, restarts API periodically)
# - CITYG_CHAOS_REQUIRE_METRICS (default: 1)
# - CITYG_CHAOS_ARTIFACT_DIR (default: /tmp/cityg-chaos-<timestamp>)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SERVER_BIND="${CITYG_CHAOS_SERVER_BIND:-127.0.0.1:18080}"
SERVER_URL="${CITYG_CHAOS_SERVER_URL:-http://${SERVER_BIND}}"
MANAGE_SERVER="${CITYG_CHAOS_MANAGE_SERVER:-1}"
WORKERS="${CITYG_CHAOS_WORKERS:-4}"
ROUNDS_PER_WORKER="${CITYG_CHAOS_ROUNDS_PER_WORKER:-5}"
MIN_COUNT="${CITYG_CHAOS_MIN_COUNT:-2}"
MAX_COUNT="${CITYG_CHAOS_MAX_COUNT:-4}"
WATCH_PERCENT="${CITYG_CHAOS_WATCH_PERCENT:-60}"
JITTER_MAX_SECS="${CITYG_CHAOS_JITTER_MAX_SECS:-3}"
WINDOW_TTL_SECS="${CITYG_CHAOS_WINDOW_TTL_SECS:-120}"
MAX_HEADS="${CITYG_CHAOS_MAX_CONCURRENT_HEADS:-4}"
USE_BUILT_BINARIES="${CITYG_CHAOS_USE_BUILT_BINARIES:-1}"
RESTART_EVERY_SECS="${CITYG_CHAOS_RESTART_EVERY_SECS:-0}"
REQUIRE_METRICS="${CITYG_CHAOS_REQUIRE_METRICS:-1}"
ARTIFACT_DIR="${CITYG_CHAOS_ARTIFACT_DIR:-${TMPDIR:-/tmp}/cityg-chaos-$(date +%Y%m%d-%H%M%S)}"
ADMIN_TOKEN="${CITYG_CLIENT_ADMIN_TOKEN:-join-leave-admin-token}"
MESSAGE_TOKEN="${CITYG_CLIENT_MESSAGE_AUTH_TOKEN:-join-leave-message-token}"

for pair in \
    "CITYG_CHAOS_MANAGE_SERVER:$MANAGE_SERVER:^[01]$" \
    "CITYG_CHAOS_WORKERS:$WORKERS:^[0-9]+$" \
    "CITYG_CHAOS_ROUNDS_PER_WORKER:$ROUNDS_PER_WORKER:^[0-9]+$" \
    "CITYG_CHAOS_MIN_COUNT:$MIN_COUNT:^[0-9]+$" \
    "CITYG_CHAOS_MAX_COUNT:$MAX_COUNT:^[0-9]+$" \
    "CITYG_CHAOS_WATCH_PERCENT:$WATCH_PERCENT:^[0-9]+$" \
    "CITYG_CHAOS_JITTER_MAX_SECS:$JITTER_MAX_SECS:^[0-9]+$" \
    "CITYG_CHAOS_WINDOW_TTL_SECS:$WINDOW_TTL_SECS:^[0-9]+$" \
    "CITYG_CHAOS_MAX_CONCURRENT_HEADS:$MAX_HEADS:^[0-9]+$" \
    "CITYG_CHAOS_RESTART_EVERY_SECS:$RESTART_EVERY_SECS:^[0-9]+$" \
    "CITYG_CHAOS_REQUIRE_METRICS:$REQUIRE_METRICS:^[01]$"; do
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
if [ "$WATCH_PERCENT" -gt 100 ]; then
    echo "error: CITYG_CHAOS_WATCH_PERCENT must be between 0 and 100" >&2
    exit 2
fi

mkdir -p "$ARTIFACT_DIR"
SERVER_LOG="$ARTIFACT_DIR/server.log"
RESTART_LOG="$ARTIFACT_DIR/restarts.log"
SUMMARY_FILE="$ARTIFACT_DIR/summary.txt"
SERVER_PID=""
RESTARTER_PID=""
START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SECONDS=0

make_room_id() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
        return
    fi
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
}

random_int() {
    local min="$1"
    local max="$2"
    if [ "$min" -eq "$max" ]; then
        echo "$min"
        return
    fi
    echo $((min + RANDOM % (max - min + 1)))
}

random_percent_hit() {
    local threshold="$1"
    [ $((RANDOM % 100)) -lt "$threshold" ]
}

random_leave_order() {
    local count="$1"
    local values=()
    local i j tmp
    for ((i = 1; i <= count; i++)); do
        values+=("$i")
    done
    for ((i = count - 1; i > 0; i--)); do
        j=$((RANDOM % (i + 1)))
        tmp="${values[i]}"
        values[i]="${values[j]}"
        values[j]="$tmp"
    done
    local joined=""
    for value in "${values[@]}"; do
        if [ -n "$joined" ]; then
            joined+=","
        fi
        joined+="$value"
    done
    echo "$joined"
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

start_server() {
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
    run_api >>"$SERVER_LOG" 2>&1 &
    SERVER_PID="$!"
    sleep 1
    if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
        echo "error: managed cityg-api failed to stay up on ${SERVER_URL}; check ${SERVER_LOG}" >&2
        return 1
    fi
    ./scripts/healthcheck_api.sh "${SERVER_URL%/}/health/ready" 45 1 >/dev/null
}

restart_server() {
    local stamp
    stamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "${stamp} restart-begin" >>"$RESTART_LOG"
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then
        kill "$SERVER_PID" >/dev/null 2>&1 || true
        wait "$SERVER_PID" >/dev/null 2>&1 || true
    fi
    start_server
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) restart-end pid=${SERVER_PID}" >>"$RESTART_LOG"
}

capture_observability() {
    local prefix="$1"
    local health_file="$ARTIFACT_DIR/${prefix}-health.json"
    local metrics_file="$ARTIFACT_DIR/${prefix}-metrics.txt"
    curl -fsS --max-time 5 "${SERVER_URL%/}/health/detailed" >"$health_file"
    if ! curl -fsS --max-time 5 "${SERVER_URL%/}/metrics" >"$metrics_file"; then
        if [ "$REQUIRE_METRICS" = "1" ]; then
            return 1
        fi
        rm -f "$metrics_file"
    fi
}

write_summary() {
    local worker_failures=0
    local worker_passes=0
    local worker_file
    for worker_file in "$ARTIFACT_DIR"/worker-*.status; do
        [ -e "$worker_file" ] || continue
        if grep -q '^status=ok$' "$worker_file"; then
            worker_passes=$((worker_passes + 1))
        else
            worker_failures=$((worker_failures + 1))
        fi
    done
    {
        echo "started_at=${START_TS}"
        echo "finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "server_url=${SERVER_URL}"
        echo "workers=${WORKERS}"
        echo "rounds_per_worker=${ROUNDS_PER_WORKER}"
        echo "worker_passes=${worker_passes}"
        echo "worker_failures=${worker_failures}"
        echo "restart_every_secs=${RESTART_EVERY_SECS}"
        echo "artifact_dir=${ARTIFACT_DIR}"
        echo "elapsed_seconds=${SECONDS}"
    } >"$SUMMARY_FILE"
}

cleanup() {
    if [ -n "$RESTARTER_PID" ] && kill -0 "$RESTARTER_PID" >/dev/null 2>&1; then
        kill "$RESTARTER_PID" >/dev/null 2>&1 || true
        wait "$RESTARTER_PID" >/dev/null 2>&1 || true
    fi
    write_summary
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then
        kill "$SERVER_PID" >/dev/null 2>&1 || true
        wait "$SERVER_PID" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

run_worker() {
    local worker_id="$1"
    local round count mode room_id alias_base leave_order jitter log_file status_file
    log_file="$ARTIFACT_DIR/worker-$(printf '%02d' "$worker_id").log"
    status_file="$ARTIFACT_DIR/worker-$(printf '%02d' "$worker_id").status"
    : >"$log_file"
    for round in $(seq 1 "$ROUNDS_PER_WORKER"); do
        room_id="$(make_room_id)"
        alias_base="chaos-w${worker_id}-r${round}"
        count="$(random_int "$MIN_COUNT" "$MAX_COUNT")"
        jitter="$(random_int 0 "$JITTER_MAX_SECS")"
        if random_percent_hit "$WATCH_PERCENT"; then
            mode="watch"
        else
            mode="batch"
        fi
        {
            echo "worker=${worker_id} round=${round} room=${room_id} mode=${mode} count=${count} jitter=${jitter}"
            ./scripts/bootstrap_room.sh "$SERVER_URL" "$room_id"
            if [ "$jitter" -gt 0 ]; then
                sleep "$jitter"
            fi
            if [ "$mode" = "watch" ]; then
                if [ "$count" -lt 2 ]; then
                    count=2
                fi
                run_join_leave "$SERVER_URL" "$room_id" "$alias_base" --watch --count="$count" --verbose
            else
                leave_order="$(random_leave_order "$count")"
                run_join_leave "$SERVER_URL" "$room_id" "$alias_base" --batch --count="$count" --leave-order="$leave_order" --verbose
            fi
        } >>"$log_file" 2>&1 || {
            echo "status=failed" >"$status_file"
            return 1
        }
    done
    echo "status=ok" >"$status_file"
}

if [ "$MANAGE_SERVER" = "1" ]; then
    echo "starting cityg-api on ${SERVER_URL}"
    start_server
else
    echo "using existing server at ${SERVER_URL}"
fi

capture_observability "initial"

if [ "$MANAGE_SERVER" = "1" ] && [ "$RESTART_EVERY_SECS" -gt 0 ]; then
    (
        while true; do
            sleep "$RESTART_EVERY_SECS"
            restart_server
        done
    ) &
    RESTARTER_PID="$!"
fi

worker_pids=()
for worker in $(seq 1 "$WORKERS"); do
    run_worker "$worker" &
    worker_pids+=("$!")
done

failed=0
for pid in "${worker_pids[@]}"; do
    if ! wait "$pid"; then
        failed=1
    fi
done

capture_observability "final" || true

if [ "$failed" -ne 0 ]; then
    echo "error: one or more chaos workers failed; see ${ARTIFACT_DIR}" >&2
    exit 1
fi

echo "chaos campaign passed: workers=${WORKERS} rounds_per_worker=${ROUNDS_PER_WORKER}"
echo "artifacts: ${ARTIFACT_DIR}"
