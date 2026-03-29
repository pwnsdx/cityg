#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

: "${CITYG_CARGO_TARGET_SLOT:=stress-restart-traffic}"
source "$SCRIPT_DIR/cargo_repo_env.sh"

cd "$REPO_ROOT"

if [[ ! -x "$CARGO_TARGET_DIR/debug/cityg-api" ]]; then
  cargo build --locked -p cityg-api
fi
if [[ ! -x "$CARGO_TARGET_DIR/debug/join_leave" ]]; then
  cargo build --locked -p cityg-gui --features native-app --bin join_leave
fi
if [[ ! -x "$CARGO_TARGET_DIR/debug/cityg-stress" ]]; then
  cargo build --locked -p cityg-stress
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
ARTIFACT_DIR="${CITYG_STRESS_ARTIFACT_DIR:-/tmp/cityg-stress-restart-traffic-$STAMP}"

exec "$CARGO_TARGET_DIR/debug/cityg-stress" --plain \
  --api-bin "$CARGO_TARGET_DIR/debug/cityg-api" \
  --join-leave-bin "$CARGO_TARGET_DIR/debug/join_leave" \
  --artifact-dir "$ARTIFACT_DIR" \
  --server-bind "${CITYG_STRESS_SERVER_BIND:-127.0.0.1:18130}" \
  --server-url "${CITYG_STRESS_SERVER_URL:-http://127.0.0.1:18130}" \
  --workers "${CITYG_STRESS_WORKERS:-3}" \
  --rounds-per-worker "${CITYG_STRESS_ROUNDS_PER_WORKER:-18}" \
  --duration-secs "${CITYG_STRESS_DURATION_SECS:-600}" \
  --min-count "${CITYG_STRESS_MIN_COUNT:-3}" \
  --max-count "${CITYG_STRESS_MAX_COUNT:-8}" \
  --leaves-per-room "${CITYG_STRESS_LEAVES_PER_ROOM:-2}" \
  --watch-percent "${CITYG_STRESS_WATCH_PERCENT:-100}" \
  --jitter-max-secs "${CITYG_STRESS_JITTER_MAX_SECS:-0}" \
  --round-delay-secs "${CITYG_STRESS_ROUND_DELAY_SECS:-0}" \
  --message-burst-count "${CITYG_STRESS_MESSAGE_BURST_COUNT:-8}" \
  --message-burst-interval-ms "${CITYG_STRESS_MESSAGE_BURST_INTERVAL_MS:-15}" \
  --restart-every-secs "${CITYG_STRESS_RESTART_EVERY_SECS:-45}" \
  --client-restart-every-secs "${CITYG_STRESS_CLIENT_RESTART_EVERY_SECS:-20}" \
  --capture-client-state-artifacts \
  --require-metrics \
  "$@"
