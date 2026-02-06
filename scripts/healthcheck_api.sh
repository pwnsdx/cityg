#!/bin/bash
set -euo pipefail

# Polls an HTTP health endpoint until it succeeds or times out.
# Usage: ./scripts/healthcheck_api.sh [url] [timeout_secs] [interval_secs]

URL="${1:-http://127.0.0.1:8080/health/ready}"
TIMEOUT_SECS="${2:-30}"
INTERVAL_SECS="${3:-1}"

if ! [[ "$TIMEOUT_SECS" =~ ^[0-9]+$ ]] || [ "$TIMEOUT_SECS" -le 0 ]; then
    echo "error: timeout_secs must be a positive integer (got '$TIMEOUT_SECS')" >&2
    exit 2
fi

if ! [[ "$INTERVAL_SECS" =~ ^[0-9]+$ ]] || [ "$INTERVAL_SECS" -le 0 ]; then
    echo "error: interval_secs must be a positive integer (got '$INTERVAL_SECS')" >&2
    exit 2
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "error: curl is required for health checks" >&2
    exit 2
fi

deadline=$((SECONDS + TIMEOUT_SECS))
while [ "$SECONDS" -lt "$deadline" ]; do
    if curl -fsS --max-time 3 "$URL" >/dev/null 2>&1; then
        echo "ready: $URL"
        exit 0
    fi
    sleep "$INTERVAL_SECS"
done

echo "timeout: service did not become ready within ${TIMEOUT_SECS}s ($URL)" >&2
exit 1
