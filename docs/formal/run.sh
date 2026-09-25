#!/usr/bin/env bash
# Run every scenario of the City-G v0.2 symbolic model and compare ProVerif's
# verdicts with the expected ones, query by query.
# Usage: docs/formal/run.sh [path/to/proverif]    (default: proverif in PATH)
set -euo pipefail

cd "$(dirname "$0")"
PROVERIF="${1:-proverif}"
LOGS="$(mktemp -d)"
FAILED=0

# scenario: expected verdict of each query, in order. "unproved": ProVerif
# finds the expected derivation but cannot rebuild its trace through the
# private channels that carry the members' state (a sanity check whose
# property must not be provable).
EXPECTED=(
  "key_schedule: true true true true"
  "forward_secrecy: true unproved"
  "post_compromise: true false"
  "removal: true true true true false false"
  "removal_without_author_rule: false"
  "removal_without_retired_rule: false"
  "messages: true true false"
)

for line in "${EXPECTED[@]}"; do
  scenario="${line%%:*}"
  expected="$(echo "${line#*:}" | xargs)"
  start=$(date +%s)
  "$PROVERIF" -lib cityg.pvl "$scenario.pv" > "$LOGS/$scenario.log" 2>&1 || true
  got="$(grep -E '^RESULT' "$LOGS/$scenario.log" \
    | sed -E 's/.* is (true|false)\.$/\1/; s/.* cannot be proved\.$/unproved/' \
    | xargs)"
  elapsed=$(( $(date +%s) - start ))
  if [[ "$got" == "$expected" ]]; then
    echo "ok   $scenario (${elapsed}s): $got"
  else
    echo "FAIL $scenario (${elapsed}s): expected [$expected], got [$got]"
    echo "     log: $LOGS/$scenario.log"
    FAILED=1
  fi
done

exit "$FAILED"
