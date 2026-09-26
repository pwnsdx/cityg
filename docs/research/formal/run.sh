#!/usr/bin/env bash
# Run every scenario of the "Cite" research model and compare ProVerif's
# verdicts with the expected ones, query by query.
# Usage: docs/research/formal/run.sh [path/to/proverif]   (default: proverif in PATH)
set -euo pipefail

cd "$(dirname "$0")"
PROVERIF="${1:-proverif}"
LOGS="$(mktemp -d)"
FAILED=0

# scenario: expected verdict of each query, in order ("true": the property
# is proved; "false": ProVerif finds an attack, as expected for sanity
# checks, or reaches the event of a reachability query).
EXPECTED=(
  "taint: true false"
  "taint_without_rule: false false"
  "post_compromise: true false"
  "forward_secrecy: true"
  "forward_secrecy_without_init: false"
  "fabrication: true false"
  "fabrication_without_init: false false"
  "fabrication_without_init_signed: true false"
  "join: true false"
  "anchored_join: true false"
  "anchored_join_unsigned_tag: false"
  "join_without_anchor: false"
  "entrant_removal: true false"
  "external_tag_only: false false"
  "external_checked: true false"
  "open_group: false true"
)

for line in "${EXPECTED[@]}"; do
  scenario="${line%%:*}"
  expected="$(echo "${line#*:}" | xargs)"
  start=$(date +%s)
  "$PROVERIF" -lib cite.pvl "$scenario.pv" > "$LOGS/$scenario.log" 2>&1 || true
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
