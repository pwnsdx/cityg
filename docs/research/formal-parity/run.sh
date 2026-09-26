#!/usr/bin/env bash
# Run every scenario of the symbolic model of City-G at parity with MLS and
# compare ProVerif's verdicts with the expected ones, query by query.
# Usage: docs/research/formal-parity/run.sh [path/to/proverif]   (default: proverif in PATH)
set -euo pipefail

cd "$(dirname "$0")"
PROVERIF="${1:-proverif}"
LOGS="$(mktemp -d)"
FAILED=0

# scenario: expected verdict of each query, in order ("true": the property
# is proved; "false": ProVerif finds an attack, as expected for sanity
# checks, for the fork of history_link and for history_link_rejoin, which
# is why history links are rejected; "unproved": an equivalence ProVerif
# cannot prove, as expected when the sender is sent in clear).
EXPECTED=(
  "batch_authorization: true"
  "batch_authorization_unsigned: false"
  "authorizer_anchor: true true"
  "authorizer_anchor_unsigned: false false"
  "authorizer_follow: true true"
  "authorizer_follow_unchecked: false false"
  "history_link: true false"
  "history_link_rejoin: false"
  "sender_hidden: true"
  "sender_visible: unproved"
)

for line in "${EXPECTED[@]}"; do
  scenario="${line%%:*}"
  expected="$(echo "${line#*:}" | xargs)"
  start=$(date +%s)
  "$PROVERIF" -lib parity.pvl "$scenario.pv" > "$LOGS/$scenario.log" 2>&1 || true
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
