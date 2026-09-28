#!/usr/bin/env bash
# Run every scenario of the symbolic model of the message plane and compare
# ProVerif's verdicts with the expected ones, query by query.
# Usage: docs/research/formal-messages/run.sh [path/to/proverif]   (default: proverif in PATH)
set -euo pipefail

cd "$(dirname "$0")"
PROVERIF="${1:-proverif}"
LOGS="$(mktemp -d)"
FAILED=0

# scenario: expected verdict of each query, in order ("true": the property
# is proved; "false": ProVerif finds an attack, as expected for sanity
# checks, for the fork of reader_removed, for what reader_link_ban's R still
# reads before its ban, and for the policy of reader_link_no_break).
EXPECTED=(
  "reader_bundle: true true"
  "reader_bundle_no_tag: false false"
  "reader_bundle_unsigned_request: false true"
  "reader_removed: true false"
  "reader_removed_signed_bundle: true true"
  "reader_removed_with_root: false"
  "reader_removed_ratchet: false"
  "reader_link: true true"
  "reader_link_ban: false true true"
  "reader_link_no_break: false"
  "bundle_any_member: true"
  "reader_seal: true"
  "reader_seal_unchecked: false"
  "burst_chain: true"
  "burst_chain_mac_only: false"
  "card_revalidated: true"
  "card_cached: false"
)

for line in "${EXPECTED[@]}"; do
  scenario="${line%%:*}"
  expected="$(echo "${line#*:}" | xargs)"
  start=$(date +%s)
  "$PROVERIF" -lib msg.pvl "$scenario.pv" > "$LOGS/$scenario.log" 2>&1 || true
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
