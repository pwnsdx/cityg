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
# checks, for the fork of history_link, for history_link_rejoin, which is
# why history links are rejected, for a server that draws the tree's
# secrets and a member it removed, for two servers that both collude, and
# for the cheaper dispute of wrap_dispute_replay, for an îlot that the
# window removing one of its members does not re-key, for a relay that the
# member does not check against the sealed tag, for stable îlot keys
# without the init chain, for an init secret sealed to an îlot instead of
# welcomes, for a lone entrant that applies a removal without renewing
# the top, for a city above the îlots that a window does not re-key,
# with two removed members, and for a catch-up signed with a stolen device
# key under the former rule of v0.4; in wrap_dispute_report, "false" means that a
# hostile committer can be convicted, as intended, and in the catch_up
# scenarios the second "false" means that the member's own jump completes;
# "unproved": an equivalence ProVerif cannot prove, as expected when the
# sender is sent in clear).
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
  "server_rekey: true true"
  "server_rekey_removed: false false"
  "member_rekey_removed: true true"
  "split_rekey: true"
  "split_rekey_unsigned: false"
  "split_rekey_collude: false"
  "wrap_dispute: true"
  "wrap_dispute_report: true true false"
  "wrap_dispute_replay: false"
  "ilot_removal: true"
  "ilot_removal_unrekeyed: false"
  "ilot_relay: true"
  "ilot_relay_unchecked: false"
  "ilot_forward_secrecy: true"
  "ilot_forward_secrecy_without_init: false"
  "ilot_init_by_ilot: false"
  "ilot_entrant_join: true true"
  "ilot_entrant_removal_without_top: false"
  "ilot_entrant_removal: true"
  "ilot_city_stale: false"
  "ilot_city_maintained: true"
  "ilot_city_sticky: true"
  "catch_up_device_key: false false"
  "catch_up_leaf_bound: true false"
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
