#!/usr/bin/env bash
# Run every model of the computational research model with CryptoVerif and
# compare each verdict with the expected one.
# Usage: docs/research/formal-computational/run.sh [path/to/cryptoverif]
#        (default: cryptoverif in PATH; its library default.ocvl sits next to it)
set -euo pipefail

cd "$(dirname "$0")"
CRYPTOVERIF="${1:-cryptoverif}"
CRYPTOVERIF="$(command -v "$CRYPTOVERIF")"
LIB="$(dirname "$CRYPTOVERIF")/default"
LOGS="$(mktemp -d)"
FAILED=0

# model: expected verdict ("proved": every query is proved; "unproved":
# CryptoVerif proves nothing, as expected for the controls, which remove
# the mechanism or the assumption a property rests on).
EXPECTED=(
  "fs_stable_keys: proved"
  "fs_stable_keys_without_init: unproved"
  "sticky_removal: proved"
  "sticky_removal_single_prf: unproved"
  "sticky_removal_collude: unproved"
  "entrant_window: proved"
  "entrant_window_removal_waiting: unproved"
  "relay: proved"
  "relay_known_root: unproved"
  "city_maintained: proved"
  "city_stale: unproved"
  "city_sticky: proved"
  "weak_rng: proved"
  "weak_rng_unhedged: unproved"
  "relay_tag: proved"
  "relay_tag_unbound: unproved"
  "witness_quorum: proved"
  "witness_quorum_two_dishonest: unproved"
  "witness_quorum_two_of_four: unproved"
  "catch_up_leaf_bound: proved"
  "catch_up_init_only: unproved"
  "taint: proved"
  "taint_without_rule: unproved"
  "post_compromise: proved"
  "post_compromise_without_update: unproved"
)

for line in "${EXPECTED[@]}"; do
  model="${line%%:*}"
  expected="$(echo "${line#*:}" | xargs)"
  start=$(date +%s)
  "$CRYPTOVERIF" -lib "$LIB" -lib dualprf "$model.ocv" > "$LOGS/$model.log" 2>&1 || true
  if grep -q '^All queries proved\.' "$LOGS/$model.log"; then
    got=proved
  elif grep -q '^RESULT Could not prove' "$LOGS/$model.log"; then
    got=unproved
  else
    got=error
  fi
  elapsed=$(( $(date +%s) - start ))
  if [[ "$got" == "$expected" ]]; then
    echo "ok   $model (${elapsed}s): $got"
  else
    echo "FAIL $model (${elapsed}s): expected [$expected], got [$got]"
    echo "     log: $LOGS/$model.log"
    FAILED=1
  fi
done

exit "$FAILED"
