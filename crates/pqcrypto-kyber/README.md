# pqcrypto-kyber (Local Bridge)

This crate is a local bridge that preserves the
`pqcrypto_kyber::kyber768` Rust API shape while the current City-G base profile
uses `ml-kem-768` normatively.

## Why this crate exists

- It keeps the workspace import surface stable.
- It avoids a large mechanical rename across protocol, client, server, GUI, and
  tests.
- It lets the repository express `ml-kem-768` on the wire and in the spec while
  still using a familiar `pqcrypto_kyber::kyber768` module path in Rust code.

## What this crate is not

- Not a legacy wire-profile path.
- Not a protocol-level compatibility mode.
- Not a knob that switches between Kyber and ML-KEM at runtime.

Within this repository, `pqcrypto_kyber::kyber768` should be read as a stable
local bridge over ML-KEM-768.

## Scope

The bridge currently exposes the keypair, encapsulation, decapsulation, and
byte conversion APIs needed by the rest of the City-G workspace.

## Normative source

The normative protocol/profile definition remains
[`docs/specs.md`](../../docs/specs.md). This crate only provides a Rust API
bridge for that profile.
