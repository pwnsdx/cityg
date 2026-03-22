# 19 — Future Roadmap

> [!IMPORTANT]
> This chapter is informative. Items listed here are not part of the v0.1.4 normative spec.

**Profile**: City-G `tswe/msphf-we/fs-hybrid + prs-barrier`
**Status**: Informative (planned work)

---

## 1. Leaf-Index Exhaustion Policy

**Problem**: N_max is fixed (power-of-two) for a group's lifetime. Leaf indices are single-assignment and never reused after revocation. The current spec (v0.1.4) does not define behaviour when all 2^k slots have been consumed.

**Planned Work**:
- Define a monitoring threshold (e.g., warn at 80% utilization) and a mandatory group-retirement-and-reboot procedure when exhaustion is imminent.
- Specify whether a "reboot" preserves message history references or starts a clean epoch.
- Add an informative metric (`leaf_utilization_ratio`) to the server acceptance response.

---

## 2. Cipher Migration Path

**Problem**: The current profile hard-codes ML-KEM-768, ML-DSA-65, BLAKE3, and ChaCha20-Poly1305. If any primitive is broken or deprecated, no in-protocol negotiation mechanism exists.

**Planned Work**:
- Define a `cipher_suite_id` field in the anchor header (similar to MLS cipher suites).
- Specify a transition protocol: old-suite anchors remain valid for a deprecation window; new-suite anchors are published in parallel until all members upgrade.
- Document the migration sequence for each primitive class (KEM, signature, hash, AEAD).

---

## 3. Hybrid PQ + Classical Mode

**Problem**: Some deployment contexts require interoperability with classical-only peers or mandate a hybrid approach during the PQ transition period (e.g., CNSA 2.0 compliance).

**Planned Work**:
- Define a hybrid KEM combiner (ML-KEM-768 + X25519) with a documented security reduction.
- Specify how the hybrid shared secret feeds into the existing HKDF-BLAKE3 key schedule.
- Evaluate whether hybrid mode affects anchor size budgets and SRX proof sizes.

---

## 4. Bounded Pending-Barrier Recovery

**Problem**: The spec explicitly forbids timer-based clearance of pending barrier recovery state (`pending_barrier_recovery` in S11). This means a member who misses a barrier update accumulates unbounded recovery state.

**Planned Work**:
- Analyze the practical growth rate of pending recovery state under realistic churn patterns.
- Propose an optional bounded-recovery policy (e.g., checkpoint after N missed barriers, requiring a rejoin beyond that threshold).
- Ensure any bound preserves the security guarantee that barrier secrets are not leaked to the server.

---

## 5. Large-Scale Benchmarks

**Problem**: The architecture is O(log N) and deterministic simulations target millions of members, but the largest tested N_max is 2048. Claims about performance at 100K+ or 1M members are unvalidated.

**Planned Work**:
- Establish a benchmark suite at N_max ∈ {2^14, 2^16, 2^20} measuring: anchor creation time, server acceptance time, ME-OR derivation time, SRX proof size, and barrier update fan-out.
- Publish results with hardware specs and methodology.
- Update the README comparison table and `16-comparison-mls.md` with validated numbers.
- Identify any non-logarithmic bottlenecks (e.g., SRX proof size, CBOR serialization, network fan-out).

---

## 6. Incremental Tree Hashing

**Problem**: Barrier KEM-tree operations currently re-hash the full tree path on each update. For very large N_max, this may become a latency bottleneck even though the path length is O(log N).

**Planned Work**:
- Evaluate incremental / cached Merkle tree hashing strategies compatible with the barrier tree structure.
- Benchmark the difference between full-path and incremental hashing at N_max = 2^20.
- If the improvement is material, specify the caching invariants and integrate into the barrier update flow.

---

**Next**: [00 — README](./00-README.md)

---

**Document Version**: 0.1.4
