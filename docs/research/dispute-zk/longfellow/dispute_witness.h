// The witness and the public inputs of DisputeCircuit, from the member's
// X-Wing key, the ciphertext and its reference decapsulation. Research
// code.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_DISPUTE_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_DISPUTE_WITNESS_H_

#include <stddef.h>
#include <stdint.h>

#include <cstring>
#include <memory>
#include <vector>

#include "arrays/dense.h"
#include "circuits/tests/sha3/sha3_witness.h"
#include "circuits/tests/x25519/dispute_circuit.h"
#include "circuits/tests/x25519/lattice_witness.h"
#include "circuits/tests/x25519/mlkem_reference.h"
#include "circuits/tests/x25519/wrap_reference.h"
#include "circuits/tests/x25519/x25519_witness.h"

namespace proofs {

template <class Field>
class DisputeWitness {
  using Elt = typename Field::Elt;

 public:
  explicit DisputeWitness(const Field& f) : f_(f), x25519_(f), lattice_(f) {}

  // context is the wrap's. Returns false when the statement of the mode
  // does not hold (kDiffers needs a re-encryption that fails, the others
  // one that succeeds) or when a value does not match the reference.
  bool compute(const mlkem::XWingKey& key,
               const uint8_t ct[mlkem::kXWingCtBytes],
               const mlkem::XWingDecapsulation& d, Reencryption mode,
               const std::vector<uint8_t>& context) {
    using namespace mlkem;
    mode_ = mode;
    const uint8_t* ct_x = ct + kCtBytes;
    if (d.m.fo_ok != (mode != Reencryption::kDiffers)) return false;
    keccak_.clear();

    // G, then the PRF calls, each on one padded block.
    uint8_t out[200];
    permute(d.m.g_in, 64, 72, 0x06, out);
    if (std::memcmp(out, d.m.g, 64) != 0) return false;
    if (mode != Reencryption::kNone) {
      for (size_t n = 0; n < 2 * kK + 1; ++n) {
        uint8_t in[33];
        std::memcpy(in, d.m.g + 32, 32);
        in[32] = static_cast<uint8_t>(n);
        permute(in, 33, 136, 0x1f, out);
        if (std::memcmp(out, d.m.re.prf[n], kPrfBytes) != 0) return false;
      }
    }
    if (dispute_combines(mode)) {
      if (!x25519_.compute(key.sk_x, ct_x)) return false;
      uint8_t b[32];
      x25519_.pk_bytes(b);
      if (std::memcmp(b, key.pk_x, 32) != 0) return false;
      x25519_.ss_bytes(b);
      if (std::memcmp(b, d.ss_x, 32) != 0) return false;
      permute(d.combiner_in, 134, 136, 0x06, out);
      if (std::memcmp(out, d.ss, 32) != 0) return false;
      if (!schedule_.compute(d.ss, context)) return false;
    }
    if (keccak_.size() != dispute_permutations(mode)) return false;

    statement_ = std::make_unique<LatticeStatement>(key.pk, ct);
    if (!lattice_.compute(*statement_, key.m.s, key.m.e, d.m, mode)) {
      return false;
    }
    std::memcpy(h_, key.m.h, 32);
    std::memcpy(ct_x_, ct_x, 32);
    std::memcpy(pk_x_, key.pk_x, 32);
    return true;
  }

  // The Poly1305 key that the proof reveals.
  const uint8_t* poly1305_key() const { return schedule_.poly1305_key; }

  // The public inputs that do not depend on rho, in the order of
  // DisputeCircuit::Public::read.
  void fill_public(DenseFiller<Field>& filler) const {
    bool combines = dispute_combines(mode_);
    if (combines) x25519_.fill_public(filler);  // pk_X, then ct_X
    for (const uint8_t* v : {h_, ct_x_, pk_x_}) {
      if (v != h_ && !combines) continue;
      for (size_t t = 0; t < 256; ++t) {
        filler.push_back(f_.of_scalar((v[t / 8] >> (t % 8)) & 1));
      }
    }
    if (!combines) return;
    for (const auto* b : {&schedule_.key_info, &schedule_.nonce_info}) {
      for (uint32_t x : b->m0) filler.push_back(f_.of_scalar(x));
      for (uint32_t x : b->m1) filler.push_back(f_.of_scalar(x));
      for (size_t j = 0; j < 32; ++j) {
        filler.push_back(f_.of_scalar((b->len1 >> j) & 1));
      }
    }
    for (uint32_t x : schedule_.clear.outputs) filler.push_back(f_.of_scalar(x));
  }

  // The public inputs of the lattice part, which rho gives.
  std::vector<Elt> lattice_public(const Elt& rho) const {
    return LatticeWitness<Field>::public_inputs(*statement_, rho, f_, mode_);
  }

  // The private inputs, in the order of DisputeCircuit::Witness::input.
  void fill_witness(DenseFiller<Field>& filler) const {
    if (dispute_combines(mode_)) x25519_.fill_witness(filler);
    for (const auto& bw : keccak_) Sha3Witness::fill_witness(filler, bw, f_);
    lattice_.fill_witness(filler);
    if (dispute_combines(mode_)) {
      for (uint8_t b : schedule_.clear.tape) filler.push_back(f_.of_scalar(b));
    }
  }

  const LatticeStatement& statement() const { return *statement_; }

 private:
  // Keccak-f[1600] on msg (n < rate - 1 bytes) padded with the domain byte
  // and 0x80, recording its witness; out gets the state's bytes.
  void permute(const uint8_t* msg, size_t n, size_t rate, uint8_t domain,
               uint8_t out[200]) {
    uint8_t block[200] = {0};
    std::memcpy(block, msg, n);
    block[n] ^= domain;
    block[rate - 1] ^= 0x80;
    uint64_t a[5][5];
    for (size_t i = 0; i < 25; ++i) {
      uint64_t x = 0;
      for (size_t j = 0; j < 8; ++j) x |= uint64_t{block[8 * i + j]} << (8 * j);
      a[i % 5][i / 5] = x;
    }
    keccak_.emplace_back();
    Sha3Witness::compute_witness_block(a, keccak_.back());
    for (size_t i = 0; i < 200; ++i) {
      out[i] = (a[(i / 8) % 5][(i / 8) / 5] >> (8 * (i % 8))) & 0xff;
    }
  }

  const Field& f_;
  Reencryption mode_ = Reencryption::kNone;
  X25519Witness<Field> x25519_;
  LatticeWitness<Field> lattice_;
  std::vector<Sha3Witness::BlockWitness> keccak_;
  std::unique_ptr<LatticeStatement> statement_;
  wrapref::Schedule schedule_;
  uint8_t h_[32], ct_x_[32], pk_x_[32];
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_DISPUTE_WITNESS_H_
