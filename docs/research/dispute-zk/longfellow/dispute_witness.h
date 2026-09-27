// The witness and the public inputs of DisputeCircuit, from the member's
// X-Wing key, the ciphertext and its reference decapsulation, and, for
// branch 2, the wrap's sealed secret and the node key that the committer
// published. Research code.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_DISPUTE_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_DISPUTE_WITNESS_H_

#include <stddef.h>
#include <stdint.h>

#include <array>
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

// The wrap of a dispute, besides its KEM ciphertext: its context and, for
// branch 2, the first 32 bytes of its sealed secret (the tag is not
// needed) and pk_v, the node key that the committer published.
struct DisputeWrap {
  std::vector<uint8_t> context;
  std::array<uint8_t, 32> sealed{};
  std::vector<uint8_t> pk_v;
};

// pk_v as the verifier of branch 2 reads it: A_v = NTT^-1(A_hat_v), which
// its matrix seed gives, t_v = NTT^-1(t_hat_v), in [0, q), the seed, and
// pk_X,v. The verifier first checks that t_hat_v's coefficients are below
// q (FIPS 203's modulus check) and pk_X,v below p: no key generation gives
// another encoding, which convicts the committer without a proof.
struct NodeStatement {
  mlkem::Matrix a;
  mlkem::PolyVec t;
  uint8_t seed[32], pk_x[32];
  bool t_canonical;

  explicit NodeStatement(const uint8_t pk[mlkem::kXWingPkBytes]) {
    using namespace mlkem;
    PublicKey k = parse_ek(pk);
    uint8_t again[384 * kK];
    for (size_t i = 0; i < kK; ++i) {
      t[i] = intt(k.t_hat[i]);
      for (size_t j = 0; j < kK; ++j) a[i][j] = intt(k.a_hat[i][j]);
      byte_encode(k.t_hat[i], 12, again + 384 * i);
    }
    t_canonical = std::memcmp(again, pk, sizeof(again)) == 0;
    std::memcpy(seed, k.rho, 32);
    std::memcpy(pk_x, pk + kEkBytes, 32);
  }
};

template <class Field>
class DisputeWitness {
  using Elt = typename Field::Elt;
  using Nat = typename Field::N;

 public:
  // As DisputeCircuit::kPlaces: the matrix seed's bits, t, pk_X.
  static constexpr size_t kPlaces = 256 + mlkem::kK * mlkem::kN + 1;

  explicit DisputeWitness(const Field& f)
      : f_(f), x25519_(f), node_x25519_(f), lattice_(f) {}

  // Returns false when the statement does not hold (kReencryptionDiffers
  // needs a re-encryption that fails, the others one that succeeds;
  // kWrongSecret needs a node key other than pk_v) or when a value does
  // not match the reference. Tests may force the place of kWrongSecret.
  bool compute(const mlkem::XWingKey& key,
               const uint8_t ct[mlkem::kXWingCtBytes],
               const mlkem::XWingDecapsulation& d, Statement st,
               const DisputeWrap& wrap, size_t force_place = SIZE_MAX) {
    using namespace mlkem;
    st_ = st;
    const Reencryption mode = lattice_mode(st);
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
    if (dispute_combines(st)) {
      if (!x25519_.compute(key.sk_x, ct_x)) return false;
      uint8_t b[32];
      x25519_.pk_bytes(b);
      if (std::memcmp(b, key.pk_x, 32) != 0) return false;
      x25519_.ss_bytes(b);
      if (std::memcmp(b, d.ss_x, 32) != 0) return false;
      permute(d.combiner_in, 134, 136, 0x06, out);
      if (std::memcmp(out, d.ss, 32) != 0) return false;
      if (dispute_opens(st)) {
        if (!schedule_.expand(d.ss, wrap.context)) return false;
        if (!schedule_.open(wrap.sealed.data())) return false;
        if (!node_key(wrap.pk_v)) return false;
      } else if (!schedule_.compute(d.ss, wrap.context)) {
        return false;
      }
    }
    if (keccak_.size() != dispute_permutations(st)) return false;

    statement_ = std::make_unique<LatticeStatement>(key.pk, ct);
    if (!lattice_.compute(*statement_, key.m.s, key.m.e, d.m, mode)) {
      return false;
    }
    std::memcpy(h_, key.m.h, 32);
    std::memcpy(ct_x_, ct_x, 32);
    std::memcpy(pk_x_, key.pk_x, 32);
    std::memcpy(sealed_, wrap.sealed.data(), 32);
    // After the lattice part, whose values compute_node leaves alone.
    return !dispute_opens(st) || node_place(force_place);
  }

  // The Poly1305 key that the proof reveals, branch 1.
  const uint8_t* poly1305_key() const { return schedule_.poly1305_key; }
  // The secret that the wrap opens to, and its node key, branch 2.
  const uint8_t* opened() const { return schedule_.opened; }
  const mlkem::KeyPair& node() const { return node_; }
  const uint8_t* node_pk_x() const { return node_pk_x_; }
  size_t place() const { return place_; }

  // The public inputs that do not depend on rho, in the order of
  // DisputeCircuit::Public::read.
  void fill_public(DenseFiller<Field>& filler) const {
    const bool combines = dispute_combines(st_);
    auto bits = [&](const uint8_t v[32]) {
      for (size_t t = 0; t < 256; ++t) {
        filler.push_back(f_.of_scalar((v[t / 8] >> (t % 8)) & 1));
      }
    };
    if (combines) x25519_.fill_public(filler);  // pk_X, then ct_X
    bits(h_);
    if (combines) {
      bits(ct_x_);
      bits(pk_x_);
      for (const auto* b : {&schedule_.key_info, &schedule_.nonce_info}) {
        for (uint32_t x : b->m0) filler.push_back(f_.of_scalar(x));
        for (uint32_t x : b->m1) filler.push_back(f_.of_scalar(x));
        for (size_t j = 0; j < 32; ++j) {
          filler.push_back(f_.of_scalar((b->len1 >> j) & 1));
        }
      }
      if (!dispute_opens(st_)) {
        for (uint32_t x : schedule_.clear.outputs) {
          filler.push_back(f_.of_scalar(x));
        }
      }
    }
    if (dispute_opens(st_)) {
      bits(sealed_);
      bits(node_statement_->seed);
      filler.push_back(pk_x_v_);
      for (size_t i = 0; i < mlkem::kK; ++i) {
        for (size_t l = 0; l < mlkem::kN; ++l) {
          filler.push_back(
              f_.of_scalar(static_cast<uint64_t>(node_statement_->t[i][l])));
        }
      }
    }
  }

  // The public inputs that rho gives: the lattice part's, then, for branch
  // 2, A_v(rho).
  std::vector<Elt> lattice_public(const Elt& rho) const {
    std::vector<Elt> out = LatticeWitness<Field>::public_inputs(
        *statement_, rho, f_, lattice_mode(st_));
    if (dispute_opens(st_)) {
      std::vector<Elt> a =
          LatticeWitness<Field>::node_public(node_statement_->a, rho, f_);
      out.insert(out.end(), a.begin(), a.end());
    }
    return out;
  }

  // The private inputs, in the order of DisputeCircuit::Witness::input.
  void fill_witness(DenseFiller<Field>& filler) const {
    if (dispute_combines(st_)) x25519_.fill_witness(filler);
    for (const auto& bw : keccak_) Sha3Witness::fill_witness(filler, bw, f_);
    lattice_.fill_witness(filler);
    if (dispute_opens(st_)) {
      lattice_.fill_node(filler);
      node_x25519_.fill_public_key(filler);
      for (size_t k = 0; k < kPlaces; ++k) {
        filler.push_back(k == place_ ? f_.one() : f_.zero());
      }
      filler.push_back(sel_inv_);
    }
    if (dispute_combines(st_)) {
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

  // Branch 2: X-Wing's key generation from the opened secret's seed,
  // SHAKE256(seed, 96) = d || z || sk_X', ML-KEM's from (d, z), and pk_v.
  bool node_key(const std::vector<uint8_t>& pk_v) {
    using namespace mlkem;
    if (pk_v.size() != kXWingPkBytes) return false;
    node_statement_ = std::make_unique<NodeStatement>(pk_v.data());
    const Nat pk_x_v = Nat::of_bytes(node_statement_->pk_x);
    if (!node_statement_->t_canonical || !(pk_x_v < f_.m_)) return false;
    pk_x_v_ = f_.to_montgomery(pk_x_v);

    uint8_t e[200], out[200];
    permute(schedule_.node_seed, 32, 136, 0x1f, e);
    node_ = keygen(e, e + 32);
    uint8_t in[33];
    std::memcpy(in, e, 32);
    in[32] = kK;
    permute(in, 33, 72, 0x06, out);
    if (std::memcmp(out, node_.rho, 32) != 0 ||
        std::memcmp(out + 32, node_.sigma, 32) != 0) {
      return false;
    }
    for (size_t n = 0; n < 2 * kK; ++n) {
      std::memcpy(in, node_.sigma, 32);
      in[32] = static_cast<uint8_t>(n);
      permute(in, 33, 136, 0x1f, out);
      uint8_t ref[kPrfBytes];
      prf(node_.sigma, static_cast<uint8_t>(n), ref);
      if (std::memcmp(out, ref, kPrfBytes) != 0) return false;
    }
    node_x25519_.compute_public_key(e + 64);
    node_x25519_.pk_bytes(node_pk_x_);
    return true;
  }

  // The first place where pk' = (rho', t', pk_X') and pk_v differ, unless
  // forced, and the inverse of the difference there. t' is A_v s' + e',
  // which is pk''s t when rho' is pk_v's seed.
  bool node_place(size_t force_place) {
    using namespace mlkem;
    if (!lattice_.compute_node(node_statement_->a, node_.s, node_.e)) {
      return false;
    }
    const std::vector<int32_t>& t = lattice_.node_t();
    auto diff = [&](size_t k) {
      if (k < 256) {
        int bit_n = (node_.rho[k / 8] >> (k % 8)) & 1;
        int bit_v = (node_statement_->seed[k / 8] >> (k % 8)) & 1;
        return LatticeWitness<Field>::of_int(bit_n - bit_v, f_);
      }
      if (k < kPlaces - 1) {
        size_t l = k - 256;
        return LatticeWitness<Field>::of_int(
            t[l] - node_statement_->t[l / kN][l % kN], f_);
      }
      return f_.subf(node_x25519_.pk_, pk_x_v_);
    };
    place_ = force_place;
    for (size_t k = 0; k < kPlaces && place_ == SIZE_MAX; ++k) {
      if (diff(k) != f_.zero()) place_ = k;
    }
    if (place_ >= kPlaces) return false;
    Elt dp = diff(place_);
    sel_inv_ = dp == f_.zero() ? dp : f_.invertf(dp);
    return dp != f_.zero();
  }

  const Field& f_;
  Statement st_ = Statement::kWrap;
  X25519Witness<Field> x25519_, node_x25519_;
  LatticeWitness<Field> lattice_;
  std::vector<Sha3Witness::BlockWitness> keccak_;
  std::unique_ptr<LatticeStatement> statement_;
  wrapref::Schedule schedule_;
  uint8_t h_[32], ct_x_[32], pk_x_[32], sealed_[32];
  // Branch 2.
  std::unique_ptr<NodeStatement> node_statement_;
  Elt pk_x_v_;
  mlkem::KeyPair node_;
  uint8_t node_pk_x_[32];
  size_t place_ = SIZE_MAX;
  Elt sel_inv_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_DISPUTE_WITNESS_H_
