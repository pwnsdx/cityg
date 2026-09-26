// A whole City-G wrap dispute, as one Longfellow circuit over
// F_{2^255-19}: research code, not vetted for production.
//
// The member's key (s, e) and sk_X are bound to the public key by the
// lattice part and by pk_X; the key's seed stays out of the statement. The
// lattice part decrypts m', and G(m' || h) = SHA3-512 gives K and r'.
// Three statements, one per mode of the lattice part:
//   - kNone, the wrap: X25519 gives ss_X, and the combiner SHA3-256(K ||
//     ss_X || ct_X || pk_X || label) the shared secret ss. Then
//     ExpandLabel(ss, "wrap key" | "wrap nonce", context) gives the key
//     and nonce of the wrap's ChaCha20-Poly1305, and ChaCha20's first
//     block its Poly1305 key, which the proof reveals: the verifier
//     computes the tag of the wrap itself. Two Keccak-f[1600]
//     permutations (G and the combiner), four BLAKE3 compressions and one
//     ChaCha20 block.
//   - kEqual, the whole decapsulation: as kNone, and the re-encryption of
//     m' with the noise of PRF(r', N) = SHAKE256(r' || N), N = 0 to 6,
//     gives the ciphertext back. Nine permutations.
//   - kDiffers, the re-encryption differs: the re-encryption of m' differs
//     from the ciphertext in a coefficient that the proof does not reveal.
//     Eight permutations, no X25519.
// For a ciphertext that an honest committer made, the re-encryption gives
// the ciphertext back, and K is the ML-KEM secret: kNone suffices to show
// that the wrap does not open, and kDiffers convicts the committer of a
// ciphertext whose re-encryption fails.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_DISPUTE_CIRCUIT_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_DISPUTE_CIRCUIT_H_

#include <stddef.h>
#include <stdint.h>

#include <array>
#include <functional>
#include <memory>
#include <vector>

#include "circuits/tests/sha3/sha3_circuit.h"
#include "circuits/tests/x25519/arx.h"
#include "circuits/tests/x25519/lattice_circuit.h"
#include "circuits/tests/x25519/x25519_circuit.h"

namespace proofs {

// The Keccak-f[1600] permutations of each statement.
inline size_t dispute_permutations(Reencryption mode) {
  switch (mode) {
    case Reencryption::kNone:
      return 2;  // G, the combiner
    case Reencryption::kEqual:
      return 9;  // G, PRF(r', 0..6), the combiner
    case Reencryption::kDiffers:
      return 8;  // G, PRF(r', 0..6)
  }
  return 0;
}

// Whether the statement decapsulates X25519 and combines.
inline bool dispute_combines(Reencryption mode) {
  return mode != Reencryption::kDiffers;
}

template <class LogicCircuit, class Field>
class DisputeCircuit {
  using EltW = typename LogicCircuit::EltW;
  using BitW = typename LogicCircuit::BitW;
  using v64 = typename LogicCircuit::template bitvec<64>;
  using v32 = typename LogicCircuit::v32;

 public:
  using Sha3 = Sha3Circuit<LogicCircuit>;
  using X25519 = X25519Circuit<LogicCircuit, Field>;
  using Lattice = LatticeCircuit<LogicCircuit>;
  static constexpr size_t kBits = 256;

  // ExpandLabel's input, two blocks of 16 words, and the second block's
  // length as 32 bits.
  struct ExpandInput {
    std::array<EltW, 16> m0, m1;
    std::vector<EltW> len1;
  };

  struct Public {
    EltW pk_x, ct_x;  // as field elements, for the X25519 circuit
    // As bits, least significant first: H(ek), ct_X and pk_X.
    std::vector<EltW> h, ct_x_bits, pk_x_bits;
    ExpandInput key_info, nonce_info;  // "wrap key", "wrap nonce"
    std::array<EltW, 8> poly1305_key;  // the revealed words
    typename Lattice::Public lattice;  // depends on rho: comes last

    template <class Next>
    void read(Next&& next, Reencryption mode) {
      auto take = [&](std::vector<EltW>& x, size_t n) {
        x.resize(n);
        for (auto& b : x) b = next();
      };
      if (dispute_combines(mode)) {
        pk_x = next();
        ct_x = next();
      }
      take(h, kBits);
      if (dispute_combines(mode)) {
        take(ct_x_bits, kBits);
        take(pk_x_bits, kBits);
        for (ExpandInput* e : {&key_info, &nonce_info}) {
          for (auto& x : e->m0) x = next();
          for (auto& x : e->m1) x = next();
          take(e->len1, 32);
        }
        for (auto& x : poly1305_key) x = next();
      }
      lattice.read(next, mode);
    }
  };

  struct Witness {
    std::unique_ptr<typename X25519::Witness> x25519;
    std::vector<std::unique_ptr<typename Sha3::BlockWitness>> keccak;
    typename Lattice::Witness lattice;
    // The additions of ExpandLabel and ChaCha20, read as the circuit
    // needs them, after everything else.
    std::function<EltW()> tape;

    void input(const LogicCircuit& lc, Reencryption mode) {
      tape = [&lc] { return lc.eltw_input(); };
      if (dispute_combines(mode)) {
        x25519 = std::make_unique<typename X25519::Witness>();
        x25519->input(lc);
      }
      for (size_t k = 0; k < dispute_permutations(mode); ++k) {
        keccak.push_back(std::make_unique<typename Sha3::BlockWitness>());
        keccak.back()->input(lc);
      }
      lattice.read([&] { return lc.eltw_input(); }, mode);
    }
  };

  DisputeCircuit(const LogicCircuit& lc, const Field& f, Reencryption mode)
      : lc_(lc),
        f_(f),
        mode_(mode),
        sha3_(lc),
        x25519_(lc, f),
        lattice_(lc, f, mode) {}

  void assert_dispute(const Public& p, const Witness& w) const {
    // G(m' || h) = SHA3-512: 64 bytes, rate 72.
    v64 g[5][5];
    clear(g);
    for (size_t t = 0; t < kBits; ++t) {
      bit(g, t) = BitW(w.lattice.m[t], f_);
      bit(g, kBits + t) = BitW(p.h[t], f_);
    }
    lane(g, 8) = lc_.template vbit<64>(0x06 | (uint64_t{0x80} << 56));
    sha3_.keccak_f_1600(g, *w.keccak[0]);

    // PRF(r', N) = SHAKE256(r' || N): 33 bytes, rate 136; r' is bytes 32
    // to 63 of G, lanes 4 to 7.
    std::vector<EltW> prf;
    if (mode_ != Reencryption::kNone) {
      prf.reserve(Lattice::kPrfs * Lattice::kPrfBits);
      for (size_t n = 0; n < Lattice::kPrfs; ++n) {
        v64 a[5][5];
        clear(a);
        for (size_t i = 0; i < 4; ++i) lane(a, i) = lane(g, 4 + i);
        lane(a, 4) = lc_.template vbit<64>(n | (uint64_t{0x1f} << 8));
        lane(a, 16) = lc_.template vbit<64>(uint64_t{0x80} << 56);
        sha3_.keccak_f_1600(a, *w.keccak[1 + n]);
        for (size_t t = 0; t < Lattice::kPrfBits; ++t) {
          prf.push_back(lc_.eval(bit(a, t)));
        }
      }
    }
    lattice_.assert_lattice(p.lattice, w.lattice, prf);
    if (!dispute_combines(mode_)) return;

    x25519_.assert_dispute(p.pk_x, p.ct_x, *w.x25519);

    // The combiner, SHA3-256(K || ss_X || ct_X || pk_X || label): 134
    // bytes, rate 136; K is bytes 0 to 31 of G.
    v64 c[5][5];
    clear(c);
    for (size_t i = 0; i < 4; ++i) lane(c, i) = lane(g, i);
    for (size_t t = 0; t < X25519::kSsBits; ++t) {
      bit(c, kBits + t) = BitW(w.x25519->ss[t], f_);
    }
    for (size_t t = 0; t < kBits; ++t) {
      bit(c, 2 * kBits + t) = BitW(p.ct_x_bits[t], f_);
      bit(c, 3 * kBits + t) = BitW(p.pk_x_bits[t], f_);
    }
    // The label 5c 2e 2f 2f 5e 5c, then SHA-3's padding 06 ... 80.
    lane(c, 16) = lc_.template vbit<64>(0x5c5e2f2f2e5cULL |
                                        (uint64_t{0x06} << 48) |
                                        (uint64_t{0x80} << 56));
    sha3_.keccak_f_1600(c, *w.keccak.back());

    // ExpandLabel(ss, "wrap key" | "wrap nonce", context), keyed with the
    // combiner's output, then the Poly1305 key.
    using Backend = arx::ArxCircuit<LogicCircuit, std::function<EltW()>>;
    Backend backend(lc_, f_, w.tape);
    arx::Arx<Backend> a(backend);
    std::array<v32, 8> ss;
    for (size_t t = 0; t < kBits; ++t) ss[t / 32][t % 32] = bit(c, t);
    auto expand = [&](const ExpandInput& e, size_t n) {
      v32 len1;
      for (size_t j = 0; j < 32; ++j) len1[j] = BitW(e.len1[j], f_);
      return a.keyed_hash2(ss, e.m0, e.m1, len1, n);
    };
    std::vector<v32> key = expand(p.key_info, 8);
    std::vector<v32> nonce = expand(p.nonce_info, 3);
    std::array<v32, 8> k;
    for (size_t i = 0; i < 8; ++i) k[i] = key[i];
    std::array<v32, 3> n;
    for (size_t i = 0; i < 3; ++i) n[i] = nonce[i];
    a.poly1305_key(k, n, p.poly1305_key);
  }

 private:
  // Lane i of a state, x + 5 y = i, and bit t of the state.
  static v64& lane(v64 a[5][5], size_t i) { return a[i % 5][i / 5]; }
  static BitW& bit(v64 a[5][5], size_t t) { return lane(a, t / 64)[t % 64]; }

  void clear(v64 a[5][5]) const {
    for (size_t i = 0; i < 25; ++i) lane(a, i) = lc_.template vbit<64>(0);
  }

  const LogicCircuit& lc_;
  const Field& f_;
  Reencryption mode_;
  mutable Sha3 sha3_;
  X25519 x25519_;
  Lattice lattice_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_DISPUTE_CIRCUIT_H_
