// A whole City-G wrap dispute, as one Longfellow circuit over
// F_{2^255-19}: research code, not vetted for production.
//
// The member's key (s, e) and sk_X are bound to the public key by the
// lattice part and by pk_X; the key's seed stays out of the statement. The
// lattice part decrypts m', and G(m' || h) = SHA3-512 gives K and r'.
// Four statements:
//   - kWrap, branch 1, the wrap does not open: X25519 gives ss_X, and the
//     combiner SHA3-256(K || ss_X || ct_X || pk_X || label) the shared
//     secret ss. Then ExpandLabel(ss, "wrap key" | "wrap nonce", context)
//     gives the key and nonce of the wrap's ChaCha20-Poly1305, and
//     ChaCha20's first block its Poly1305 key, which the proof reveals:
//     the verifier computes the tag of the wrap itself. Two Keccak-f[1600]
//     permutations (G and the combiner), four BLAKE3 compressions and one
//     ChaCha20 block.
//   - kWrongSecret, branch 2, the wrap gives a secret whose node key is not
//     pk_v: as kWrap up to the key and nonce; then ChaCha20's second block
//     opens the sealed secret s, ExpandLabel(s, "tree node key", [], 32)
//     seeds the node key, and X-Wing's key generation gives its public key
//     pk', which differs from pk_v at a place that the proof does not
//     reveal. The tag is left out: if it is wrong, the wrap does not open,
//     which convicts the committer as well. Ten permutations (G, the
//     combiner, SHAKE256 of the seed, G of ML-KEM's key generation and six
//     PRF), five compressions, one block and a third X25519 ladder.
//   - kWrongSecretShort, branch 2 when pk' differs from pk_v in its matrix
//     seed rho' or in its X25519 key, which is what a committer that seals
//     another secret gives: as kWrongSecret, without the six PRF and t'.
//     Four permutations.
//   - kWholeDecapsulation: as kWrap, and the re-encryption of m' with the
//     noise of PRF(r', N) = SHAKE256(r' || N), N = 0 to 6, gives the
//     ciphertext back. Nine permutations.
//   - kReencryptionDiffers: the re-encryption of m' differs from the
//     ciphertext in a coefficient that the proof does not reveal. Eight
//     permutations, no X25519.
// For a ciphertext that an honest committer made, the re-encryption gives
// the ciphertext back, and K is the ML-KEM secret: kWrap and kWrongSecret
// suffice, and kReencryptionDiffers convicts the committer of a ciphertext
// whose re-encryption fails.

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
#include "circuits/tests/x25519/wrap_reference.h"
#include "circuits/tests/x25519/x25519_circuit.h"

namespace proofs {

enum class Statement {
  kWrap,                 // branch 1: the wrap does not open
  kWrongSecret,          // branch 2: it opens to the wrong secret
  kWrongSecretShort,     // branch 2, when rho' or pk_X' differs
  kWholeDecapsulation,   // branch 1, with the re-encryption
  kReencryptionDiffers,  // the ciphertext is invalid
};

// What the lattice part checks for each statement.
inline Reencryption lattice_mode(Statement st) {
  switch (st) {
    case Statement::kWrap:
    case Statement::kWrongSecret:
    case Statement::kWrongSecretShort:
      return Reencryption::kNone;
    case Statement::kWholeDecapsulation:
      return Reencryption::kEqual;
    case Statement::kReencryptionDiffers:
      return Reencryption::kDiffers;
  }
  return Reencryption::kNone;
}

// Whether the statement decapsulates X25519 and combines.
inline bool dispute_combines(Statement st) {
  return st != Statement::kReencryptionDiffers;
}

// Whether it opens the wrap (branch 2), or reveals its Poly1305 key.
inline bool dispute_opens(Statement st) {
  return st == Statement::kWrongSecret || st == Statement::kWrongSecretShort;
}

// Whether it derives the node key's t', with six PRF and an identity of the
// lattice part.
inline bool dispute_node_t(Statement st) {
  return st == Statement::kWrongSecret;
}

// Branch 2: the places where pk' and pk_v may differ, the 256 bits of the
// matrix seed, the 768 coefficients of t if the statement derives it, and
// pk_X.
inline size_t dispute_places(Statement st) {
  if (!dispute_opens(st)) return 0;
  return 256 + (dispute_node_t(st) ? 3 * 256 : 0) + 1;
}

// The Keccak-f[1600] permutations of each statement.
inline size_t dispute_permutations(Statement st) {
  switch (st) {
    case Statement::kWrap:
      return 2;  // G, the combiner
    case Statement::kWrongSecret:
      return 10;  // G, the combiner, SHAKE256, G, PRF(sigma, 0..5)
    case Statement::kWrongSecretShort:
      return 4;  // G, the combiner, SHAKE256, G
    case Statement::kWholeDecapsulation:
      return 9;  // G, PRF(r', 0..6), the combiner
    case Statement::kReencryptionDiffers:
      return 8;  // G, PRF(r', 0..6)
  }
  return 0;
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
    std::array<EltW, 8> poly1305_key;  // the revealed words, branch 1
    // Branch 2: the sealed secret's 256 bits, then pk_v: the bits of its
    // matrix seed, its X25519 key and, if the statement derives t',
    // t_v = NTT^-1(t_hat_v), in [0, q).
    std::vector<EltW> sealed, seed_v;
    EltW pk_x_v;
    std::vector<EltW> t_v;
    // Depend on rho, the point of the lattice part: they come last.
    typename Lattice::Public lattice;
    typename Lattice::NodePublic node;  // with t_v

    template <class Next>
    void read(Next&& next, Statement st) {
      auto take = [&](std::vector<EltW>& x, size_t n) {
        x.resize(n);
        for (auto& b : x) b = next();
      };
      if (dispute_combines(st)) {
        pk_x = next();
        ct_x = next();
      }
      take(h, kBits);
      if (dispute_combines(st)) {
        take(ct_x_bits, kBits);
        take(pk_x_bits, kBits);
        for (ExpandInput* e : {&key_info, &nonce_info}) {
          for (auto& x : e->m0) x = next();
          for (auto& x : e->m1) x = next();
          take(e->len1, 32);
        }
        if (!dispute_opens(st)) {
          for (auto& x : poly1305_key) x = next();
        }
      }
      if (dispute_opens(st)) {
        take(sealed, kBits);
        take(seed_v, kBits);
        pk_x_v = next();
      }
      if (dispute_node_t(st)) take(t_v, Lattice::kK * Lattice::kN);
      lattice.read(next, lattice_mode(st));
      if (dispute_node_t(st)) node.read(next);
    }
  };

  struct Witness {
    std::unique_ptr<typename X25519::Witness> x25519;
    std::vector<std::unique_ptr<typename Sha3::BlockWitness>> keccak;
    typename Lattice::Witness lattice;
    // Branch 2: t' = A_v s' + e' if the statement derives it, the ladder
    // of pk_X' and the inverse of its last z_2, a one-hot selection of the
    // place where pk' and pk_v differ, and the inverse of that difference.
    typename Lattice::NodeWitness node;
    typename X25519::Ladder node_ladder;
    EltW node_inv;
    std::vector<EltW> sel;
    EltW sel_inv;
    // The additions of ExpandLabel and ChaCha20, read as the circuit
    // needs them, after everything else.
    std::function<EltW()> tape;

    void input(const LogicCircuit& lc, Statement st) {
      tape = [&lc] { return lc.eltw_input(); };
      if (dispute_combines(st)) {
        x25519 = std::make_unique<typename X25519::Witness>();
        x25519->input(lc);
      }
      for (size_t k = 0; k < dispute_permutations(st); ++k) {
        keccak.push_back(std::make_unique<typename Sha3::BlockWitness>());
        keccak.back()->input(lc);
      }
      auto next = [&] { return lc.eltw_input(); };
      lattice.read(next, lattice_mode(st));
      if (dispute_node_t(st)) node.read(next);
      if (dispute_opens(st)) {
        node_ladder.input(lc);
        node_inv = next();
        sel.resize(dispute_places(st));
        for (auto& x : sel) x = next();
        sel_inv = next();
      }
    }
  };

  DisputeCircuit(const LogicCircuit& lc, const Field& f, Statement st)
      : lc_(lc),
        f_(f),
        st_(st),
        sha3_(lc),
        x25519_(lc, f),
        lattice_(lc, f, lattice_mode(st)) {}

  void assert_dispute(const Public& p, const Witness& w) const {
    size_t block = 0;  // the next Keccak witness, in the witness's order

    // G(m' || h) = SHA3-512: 64 bytes, rate 72.
    v64 g[5][5];
    clear(g);
    for (size_t t = 0; t < kBits; ++t) {
      bit(g, t) = BitW(w.lattice.m[t], f_);
      bit(g, kBits + t) = BitW(p.h[t], f_);
    }
    lane(g, 8) = lc_.template vbit<64>(0x06 | (uint64_t{0x80} << 56));
    sha3_.keccak_f_1600(g, *w.keccak[block++]);

    // PRF(r', N): r' is bytes 32 to 63 of G, lanes 4 to 7.
    std::vector<EltW> prf;
    if (lattice_mode(st_) != Reencryption::kNone) {
      prf = prfs(g, Lattice::kPrfs, w, block);
    }
    lattice_.assert_lattice(p.lattice, w.lattice, prf);
    if (!dispute_combines(st_)) return;

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
    sha3_.keccak_f_1600(c, *w.keccak[block++]);

    // ExpandLabel(ss, "wrap key" | "wrap nonce", context), keyed with the
    // combiner's output.
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
    if (!dispute_opens(st_)) {
      a.poly1305_key(k, n, p.poly1305_key);  // branch 1
      return;
    }

    // Branch 2. The keystream of block 1 opens the sealed secret, and
    // ExpandLabel(secret, "tree node key", [], 32), a constant block of 37
    // bytes, gives the node key's seed.
    std::array<v32, 8> stream = a.keystream(k, 1, n);
    std::array<v32, 8> secret;
    for (size_t t = 0; t < kBits; ++t) {
      secret[t / 32][t % 32] =
          lc_.lxor(stream[t / 32][t % 32], BitW(p.sealed[t], f_));
    }
    std::array<uint32_t, 16> info;
    uint32_t info_len = 0;
    wrapref::block(wrapref::node_info(), info, info_len);
    std::array<EltW, 16> m0;
    for (size_t i = 0; i < 16; ++i) m0[i] = lc_.konst(f_.of_scalar(info[i]));
    std::vector<v32> seed =
        a.keyed_hash1(secret, m0, lc_.template vbit<32>(info_len), 8);

    // X-Wing's key generation: SHAKE256(seed, 96) = d || z || sk_X', 32
    // bytes in, rate 136.
    v64 x[5][5];
    clear(x);
    for (size_t t = 0; t < kBits; ++t) bit(x, t) = seed[t / 32][t % 32];
    lane(x, 4) = lc_.template vbit<64>(0x1f);
    lane(x, 16) = lc_.template vbit<64>(uint64_t{0x80} << 56);
    sha3_.keccak_f_1600(x, *w.keccak[block++]);
    // G(d || 3) = SHA3-512: 33 bytes, rate 72; it gives the matrix seed
    // rho' (lanes 0 to 3) and sigma' (lanes 4 to 7).
    v64 gk[5][5];
    clear(gk);
    for (size_t i = 0; i < 4; ++i) lane(gk, i) = lane(x, i);
    lane(gk, 4) = lc_.template vbit<64>(3 | (0x06 << 8));
    lane(gk, 8) = lc_.template vbit<64>(uint64_t{0x80} << 56);
    sha3_.keccak_f_1600(gk, *w.keccak[block++]);
    // PRF(sigma', N), N = 0 to 5, gives s' and e'; t' = A_v s' + e'.
    std::vector<EltW> t;
    if (dispute_node_t(st_)) {
      std::vector<EltW> node_prf = prfs(gk, 2 * Lattice::kK, w, block);
      t = lattice_.node_key(p.lattice, p.node, w.node, node_prf);
    }
    // sk_X' is bytes 64 to 95 of SHAKE256's output.
    BitW sk[X25519::kSkBits];
    for (size_t i = 0; i < X25519::kSkBits; ++i) sk[i] = bit(x, 512 + i);
    EltW pk_x = x25519_.public_key(sk, w.node_ladder, w.node_inv);

    // pk' = (t', rho', pk_X') differs from pk_v at the selected place: the
    // difference there has an inverse. If rho' differs from pk_v's seed,
    // then so does pk', whatever t' the matrix A_v gives; if it does not,
    // A_v is the matrix of pk', and t' its t. The short statement selects
    // among rho' and pk_X' alone.
    const size_t places = w.sel.size();
    for (const EltW& s : w.sel) lc_.assert_is_bit(s);
    lc_.assert_eq(lc_.add(0, places, [&](size_t i) { return w.sel[i]; }),
                  lc_.konst(1));
    EltW diff = lc_.add(0, kBits, [&](size_t i) {
      return lc_.mul(w.sel[i], lc_.sub(lc_.eval(bit(gk, i)), p.seed_v[i]));
    });
    if (!t.empty()) {
      diff = lc_.add(diff, lc_.add(0, t.size(), [&](size_t l) {
        return lc_.mul(w.sel[kBits + l], lc_.sub(t[l], p.t_v[l]));
      }));
    }
    diff = lc_.add(diff, lc_.mul(w.sel[places - 1], lc_.sub(pk_x, p.pk_x_v)));
    lc_.assert_eq(lc_.mul(diff, w.sel_inv), lc_.konst(1));
  }

 private:
  // Lane i of a state, x + 5 y = i, and bit t of the state.
  static v64& lane(v64 a[5][5], size_t i) { return a[i % 5][i / 5]; }
  static BitW& bit(v64 a[5][5], size_t t) { return lane(a, t / 64)[t % 64]; }

  void clear(v64 a[5][5]) const {
    for (size_t i = 0; i < 25; ++i) lane(a, i) = lc_.template vbit<64>(0);
  }

  // PRF(r, N) = SHAKE256(r || N, 128) for N < count, with r in lanes 4 to
  // 7 of src: 33 bytes, rate 136. Returns their 1024 bits each.
  std::vector<EltW> prfs(v64 src[5][5], size_t count, const Witness& w,
                         size_t& block) const {
    std::vector<EltW> out;
    out.reserve(count * Lattice::kPrfBits);
    for (size_t n = 0; n < count; ++n) {
      v64 a[5][5];
      clear(a);
      for (size_t i = 0; i < 4; ++i) lane(a, i) = lane(src, 4 + i);
      lane(a, 4) = lc_.template vbit<64>(n | (uint64_t{0x1f} << 8));
      lane(a, 16) = lc_.template vbit<64>(uint64_t{0x80} << 56);
      sha3_.keccak_f_1600(a, *w.keccak[block++]);
      for (size_t t = 0; t < Lattice::kPrfBits; ++t) {
        out.push_back(lc_.eval(bit(a, t)));
      }
    }
    return out;
  }

  const LogicCircuit& lc_;
  const Field& f_;
  Statement st_;
  mutable Sha3 sha3_;
  X25519 x25519_;
  Lattice lattice_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_DISPUTE_CIRCUIT_H_
