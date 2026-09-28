// The X25519 half of a City-G wrap dispute, as a Longfellow circuit over
// F_{2^255-19}: research code, not vetted for production.
//
// From the 256 bits of sk_X, the circuit checks pk_X = X25519(sk_X, 9)
// against the public key and returns ss_X = X25519(sk_X, u) as 255
// canonical bits for the SHA3-256 combiner; for branch 2 of a dispute,
// public_key computes X25519(sk, 9) from bits that the rest of the circuit
// gives. The Montgomery ladders of RFC 7748 take the state after each step
// as a witness, so that each step is checked on its own and the circuit
// stays shallow, as the ECDSA circuit of Longfellow does with its
// intermediate points.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_X25519_CIRCUIT_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_X25519_CIRCUIT_H_

#include <stddef.h>

namespace proofs {

template <class LogicCircuit, class Field>
class X25519Circuit {
  using EltW = typename LogicCircuit::EltW;
  using BitW = typename LogicCircuit::BitW;
  using Elt = typename Field::Elt;
  using Nat = typename Field::N;

 public:
  static constexpr size_t kSteps = 255;   // steps t = 254 down to 0
  static constexpr size_t kSkBits = 256;  // sk_X, least significant first
  static constexpr size_t kSsBits = 255;  // ss_X, least significant first

  // The state (x_2, z_2, x_3, z_3) after step t, at index t.
  struct Ladder {
    EltW x2[kSteps], z2[kSteps], x3[kSteps], z3[kSteps];

    void input(const LogicCircuit& lc) {
      for (size_t t = 0; t < kSteps; ++t) {
        x2[t] = lc.eltw_input();
        z2[t] = lc.eltw_input();
        x3[t] = lc.eltw_input();
        z3[t] = lc.eltw_input();
      }
    }
  };

  struct Witness {
    EltW sk[kSkBits];
    Ladder pk_ladder, ss_ladder;
    EltW inv;  // z_2^(p-2) at the end of the ladder of ss_X
    EltW ss[kSsBits];

    void input(const LogicCircuit& lc) {
      for (size_t i = 0; i < kSkBits; ++i) sk[i] = lc.eltw_input();
      pk_ladder.input(lc);
      ss_ladder.input(lc);
      inv = lc.eltw_input();
      for (size_t i = 0; i < kSsBits; ++i) ss[i] = lc.eltw_input();
    }
  };

  X25519Circuit(const LogicCircuit& lc, const Field& f) : lc_(lc), f_(f) {}

  // pk = X25519(sk, 9), and w.ss holds the canonical bits of X25519(sk, u).
  void assert_dispute(const EltW& pk, const EltW& u, const Witness& w) const {
    BitW sk[kSkBits], swap[kSteps];
    for (size_t i = 0; i < kSkBits; ++i) {
      lc_.assert_is_bit(w.sk[i]);
      sk[i] = BitW(w.sk[i], f_);
    }
    swaps(sk, swap);

    EltW x2, z2;
    ladder(/*x1_const=*/true, f_.of_scalar(9), u, swap, w.pk_ladder, x2, z2);
    lc_.assert_eq(x2, lc_.mul(pk, z2));

    ladder(/*x1_const=*/false, f_.zero(), u, swap, w.ss_ladder, x2, z2);
    // ss = x_2 z_2^(p-2), which is 0 when z_2 is 0, as in RFC 7748.
    EltW t = lc_.mul(z2, w.inv);
    EltW one_minus_t = lc_.sub(lc_.konst(f_.one()), t);
    lc_.assert0(lc_.mul(z2, one_minus_t));
    lc_.assert0(lc_.mul(w.inv, one_minus_t));
    EltW ss = lc_.mul(x2, w.inv);

    // The bits of ss, canonical: below p = 2^255 - 19.
    BitW b[kSsBits], p_bits[kSsBits];
    Elt two_i = f_.one();
    EltW sum = lc_.konst(f_.zero());
    const Nat& p = f_.m_;
    for (size_t i = 0; i < kSsBits; ++i) {
      lc_.assert_is_bit(w.ss[i]);
      b[i] = BitW(w.ss[i], f_);
      p_bits[i] = lc_.bit(p.bit(i));
      sum = lc_.add(sum, lc_.mul(two_i, w.ss[i]));
      f_.add(two_i, two_i);
    }
    lc_.assert_eq(sum, ss);
    lc_.assert1(lc_.lt(kSsBits, b, p_bits));
  }

  // X25519(sk, 9) as a field element, from the 256 bits of sk, which the
  // caller has checked, with the ladder's states and the inverse of its
  // last z_2 as witnesses. A clamped scalar is never a multiple of l, so
  // that z_2 is never 0.
  EltW public_key(const BitW sk[kSkBits], const Ladder& w,
                  const EltW& inv) const {
    BitW swap[kSteps];
    swaps(sk, swap);
    EltW x2, z2;
    ladder(/*x1_const=*/true, f_.of_scalar(9), lc_.konst(f_.zero()), swap, w,
           x2, z2);
    lc_.assert_eq(lc_.mul(z2, inv), lc_.konst(f_.one()));
    return lc_.mul(x2, inv);
  }

 private:
  // Clamping (bits 0 to 2 and 255 are 0, bit 254 is 1), then the swap
  // bits: the ladder swaps at step t when k_{t+1} xor k_t is 1, and at the
  // end when k_0 is, which clamping rules out.
  void swaps(const BitW sk[kSkBits], BitW swap[kSteps]) const {
    BitW k[kSkBits];
    for (size_t i = 0; i < kSkBits; ++i) {
      k[i] = (i >= 3 && i <= 253) ? sk[i] : lc_.bit(i == 254 ? 1 : 0);
    }
    for (size_t t = 0; t < kSteps; ++t) swap[t] = lc_.lxor(k[t + 1], k[t]);
  }

  // Swap a and b when s is 1: one multiplication.
  void cswap(const BitW& s, EltW& a, EltW& b) const {
    EltW d = lc_.lmul(s, lc_.sub(b, a));
    a = lc_.add(a, d);
    b = lc_.sub(b, d);
  }

  // RFC 7748's ladder from x_1, a constant or a public wire.
  void ladder(bool x1_const, const Elt& x1k, const EltW& x1w,
              const BitW swap[], const Ladder& w, EltW& x2o,
              EltW& z2o) const {
    const Elt a24 = f_.of_scalar(121665);
    EltW x2 = lc_.konst(f_.one()), z2 = lc_.konst(f_.zero());
    EltW x3 = x1_const ? lc_.konst(x1k) : x1w, z3 = lc_.konst(f_.one());
    for (size_t i = 0; i < kSteps; ++i) {
      size_t t = kSteps - 1 - i;
      cswap(swap[t], x2, x3);
      cswap(swap[t], z2, z3);
      EltW a = lc_.add(x2, z2), b = lc_.sub(x2, z2);
      EltW aa = lc_.mul(a, a), bb = lc_.mul(b, b);
      EltW e = lc_.sub(aa, bb);
      EltW c = lc_.add(x3, z3), d = lc_.sub(x3, z3);
      EltW da = lc_.mul(d, a), cb = lc_.mul(c, b);
      EltW sum = lc_.add(da, cb), diff = lc_.sub(da, cb);
      EltW dd = lc_.mul(diff, diff);
      lc_.assert_eq(lc_.mul(sum, sum), w.x3[t]);
      lc_.assert_eq(x1_const ? lc_.mul(x1k, dd) : lc_.mul(x1w, dd), w.z3[t]);
      lc_.assert_eq(lc_.mul(aa, bb), w.x2[t]);
      lc_.assert_eq(lc_.mul(e, lc_.add(aa, lc_.mul(a24, e))), w.z2[t]);
      x2 = w.x2[t];
      z2 = w.z2[t];
      x3 = w.x3[t];
      z3 = w.z3[t];
    }
    x2o = x2;
    z2o = z2;
  }

  const LogicCircuit& lc_;
  const Field& f_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_X25519_CIRCUIT_H_
