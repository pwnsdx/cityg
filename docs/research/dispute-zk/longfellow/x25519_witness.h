// The witness of X25519Circuit: the two ladders of RFC 7748, computed in
// the clear with the same formulas. Research code.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_X25519_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_X25519_WITNESS_H_

#include <stddef.h>
#include <stdint.h>

#include <utility>

#include "arrays/dense.h"

namespace proofs {

template <class Field>
class X25519Witness {
  using Elt = typename Field::Elt;
  using Nat = typename Field::N;

 public:
  static constexpr size_t kSteps = 255;

  struct Ladder {
    Elt x2[kSteps], z2[kSteps], x3[kSteps], z3[kSteps];
  };

  explicit X25519Witness(const Field& f) : f_(f) {}

  // Returns false if ct is not a canonical u-coordinate, which no honest
  // encapsulation gives.
  bool compute(const uint8_t sk[32], const uint8_t ct[32]) {
    Nat un = Nat::of_bytes(ct);
    if (!(un < f_.m_)) return false;
    u_ = f_.to_montgomery(un);
    for (size_t i = 0; i < 256; ++i) {
      sk_[i] = (sk[i / 8] >> (i % 8)) & 1;
    }
    unsigned k[256];
    for (size_t i = 0; i < 256; ++i) k[i] = sk_[i];
    k[0] = k[1] = k[2] = 0;
    k[254] = 1;
    k[255] = 0;
    for (size_t t = 0; t < kSteps; ++t) swap_[t] = k[t + 1] ^ k[t];

    Elt x2, z2;
    ladder(f_.of_scalar(9), pk_ladder_, x2, z2);
    pk_ = f_.mulf(x2, f_.invertf(z2));

    ladder(u_, ss_ladder_, x2, z2);
    inv_ = (z2 == f_.zero()) ? f_.zero() : f_.invertf(z2);
    ss_ = f_.mulf(x2, inv_);
    Nat ssn = f_.from_montgomery(ss_);
    for (size_t i = 0; i < 255; ++i) ss_bits_[i] = ssn.bit(i);
    return true;
  }

  // The public inputs, in the order of the circuit: pk, then u.
  void fill_public(DenseFiller<Field>& filler) const {
    filler.push_back(pk_);
    filler.push_back(u_);
  }

  // The private inputs, in the order of X25519Circuit::Witness::input().
  void fill_witness(DenseFiller<Field>& filler) const {
    for (size_t i = 0; i < 256; ++i) filler.push_back(f_.of_scalar(sk_[i]));
    fill_ladder(filler, pk_ladder_);
    fill_ladder(filler, ss_ladder_);
    filler.push_back(inv_);
    for (size_t i = 0; i < 255; ++i) {
      filler.push_back(f_.of_scalar(ss_bits_[i]));
    }
  }

  // The little-endian encodings of pk_X and ss_X.
  void pk_bytes(uint8_t out[32]) const { f_.to_bytes_field(out, pk_); }
  void ss_bytes(uint8_t out[32]) const { f_.to_bytes_field(out, ss_); }

  Elt pk_, u_, ss_, inv_;
  unsigned sk_[256], ss_bits_[255], swap_[kSteps];
  Ladder pk_ladder_, ss_ladder_;

 private:
  void ladder(const Elt& x1, Ladder& w, Elt& x2o, Elt& z2o) const {
    const Elt a24 = f_.of_scalar(121665);
    Elt x2 = f_.one(), z2 = f_.zero(), x3 = x1, z3 = f_.one();
    for (size_t i = 0; i < kSteps; ++i) {
      size_t t = kSteps - 1 - i;
      if (swap_[t]) {
        std::swap(x2, x3);
        std::swap(z2, z3);
      }
      Elt a = f_.addf(x2, z2), b = f_.subf(x2, z2);
      Elt aa = f_.mulf(a, a), bb = f_.mulf(b, b);
      Elt e = f_.subf(aa, bb);
      Elt c = f_.addf(x3, z3), d = f_.subf(x3, z3);
      Elt da = f_.mulf(d, a), cb = f_.mulf(c, b);
      Elt sum = f_.addf(da, cb), diff = f_.subf(da, cb);
      x3 = f_.mulf(sum, sum);
      z3 = f_.mulf(x1, f_.mulf(diff, diff));
      x2 = f_.mulf(aa, bb);
      z2 = f_.mulf(e, f_.addf(aa, f_.mulf(a24, e)));
      w.x2[t] = x2;
      w.z2[t] = z2;
      w.x3[t] = x3;
      w.z3[t] = z3;
    }
    x2o = x2;
    z2o = z2;
  }

  void fill_ladder(DenseFiller<Field>& filler, const Ladder& w) const {
    for (size_t t = 0; t < kSteps; ++t) {
      filler.push_back(w.x2[t]);
      filler.push_back(w.z2[t]);
      filler.push_back(w.x3[t]);
      filler.push_back(w.z3[t]);
    }
  }

  const Field& f_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_X25519_WITNESS_H_
