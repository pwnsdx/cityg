// The public check of ct_X that the verifier of a wrap dispute runs before
// any proof (litige-x25519-2026-09-26.md, section 3.3). An honest
// encapsulation, X25519(ek, 9), gives the canonical u-coordinate of a point
// of prime order l; any other ct_X convicts the committer without a proof.
// On that subgroup, X25519(sk_X, ct_X) depends only on sk_X modulo l, up to
// its sign, which pk_X fixes. Research code.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_X25519_CHECK_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_X25519_CHECK_H_

#include <stdint.h>

#include <utility>

namespace proofs {

// l = 2^252 + 27742317777372353535851937790883648493, little-endian.
constexpr uint8_t kX25519Order[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
    0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

// True when ct_X is the canonical u-coordinate of a point of order l.
// RFC 7748's ladder, run with the scalar l unclamped, ends with z = 0
// exactly when l P = O: on the curve, P then has order l; a point of the
// twist, whose order is prime to l, never gets there. u = 0, the point of
// order 2, would make the ladder's differential addition degenerate.
template <class Field>
bool ct_x_in_prime_subgroup(const Field& f, const uint8_t ct_x[32]) {
  using Elt = typename Field::Elt;
  using Nat = typename Field::N;
  const Nat un = Nat::of_bytes(ct_x);
  if (!(un < f.m_)) return false;  // not canonical, or bit 255 set
  const Elt x1 = f.to_montgomery(un);
  if (x1 == f.zero()) return false;
  const Elt a24 = f.of_scalar(121665);
  Elt x2 = f.one(), z2 = f.zero(), x3 = x1, z3 = f.one();
  unsigned swap = 0;
  for (int t = 254; t >= 0; --t) {
    unsigned k = (kX25519Order[t / 8] >> (t % 8)) & 1;
    if (swap ^ k) {
      std::swap(x2, x3);
      std::swap(z2, z3);
    }
    swap = k;
    Elt a = f.addf(x2, z2), b = f.subf(x2, z2);
    Elt aa = f.mulf(a, a), bb = f.mulf(b, b), e = f.subf(aa, bb);
    Elt c = f.addf(x3, z3), d = f.subf(x3, z3);
    Elt da = f.mulf(d, a), cb = f.mulf(c, b);
    Elt sum = f.addf(da, cb), diff = f.subf(da, cb);
    x3 = f.mulf(sum, sum);
    z3 = f.mulf(x1, f.mulf(diff, diff));
    x2 = f.mulf(aa, bb);
    z2 = f.mulf(e, f.addf(aa, f.mulf(a24, e)));
  }
  if (swap) std::swap(z2, z3);
  return z2 == f.zero();
}

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_X25519_CHECK_H_
