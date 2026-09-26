// The lattice part of a City-G wrap dispute, as a Longfellow circuit over
// F_{2^255-19}: research code, not vetted for production.
//
// ML-KEM-768's arithmetic, in the normal domain, with A, t, u' and v'
// public:
//   - the key binding t = A s + e, with s and e small and of bounded norm;
//   - the decryption w = v' - s^T u', with m' = Compress_1(w);
//   - in two of the three modes, the re-encryption of m' with the noise y,
//     e1, e2 that the PRF gives: u'' = A^T y + e1 and
//     v'' = t^T y + e2 + 1665 m'. Mode kEqual checks
//     Compress_10(u'') = c1 and Compress_4(v'') = c2; mode kDiffers shows
//     that one coefficient differs from the ciphertext's, without saying
//     which.
//
// Each relation is an identity between polynomials of degree at most 510
// with small integer coefficients: the prover supplies, per coefficient,
// the quotient by q and what Compress needs, and per relation the high
// half of the product, which accounts for X^256 + 1. The circuit checks the
// identity at a point rho that the verifier draws after the prover has
// committed to the witness, as Longfellow's mdoc circuits do with their MAC
// key. Every value the circuit reads as an integer is bounded by its bits,
// so that an identity over F_p is one over the integers.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_LATTICE_CIRCUIT_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_LATTICE_CIRCUIT_H_

#include <stddef.h>
#include <stdint.h>

#include <vector>

namespace proofs {

enum class Reencryption {
  kNone,     // key binding and decryption only
  kEqual,    // the re-encryption gives the ciphertext
  kDiffers,  // it differs in some coefficient
};

template <class LogicCircuit>
class LatticeCircuit {
  using EltW = typename LogicCircuit::EltW;
  using Field = typename LogicCircuit::Field;
  using Elt = typename Field::Elt;

 public:
  static constexpr size_t kN = 256;
  static constexpr size_t kK = 3;
  static constexpr size_t kHigh = kN - 1;  // coefficients of a high half
  static constexpr size_t kPrfBits = 1024;
  static constexpr size_t kPrfs = 2 * kK + 1;
  static constexpr size_t kCoefs = (kK + 1) * kN;  // of c1, then c2
  // s and e: b0 + 2 b1 + 4 b2 - 4, in [-4, 3]; honest keys are in [-2, 2].
  static constexpr size_t kSmallBits = 3;
  // Quotients by q: sum 2^b k_b - 2048, in [-2048, 2048).
  static constexpr size_t kQuoBits = 12;
  // |s|^2 + |e|^2 <= 2047, with the slack on 11 bits.
  static constexpr size_t kNormBits = 11;
  static constexpr uint64_t kNormBound = 2047;
  // Offsets of Compress within its interval: Compress_1 (11 bits),
  // Compress_10 (2 bits) and Compress_4 (8 bits).
  static constexpr size_t kDecBits = 11, kUBits = 2, kVBits = 8;
  // Mode kDiffers: coefficients in [0, q) on 12 bits (the top one weighs
  // q - 2048 = 1281), Compress_d without its reduction modulo 2^d on 11.
  static constexpr size_t kModQBits = 12, kCompBits = 11;

  // The public inputs, which the verifier computes from rho, the public key
  // and the ciphertext. For an interval of width w on m bits, top holds
  // rho^l (w - 2^(m-1)): the weight of its top bit.
  struct Public {
    std::vector<EltW> pw;    // rho^l, l < 256
    EltW z;                  // rho^256 + 1
    EltW sum;                // sum of rho^l
    std::vector<EltW> a;     // A_ij(rho) at 3 i + j
    std::vector<EltW> t;     // t_i(rho)
    std::vector<EltW> u;     // u'_j(rho)
    EltW v;                  // v'(rho)
    // kEqual:
    std::vector<EltW> lo1;   // sum_l lo(c1_il) rho^l
    EltW lo2;                // sum_l lo(c2_l) rho^l
    std::vector<EltW> top1;  // rho^l (w(c1_il) - 2) at 256 i + l
    std::vector<EltW> top2;  // rho^l (w(c2_l) - 128)
    // kDiffers: the ciphertext's coefficients, c1 then c2.
    std::vector<EltW> c;

    template <class Next>
    void read(Next&& next, Reencryption mode) {
      auto take = [&](std::vector<EltW>& x, size_t n) {
        x.resize(n);
        for (auto& y : x) y = next();
      };
      take(pw, kN);
      z = next();
      sum = next();
      take(a, kK * kK);
      take(t, kK);
      take(u, kK);
      v = next();
      if (mode == Reencryption::kEqual) {
        take(lo1, kK);
        lo2 = next();
        take(top1, kK * kN);
        take(top2, kN);
      } else if (mode == Reencryption::kDiffers) {
        take(c, kCoefs);
      }
    }
  };

  // The witness. Bits are field elements that the circuit checks.
  struct Witness {
    std::vector<EltW> s, e;          // [j][l][b], kSmallBits each
    std::vector<EltW> norm;          // slack of the norm bound
    std::vector<EltW> k_key, h_key;  // key binding: [i][l][b], [i][l]
    std::vector<EltW> m;             // m', one bit per coefficient
    std::vector<EltW> d_dec, k_dec, h_dec;
    // kEqual: re-encryption, u then v.
    std::vector<EltW> d_u, k_u, h_u, d_v, k_v, h_v;
    // kDiffers: the re-encryption's coefficients modulo q, their quotients
    // and high halves ([i][l], u then v); a one-hot selection of the
    // coefficient that differs; Compress_d of it, before its reduction
    // modulo 2^d, with its remainder; the inverse that shows the
    // difference.
    std::vector<EltW> x_re, k_re, h_re, sel, comp, rem;
    EltW inv;

    template <class Next>
    void read(Next&& next, Reencryption mode) {
      auto take = [&](std::vector<EltW>& x, size_t n) {
        x.resize(n);
        for (auto& y : x) y = next();
      };
      take(s, kK * kN * kSmallBits);
      take(e, kK * kN * kSmallBits);
      take(norm, kNormBits);
      take(k_key, kK * kN * kQuoBits);
      take(h_key, kK * kHigh);
      take(m, kN);
      take(d_dec, kN * kDecBits);
      take(k_dec, kN * kQuoBits);
      take(h_dec, kHigh);
      if (mode == Reencryption::kEqual) {
        take(d_u, kK * kN * kUBits);
        take(k_u, kK * kN * kQuoBits);
        take(h_u, kK * kHigh);
        take(d_v, kN * kVBits);
        take(k_v, kN * kQuoBits);
        take(h_v, kHigh);
      } else if (mode == Reencryption::kDiffers) {
        take(x_re, kCoefs * kModQBits);
        take(k_re, kCoefs * kQuoBits);
        take(h_re, (kK + 1) * kHigh);
        take(sel, kCoefs);
        take(comp, kCompBits);
        take(rem, kModQBits);
        inv = next();
      }
    }
  };

  LatticeCircuit(const LogicCircuit& lc, const Field& f, Reencryption mode)
      : lc_(lc), f_(f), mode_(mode) {}

  // prf holds the 7 outputs of PRF(r', N), 1024 bits each, which the caller
  // has checked to be bits: y (N = 0, 1, 2), e1 (3, 4, 5) and e2 (6). Mode
  // kNone does not read it.
  void assert_lattice(const Public& p, const Witness& w,
                      const std::vector<EltW>& prf) const {
    for (const auto* bits :
         {&w.s, &w.e, &w.norm, &w.k_key, &w.m, &w.d_dec, &w.k_dec, &w.d_u,
          &w.k_u, &w.d_v, &w.k_v, &w.x_re, &w.k_re, &w.sel, &w.comp,
          &w.rem}) {
      for (const EltW& b : *bits) lc_.assert_is_bit(b);
    }

    // The secret polynomials, evaluated at rho.
    std::vector<EltW> s_rho(kK), e_rho(kK);
    for (size_t j = 0; j < kK; ++j) {
      s_rho[j] = eval(p, [&](size_t l) { return small(w.s, j, l); });
      e_rho[j] = eval(p, [&](size_t l) { return small(w.e, j, l); });
    }
    EltW m_rho = eval(p, [&](size_t l) { return w.m[l]; });

    // The norm bound: |s|^2 + |e|^2 + slack = 2047.
    EltW norm = packed(w.norm, 0, kNormBits);
    for (size_t j = 0; j < kK; ++j) {
      for (size_t l = 0; l < kN; ++l) {
        EltW sv = small(w.s, j, l), ev = small(w.e, j, l);
        norm = lc_.add(norm, lc_.add(lc_.mul(sv, sv), lc_.mul(ev, ev)));
      }
    }
    lc_.assert_eq(norm, lc_.konst(kNormBound));

    const Elt q = f_.of_scalar(3329);
    // Key binding: A_i s + e_i - t_i = q K_i.
    for (size_t i = 0; i < kK; ++i) {
      EltW x = reduced(p, w.h_key, i, [&](size_t j) {
        return lc_.mul(p.a[kK * i + j], s_rho[j]);
      });
      x = lc_.add(x, lc_.sub(e_rho[i], p.t[i]));
      x = lc_.sub(x, lc_.mul(q, quotient(p, w.k_key, i)));
      lc_.assert0(x);
    }

    // Decryption: v' - s^T u' = lo(m') + delta + q K, with
    // lo(m') = -832 + 1665 m' and delta in [0, 1665 - m').
    {
      EltW x = lc_.sub(p.v, reduced(p, w.h_dec, 0, [&](size_t j) {
        return lc_.mul(p.u[j], s_rho[j]);
      }));
      x = lc_.add(x, lc_.mul(f_.of_scalar(832), p.sum));
      x = lc_.sub(x, lc_.mul(f_.of_scalar(1665), m_rho));
      EltW delta = eval(p, [&](size_t l) {
        const EltW& d_top = w.d_dec[kDecBits * l + kDecBits - 1];
        EltW low = packed(w.d_dec, kDecBits * l, kDecBits - 1);
        // (641 - m') d_top: 1024 + 641 - m' = 1665 - m'.
        EltW top = lc_.sub(lc_.mul(f_.of_scalar(641), d_top),
                           lc_.mul(w.m[l], d_top));
        return lc_.add(low, top);
      });
      x = lc_.sub(x, delta);
      x = lc_.sub(x, lc_.mul(q, quotient(p, w.k_dec, 0)));
      lc_.assert0(x);
    }

    if (mode_ == Reencryption::kNone) return;

    // The re-encryption: (A^T y)_i + e1_i for i < 3, t^T y + e2 + 1665 m'
    // for i = 3, as values the modes then compare to the ciphertext.
    std::vector<EltW> y_rho(kK);
    for (size_t j = 0; j < kK; ++j) {
      y_rho[j] = eval(p, [&](size_t l) { return cbd(prf, j, l); });
    }
    // Its high half is polynomial hi of h.
    auto reencryption = [&](size_t i, const std::vector<EltW>& h,
                            size_t hi) {
      if (i < kK) {
        EltW e1 = eval(p, [&](size_t l) { return cbd(prf, kK + i, l); });
        EltW x = reduced(p, h, hi, [&](size_t j) {
          return lc_.mul(p.a[kK * j + i], y_rho[j]);
        });
        return lc_.add(x, e1);
      }
      EltW e2 = eval(p, [&](size_t l) { return cbd(prf, 2 * kK, l); });
      EltW x = reduced(p, h, hi, [&](size_t j) {
        return lc_.mul(p.t[j], y_rho[j]);
      });
      return lc_.add(lc_.add(x, e2), lc_.mul(f_.of_scalar(1665), m_rho));
    };

    if (mode_ == Reencryption::kEqual) {
      // Compress_10(u''_i) = c1_i: u''_i = lo(c1_i) + delta + q K.
      for (size_t i = 0; i < kK; ++i) {
        EltW x = lc_.sub(reencryption(i, w.h_u, i), p.lo1[i]);
        EltW delta = lc_.add(0, kN, [&](size_t l) {
          const EltW* d = &w.d_u[kUBits * (kN * i + l)];
          return lc_.add(lc_.mul(p.pw[l], d[0]),
                         lc_.mul(p.top1[kN * i + l], d[1]));
        });
        x = lc_.sub(x, delta);
        x = lc_.sub(x, lc_.mul(q, quotient(p, w.k_u, i)));
        lc_.assert0(x);
      }
      // Compress_4(v'') = c2, likewise.
      {
        EltW x = lc_.sub(reencryption(kK, w.h_v, 0), p.lo2);
        EltW delta = lc_.add(0, kN, [&](size_t l) {
          EltW low = lc_.mul(p.pw[l], packed(w.d_v, kVBits * l, kVBits - 1));
          return lc_.add(low,
                         lc_.mul(p.top2[l], w.d_v[kVBits * l + kVBits - 1]));
        });
        x = lc_.sub(x, delta);
        x = lc_.sub(x, lc_.mul(q, quotient(p, w.k_v, 0)));
        lc_.assert0(x);
      }
      return;
    }

    // kDiffers. The coefficients x_il of the re-encryption modulo q:
    // u''_i = X_i + q K_i and v'' = X_3 + q K_3.
    for (size_t i = 0; i <= kK; ++i) {
      EltW x = reencryption(i, w.h_re, i);
      x = lc_.sub(x, eval(p, [&](size_t l) { return mod_q(w.x_re, i, l); }));
      x = lc_.sub(x, lc_.mul(q, quotient(p, w.k_re, i)));
      lc_.assert0(x);
    }
    // One coefficient is selected: xu from u'' (d = 10) or xv from v''
    // (d = 4), and cs from the ciphertext.
    lc_.assert_eq(lc_.add(0, kCoefs, [&](size_t k) { return w.sel[k]; }),
                  lc_.konst(1));
    EltW xu = lc_.add(0, kK * kN, [&](size_t k) {
      return lc_.mul(w.sel[k], mod_q(w.x_re, k / kN, k % kN));
    });
    EltW xv = lc_.add(0, kN, [&](size_t l) {
      return lc_.mul(w.sel[kK * kN + l], mod_q(w.x_re, kK, l));
    });
    EltW in_v = lc_.add(0, kN, [&](size_t l) { return w.sel[kK * kN + l]; });
    EltW cs = lc_.add(0, kCoefs,
                      [&](size_t k) { return lc_.mul(w.sel[k], p.c[k]); });
    // Compress_d without its reduction: 2^d x + 1664 = comp q + rem, with
    // rem in [0, q), and 2^d x = 1024 xu + 16 xv.
    EltW comp = packed(w.comp, 0, kCompBits);
    EltW lhs = lc_.add(lc_.mul(f_.of_scalar(1024), xu),
                       lc_.mul(f_.of_scalar(16), xv));
    lhs = lc_.add(lhs, lc_.konst(1664));
    lc_.assert_eq(lhs, lc_.add(lc_.mul(q, comp), mod_q_value(w.rem, 0)));
    // Compress_d(x) = comp mod 2^d differs from cs: comp - cs is neither 0
    // nor 2^d, with 2^d = 1024 - 1008 in_v.
    EltW diff = lc_.sub(comp, cs);
    EltW two_d = lc_.sub(lc_.konst(1024), lc_.mul(f_.of_scalar(1008), in_v));
    EltW prod = lc_.mul(diff, lc_.sub(diff, two_d));
    lc_.assert_eq(lc_.mul(prod, w.inv), lc_.konst(1));
  }

 private:
  // sum_l rho^l f(l).
  template <class F>
  EltW eval(const Public& p, F&& f) const {
    return lc_.add(0, kN, [&](size_t l) { return lc_.mul(p.pw[l], f(l)); });
  }

  // sum_b 2^b bits[i0 + b] for b < n.
  EltW packed(const std::vector<EltW>& bits, size_t i0, size_t n) const {
    EltW r = lc_.konst(f_.zero());
    Elt two_b = f_.one();
    for (size_t b = 0; b < n; ++b) {
      r = lc_.axpy(r, two_b, bits[i0 + b]);
      f_.add(two_b, two_b);
    }
    return r;
  }

  // Coefficient l of polynomial j of s or e: b0 + 2 b1 + 4 b2 - 4.
  EltW small(const std::vector<EltW>& bits, size_t j, size_t l) const {
    EltW x = packed(bits, kSmallBits * (kN * j + l), kSmallBits);
    return lc_.sub(x, lc_.konst(4));
  }

  // Coefficient l of CBD_2 on PRF output n: bits 4l + 0, 1 minus 4l + 2, 3.
  EltW cbd(const std::vector<EltW>& prf, size_t n, size_t l) const {
    const EltW* b = &prf[kPrfBits * n + 4 * l];
    return lc_.sub(lc_.add(b[0], b[1]), lc_.add(b[2], b[3]));
  }

  // A value in [0, q) from 12 bits at i0: the top one weighs 1281.
  EltW mod_q_value(const std::vector<EltW>& bits, size_t i0) const {
    EltW low = packed(bits, i0, kModQBits - 1);
    return lc_.add(low, lc_.mul(f_.of_scalar(1281), bits[i0 + kModQBits - 1]));
  }

  EltW mod_q(const std::vector<EltW>& bits, size_t i, size_t l) const {
    return mod_q_value(bits, kModQBits * (kN * i + l));
  }

  // K_i(rho), for quotients on kQuoBits bits.
  EltW quotient(const Public& p, const std::vector<EltW>& bits,
                size_t i) const {
    EltW k = eval(p, [&](size_t l) {
      return packed(bits, kQuoBits * (kN * i + l), kQuoBits);
    });
    return lc_.sub(k, lc_.mul(f_.of_scalar(2048), p.sum));
  }

  // A sum of three products, sum_j f(j), reduced modulo X^256 + 1 at rho:
  // minus (rho^256 + 1) H_i(rho), where H_i is the high half of the sum.
  template <class F>
  EltW reduced(const Public& p, const std::vector<EltW>& h, size_t i,
               F&& f) const {
    EltW prod = lc_.add(0, kK, f);
    EltW hr = lc_.add(0, kHigh, [&](size_t l) {
      return lc_.mul(p.pw[l], h[kHigh * i + l]);
    });
    return lc_.sub(prod, lc_.mul(p.z, hr));
  }

  const LogicCircuit& lc_;
  const Field& f_;
  Reencryption mode_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_LATTICE_CIRCUIT_H_
