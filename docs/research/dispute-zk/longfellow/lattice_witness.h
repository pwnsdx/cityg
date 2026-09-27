// The witness and the public inputs of LatticeCircuit, computed with exact
// integer arithmetic from the reference decapsulation. Research code.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_LATTICE_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_LATTICE_WITNESS_H_

#include <stddef.h>
#include <stdint.h>

#include <array>
#include <cstdint>
#include <vector>

#include "arrays/dense.h"
#include "circuits/tests/x25519/lattice_circuit.h"
#include "circuits/tests/x25519/mlkem_reference.h"

namespace proofs {

// The integers x with Compress_d(x mod q) = c are lo, ..., lo + w - 1
// modulo q. Only c = 0 wraps around q, which a negative lo expresses.
struct CompressInterval {
  int32_t lo, w;
};

inline CompressInterval scan_interval(int32_t c, int d) {
  using mlkem::compress;
  using mlkem::kQ;
  CompressInterval r{0, 0};
  bool found = false;
  for (int32_t x = 0; x < kQ; ++x) {
    if (compress(x, d) != c) continue;
    ++r.w;
    if (c == 0 && x > kQ / 2) {
      --r.lo;  // counts the values below q that wrap to 0
    } else if (!found) {
      if (c != 0) r.lo = x;
      found = true;
    }
  }
  return r;
}

// For d = 1, 4 and 10, tabulated.
inline CompressInterval compress_interval(int32_t c, int d) {
  static const std::vector<std::vector<CompressInterval>> tables = [] {
    std::vector<std::vector<CompressInterval>> t(11);
    for (int dd : {1, 4, 10}) {
      for (int32_t cc = 0; cc < (1 << dd); ++cc) {
        t[dd].push_back(scan_interval(cc, dd));
      }
    }
    return t;
  }();
  return tables[d][c];
}

// The public data of a dispute's lattice part, as the verifier derives it
// from the public key and the ciphertext.
struct LatticeStatement {
  mlkem::Matrix a;    // A = NTT^-1(A_hat), a[i][j]
  mlkem::PolyVec t;   // NTT^-1(t_hat)
  mlkem::PolyVec c1;  // the Compress_10 values of the ciphertext
  mlkem::Poly c2;     // its Compress_4 values
  mlkem::PolyVec u;   // Decompress_10(c1)
  mlkem::Poly v;      // Decompress_4(c2)

  LatticeStatement(const uint8_t ek[mlkem::kEkBytes],
                   const uint8_t c[mlkem::kCtBytes]) {
    using namespace mlkem;
    PublicKey pk = parse_ek(ek);
    for (size_t i = 0; i < kK; ++i) {
      t[i] = intt(pk.t_hat[i]);
      for (size_t j = 0; j < kK; ++j) a[i][j] = intt(pk.a_hat[i][j]);
      c1[i] = byte_decode(c + 32 * kDu * i, kDu);
      for (size_t l = 0; l < kN; ++l) u[i][l] = decompress(c1[i][l], kDu);
    }
    c2 = byte_decode(c + 32 * kDu * kK, kDv);
    for (size_t l = 0; l < kN; ++l) v[l] = decompress(c2[l], kDv);
  }
};

template <class Field>
class LatticeWitness {
  using Elt = typename Field::Elt;
  using Poly = mlkem::Poly;
  static constexpr size_t kN = mlkem::kN, kK = mlkem::kK;
  static constexpr int32_t kQ = mlkem::kQ;
  using Wide = std::array<int64_t, 2 * kN - 1>;

 public:
  explicit LatticeWitness(const Field& f) : f_(f) {}

  // From the secret key (s, e) and the decapsulation of the statement's
  // ciphertext. Returns false when a value falls out of the range its bits
  // cover, or when the re-encryption does not do what the mode says. In
  // mode kDiffers, tests may force the selected coefficient.
  bool compute(const LatticeStatement& st, const mlkem::PolyVec& s,
               const mlkem::PolyVec& e, const mlkem::Decapsulation& d,
               Reencryption mode, size_t force_sel = SIZE_MAX) {
    values_.clear();
    out_ = &values_;
    ok_ = true;
    for (const auto* v : {&s, &e}) {
      for (size_t j = 0; j < kK; ++j) {
        for (size_t l = 0; l < kN; ++l) push_bits((*v)[j][l] + 4, 3);
      }
    }
    for (const auto* v : {&s, &e}) {
      int64_t norm = 0;
      for (size_t j = 0; j < kK; ++j) {
        for (size_t l = 0; l < kN; ++l) {
          norm += int64_t{(*v)[j][l]} * (*v)[j][l];
        }
      }
      push_bits(1100 - norm, 11);
    }

    // Key binding.
    std::vector<std::vector<int64_t>> k(kK), h(kK);
    for (size_t i = 0; i < kK; ++i) {
      Wide acc{};
      for (size_t j = 0; j < kK; ++j) mul_add(acc, st.a[i][j], s[j]);
      std::vector<int64_t> x = negacyclic(acc);
      for (size_t l = 0; l < kN; ++l) {
        x[l] += e[i][l] - st.t[i][l];
        if (x[l] % kQ != 0) ok_ = false;
        k[i].push_back(x[l] / kQ);
      }
      h[i] = high(acc);
    }
    for (size_t i = 0; i < kK; ++i) {
      for (int64_t ki : k[i]) push_bits(ki + 2048, 12);
    }
    for (size_t i = 0; i < kK; ++i) push_high(h[i]);

    // Decryption.
    {
      Wide acc{};
      for (size_t j = 0; j < kK; ++j) mul_add(acc, st.u[j], s[j]);
      std::vector<int64_t> x = negacyclic(acc);
      std::vector<int32_t> m(kN);
      std::vector<int64_t> delta(kN), kq(kN);
      for (size_t l = 0; l < kN; ++l) {
        x[l] = st.v[l] - x[l];
        int32_t w = mlkem::mod_q(x[l]);
        m[l] = mlkem::compress(w, 1);
        if (m[l] != ((d.de.m[l / 8] >> (l % 8)) & 1)) ok_ = false;
        CompressInterval iv = compress_interval(m[l], 1);
        delta[l] = mlkem::mod_q(w - iv.lo);
        kq[l] = (x[l] - iv.lo - delta[l]) / kQ;
      }
      for (size_t l = 0; l < kN; ++l) push_bits(m[l], 1);
      for (size_t l = 0; l < kN; ++l) push_split(delta[l], 11, 641 - m[l]);
      for (size_t l = 0; l < kN; ++l) push_bits(kq[l] + 2048, 12);
      push_high(high(acc));
      m_ = m;
    }

    // The re-encryption, exactly: u''_i for i < 3, then v''; its values
    // modulo q, and the ciphertext's values and Compress parameter.
    std::vector<std::vector<int64_t>> re(kK + 1), hre(kK + 1);
    std::vector<std::vector<int32_t>> xr(kK + 1), cv(kK + 1);
    std::vector<int> dv(kK + 1);
    for (size_t i = 0; i <= kK; ++i) {
      Wide acc{};
      for (size_t j = 0; j < kK; ++j) {
        mul_add(acc, i < kK ? st.a[j][i] : st.t[j], d.re.y[j]);
      }
      re[i] = negacyclic(acc);
      hre[i] = high(acc);
      dv[i] = i < kK ? mlkem::kDu : mlkem::kDv;
      for (size_t l = 0; l < kN; ++l) {
        re[i][l] += i < kK ? d.re.e1[i][l] : d.re.e2[l] + 1665 * m_[l];
        xr[i].push_back(mlkem::mod_q(re[i][l]));
        cv[i].push_back(i < kK ? st.c1[i][l] : st.c2[l]);
        if (xr[i][l] != (i < kK ? d.re.u[i][l] : d.re.v[l])) ok_ = false;
      }
    }

    if (mode == Reencryption::kEqual) {
      // Each value lo(c) + delta + q K, delta in [0, w(c)): per part, the
      // offsets, then the quotients, then the high halves.
      for (size_t part = 0; part < 2; ++part) {
        size_t i0 = part == 0 ? 0 : kK, i1 = part == 0 ? kK : kK + 1;
        std::vector<int64_t> kq;
        for (size_t i = i0; i < i1; ++i) {
          for (size_t l = 0; l < kN; ++l) {
            if (mlkem::compress(xr[i][l], dv[i]) != cv[i][l]) ok_ = false;
            CompressInterval iv = compress_interval(cv[i][l], dv[i]);
            int64_t delta = mlkem::mod_q(xr[i][l] - iv.lo);
            size_t n = i < kK ? 2 : 8;
            push_split(delta, n, iv.w - (int64_t{1} << (n - 1)));
            kq.push_back((re[i][l] - iv.lo - delta) / kQ);
          }
        }
        for (int64_t kv : kq) push_bits(kv + 2048, 12);
        for (size_t i = i0; i < i1; ++i) push_high(hre[i]);
      }
    } else if (mode == Reencryption::kDiffers) {
      // The values modulo q, their quotients, the high halves.
      for (size_t i = 0; i <= kK; ++i) {
        for (int32_t x : xr[i]) push_split(x, 12, kQ - 2048);
      }
      for (size_t i = 0; i <= kK; ++i) {
        for (size_t l = 0; l < kN; ++l) {
          push_bits((re[i][l] - xr[i][l]) / kQ + 2048, 12);
        }
      }
      for (size_t i = 0; i <= kK; ++i) push_high(hre[i]);
      // The first coefficient that differs, as a one-hot selection.
      size_t sel = SIZE_MAX;
      for (size_t k = 0; k < (kK + 1) * kN && sel == SIZE_MAX; ++k) {
        size_t i = k / kN, l = k % kN;
        if (mlkem::compress(xr[i][l], dv[i]) != cv[i][l]) sel = k;
      }
      if (force_sel != SIZE_MAX) sel = force_sel;
      if (sel == SIZE_MAX) return false;
      for (size_t k = 0; k < (kK + 1) * kN; ++k) push_bits(k == sel, 1);
      size_t i = sel / kN, l = sel % kN;
      int64_t two_d = int64_t{1} << dv[i];
      int64_t num = two_d * xr[i][l] + 1664;
      int64_t comp = num / kQ, diff = comp - cv[i][l];
      push_bits(comp, 11);
      push_split(num % kQ, 12, kQ - 2048);
      Elt prod = f_.mulf(of_int(diff, f_), of_int(diff - two_d, f_));
      if (prod == f_.zero()) ok_ = false;
      out_->push_back(prod == f_.zero() ? prod : f_.invertf(prod));
    }

    // The PRF outputs, as bits, for the circuit that takes them as inputs.
    prf_bits_.clear();
    for (size_t n = 0; n < 2 * kK + 1; ++n) {
      for (size_t b = 0; b < 8 * mlkem::kPrfBytes; ++b) {
        prf_bits_.push_back((d.re.prf[n][b / 8] >> (b % 8)) & 1);
      }
    }
    return ok_;
  }

  // Branch 2: the witness of t' = A_v s' + e' (mod q), in the order of
  // LatticeCircuit::NodeWitness::read; node_t() gets t''s coefficients.
  bool compute_node(const mlkem::Matrix& a_v, const mlkem::PolyVec& s2,
                    const mlkem::PolyVec& e2) {
    std::vector<Elt>* saved = out_;
    node_values_.clear();
    out_ = &node_values_;
    ok_ = true;
    node_t_.clear();
    std::vector<std::vector<int64_t>> x(kK), h(kK);
    for (size_t i = 0; i < kK; ++i) {
      Wide acc{};
      for (size_t j = 0; j < kK; ++j) mul_add(acc, a_v[i][j], s2[j]);
      x[i] = negacyclic(acc);
      h[i] = high(acc);
      for (size_t l = 0; l < kN; ++l) {
        x[i][l] += e2[i][l];
        node_t_.push_back(mlkem::mod_q(x[i][l]));
      }
    }
    for (size_t i = 0; i < kK; ++i) {
      for (size_t l = 0; l < kN; ++l) {
        push_split(node_t_[kN * i + l], 12, kQ - 2048);
      }
    }
    for (size_t i = 0; i < kK; ++i) {
      for (size_t l = 0; l < kN; ++l) {
        push_bits((x[i][l] - node_t_[kN * i + l]) / kQ + 2048, 12);
      }
    }
    for (size_t i = 0; i < kK; ++i) push_high(h[i]);
    out_ = saved;
    return ok_;
  }

  void fill_node(DenseFiller<Field>& filler) const {
    for (const Elt& x : node_values_) filler.push_back(x);
  }

  const std::vector<int32_t>& node_t() const { return node_t_; }

  // A_v(rho), the public inputs of LatticeCircuit::NodePublic.
  static std::vector<Elt> node_public(const mlkem::Matrix& a_v, const Elt& rho,
                                      const Field& f) {
    std::vector<Elt> out;
    for (size_t i = 0; i < kK; ++i) {
      for (size_t j = 0; j < kK; ++j) {
        Elt r = f.zero(), pw = f.one();
        for (size_t l = 0; l < kN; ++l) {
          f.add(r, f.mulf(pw, of_int(a_v[i][j][l], f)));
          pw = f.mulf(pw, rho);
        }
        out.push_back(r);
      }
    }
    return out;
  }

  // The private inputs, in the order of LatticeCircuit::Witness::read.
  // Bits and high halves come in the order compute() produced them, which
  // interleaves them as read() does.
  void fill_witness(DenseFiller<Field>& filler) const {
    for (const Elt& x : values_) filler.push_back(x);
  }

  void fill_prf(DenseFiller<Field>& filler) const {
    for (uint8_t b : prf_bits_) filler.push_back(f_.of_scalar(b));
  }

  const std::vector<Elt>& values() const { return values_; }
  const std::vector<uint8_t>& prf_bits() const { return prf_bits_; }
  const std::vector<int32_t>& m() const { return m_; }

  // The public inputs for rho, in the order of LatticeCircuit::Public::read.
  static std::vector<Elt> public_inputs(const LatticeStatement& st,
                                        const Elt& rho, const Field& f,
                                        Reencryption mode) {
    std::vector<Elt> pw(kN);
    pw[0] = f.one();
    for (size_t l = 1; l < kN; ++l) pw[l] = f.mulf(pw[l - 1], rho);
    auto at = [&](auto coef) {
      Elt r = f.zero();
      for (size_t l = 0; l < kN; ++l) {
        f.add(r, f.mulf(pw[l], of_int(coef(l), f)));
      }
      return r;
    };
    std::vector<Elt> out(pw);
    Elt z = f.addf(f.mulf(pw[kN - 1], rho), f.one());
    out.push_back(z);
    out.push_back(at([](size_t) { return int64_t{1}; }));
    for (size_t i = 0; i < kK; ++i) {
      for (size_t j = 0; j < kK; ++j) {
        out.push_back(at([&](size_t l) { return int64_t{st.a[i][j][l]}; }));
      }
    }
    for (size_t i = 0; i < kK; ++i) {
      out.push_back(at([&](size_t l) { return int64_t{st.t[i][l]}; }));
    }
    for (size_t i = 0; i < kK; ++i) {
      out.push_back(at([&](size_t l) { return int64_t{st.u[i][l]}; }));
    }
    out.push_back(at([&](size_t l) { return int64_t{st.v[l]}; }));
    if (mode == Reencryption::kEqual) {
      for (size_t i = 0; i < kK; ++i) {
        out.push_back(at([&](size_t l) {
          return int64_t{compress_interval(st.c1[i][l], mlkem::kDu).lo};
        }));
      }
      out.push_back(at([&](size_t l) {
        return int64_t{compress_interval(st.c2[l], mlkem::kDv).lo};
      }));
      for (size_t i = 0; i < kK; ++i) {
        for (size_t l = 0; l < kN; ++l) {
          int32_t w = compress_interval(st.c1[i][l], mlkem::kDu).w;
          out.push_back(f.mulf(pw[l], of_int(w - 2, f)));
        }
      }
      for (size_t l = 0; l < kN; ++l) {
        int32_t w = compress_interval(st.c2[l], mlkem::kDv).w;
        out.push_back(f.mulf(pw[l], of_int(w - 128, f)));
      }
    } else if (mode == Reencryption::kDiffers) {
      for (size_t i = 0; i < kK; ++i) {
        for (size_t l = 0; l < kN; ++l) out.push_back(of_int(st.c1[i][l], f));
      }
      for (size_t l = 0; l < kN; ++l) out.push_back(of_int(st.c2[l], f));
    }
    return out;
  }

  static Elt of_int(int64_t x, const Field& f) {
    return x >= 0 ? f.of_scalar(static_cast<uint64_t>(x))
                  : f.negf(f.of_scalar(static_cast<uint64_t>(-x)));
  }

 private:
  static void mul_add(Wide& acc, const Poly& a, const Poly& b) {
    for (size_t i = 0; i < kN; ++i) {
      for (size_t j = 0; j < kN; ++j) acc[i + j] += int64_t{a[i]} * b[j];
    }
  }

  // The product modulo X^256 + 1: X^256 = -1.
  static std::vector<int64_t> negacyclic(const Wide& acc) {
    std::vector<int64_t> r(kN);
    for (size_t l = 0; l < kN; ++l) {
      r[l] = acc[l] - (l + kN < acc.size() ? acc[l + kN] : 0);
    }
    return r;
  }

  // The coefficients of X^256, ..., X^510.
  static std::vector<int64_t> high(const Wide& acc) {
    return std::vector<int64_t>(acc.begin() + kN, acc.end());
  }

  // x on n bits, least significant first.
  void push_bits(int64_t x, size_t n) {
    if (x < 0 || x >= (int64_t{1} << n)) ok_ = false;
    for (size_t b = 0; b < n; ++b) {
      out_->push_back(f_.of_scalar((x >> b) & 1));
    }
  }

  // delta in [0, w) on n bits: n - 1 low bits and a top bit of weight top,
  // where w = 2^(n-1) + top.
  void push_split(int64_t delta, size_t n, int64_t top) {
    int64_t half = int64_t{1} << (n - 1);
    if (delta < 0 || delta >= half + top) ok_ = false;
    bool t = delta >= half;
    push_bits(t ? delta - top : delta, n - 1);
    push_bits(t ? 1 : 0, 1);
  }

  void push_high(const std::vector<int64_t>& h) {
    for (int64_t x : h) out_->push_back(of_int(x, f_));
  }

  const Field& f_;
  bool ok_ = true;
  std::vector<Elt> values_, node_values_;
  std::vector<Elt>* out_ = &values_;  // where the push functions write
  std::vector<int32_t> node_t_;
  std::vector<uint8_t> prf_bits_;
  std::vector<int32_t> m_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_LATTICE_WITNESS_H_
