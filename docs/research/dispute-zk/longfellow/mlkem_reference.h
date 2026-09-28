// ML-KEM-768 (FIPS 203) and X-Wing (draft-connolly-cfrg-xwing-kem), in the
// clear, keeping the intermediate values of decapsulation that the witness
// of a wrap dispute needs. Checked against the X-Wing test vectors. Research
// code: not constant time, not for production.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_MLKEM_REFERENCE_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_MLKEM_REFERENCE_H_

#include <stddef.h>
#include <stdint.h>

#include <array>
#include <cstring>
#include <vector>

#include "circuits/tests/sha3/sha3_reference.h"

namespace proofs {
namespace mlkem {

constexpr int32_t kQ = 3329;
constexpr size_t kN = 256;
constexpr size_t kK = 3;
constexpr int kDu = 10, kDv = 4;
constexpr size_t kEkBytes = 384 * kK + 32;          // 1184
constexpr size_t kCtBytes = 32 * (kDu * kK + kDv);  // 1088
constexpr size_t kPrfBytes = 128;                   // PRF_2: 64 eta bytes

// Coefficients are integers: in [0, q) once reduced, in [-2, 2] for the
// small polynomials.
using Poly = std::array<int32_t, kN>;
using PolyVec = std::array<Poly, kK>;
using Matrix = std::array<PolyVec, kK>;  // m[i][j]: row i, column j

inline int32_t mod_q(int64_t x) {
  int64_t r = x % kQ;
  return static_cast<int32_t>(r < 0 ? r + kQ : r);
}

inline Poly reduce(const Poly& f) {
  Poly r;
  for (size_t i = 0; i < kN; ++i) r[i] = mod_q(f[i]);
  return r;
}

// ---------- the Keccak functions: H, G, J, PRF and XOF ----------

inline void sha3_256(const uint8_t* in, size_t n, uint8_t out[32]) {
  Sha3Reference h(32);
  h.update(reinterpret_cast<const char*>(in), n);
  h.final(out);
}

inline void sha3_512(const uint8_t* in, size_t n, uint8_t out[64]) {
  Sha3Reference h(64);
  h.update(reinterpret_cast<const char*>(in), n);
  h.final(out);
}

inline void shake128(const uint8_t* in, size_t n, uint8_t* out, size_t len) {
  Sha3Reference::shake128Hash(in, n, out, len);
}

inline void shake256(const uint8_t* in, size_t n, uint8_t* out, size_t len) {
  Sha3Reference::shake256Hash(in, n, out, len);
}

// PRF_2(s, b) = SHAKE256(s || b, 128).
inline void prf(const uint8_t s[32], uint8_t b, uint8_t out[kPrfBytes]) {
  uint8_t in[33];
  std::memcpy(in, s, 32);
  in[32] = b;
  shake256(in, 33, out, kPrfBytes);
}

// ---------- the NTT (Algorithms 9 to 12) ----------

inline int32_t pow17(int e) {
  int64_t r = 1, b = 17;
  for (; e > 0; e >>= 1) {
    if (e & 1) r = r * b % kQ;
    b = b * b % kQ;
  }
  return static_cast<int32_t>(r);
}

inline int bitrev7(int x) {
  int r = 0;
  for (int i = 0; i < 7; ++i) {
    if ((x >> i) & 1) r |= 1 << (6 - i);
  }
  return r;
}

struct Tables {
  int32_t zetas[128], gammas[128];
  Tables() {
    for (int i = 0; i < 128; ++i) {
      zetas[i] = pow17(bitrev7(i));
      gammas[i] = pow17(2 * bitrev7(i) + 1);
    }
  }
};

inline const Tables& tables() {
  static const Tables t;
  return t;
}

inline Poly ntt(Poly f) {
  const int32_t* zetas = tables().zetas;
  size_t i = 1;
  for (size_t len = 128; len >= 2; len /= 2) {
    for (size_t start = 0; start < kN; start += 2 * len) {
      int64_t z = zetas[i++];
      for (size_t j = start; j < start + len; ++j) {
        int32_t t = mod_q(z * f[j + len]);
        f[j + len] = mod_q(f[j] - t);
        f[j] = mod_q(f[j] + t);
      }
    }
  }
  return f;
}

inline Poly intt(Poly f) {
  const int32_t* zetas = tables().zetas;
  size_t i = 127;
  for (size_t len = 2; len <= 128; len *= 2) {
    for (size_t start = 0; start < kN; start += 2 * len) {
      int64_t z = zetas[i--];
      for (size_t j = start; j < start + len; ++j) {
        int32_t t = f[j];
        f[j] = mod_q(t + f[j + len]);
        f[j + len] = mod_q(z * (f[j + len] - t));
      }
    }
  }
  for (size_t j = 0; j < kN; ++j) f[j] = mod_q(int64_t{3303} * f[j]);
  return f;
}

// The product in the NTT domain: 128 products modulo X^2 - gamma_i.
inline Poly ntt_mul(const Poly& a, const Poly& b) {
  const int32_t* gammas = tables().gammas;
  Poly c;
  for (size_t i = 0; i < 128; ++i) {
    int64_t a0 = a[2 * i], a1 = a[2 * i + 1], b0 = b[2 * i], b1 = b[2 * i + 1];
    c[2 * i] = mod_q(a0 * b0 + mod_q(a1 * b1) * int64_t{gammas[i]});
    c[2 * i + 1] = mod_q(a0 * b1 + a1 * b0);
  }
  return c;
}

inline Poly add(const Poly& a, const Poly& b) {
  Poly c;
  for (size_t i = 0; i < kN; ++i) c[i] = mod_q(a[i] + b[i]);
  return c;
}

// ---------- encodings, compression and sampling ----------

// ByteEncode_d and ByteDecode_d (Algorithms 5 and 6): 256 d-bit integers,
// least significant bit first. ByteDecode_12 reduces modulo q.
inline void byte_encode(const Poly& f, int d, uint8_t* out) {
  std::memset(out, 0, 32 * d);
  for (size_t i = 0; i < kN; ++i) {
    for (int b = 0; b < d; ++b) {
      size_t pos = i * d + b;
      if ((f[i] >> b) & 1) out[pos / 8] |= static_cast<uint8_t>(1 << (pos % 8));
    }
  }
}

inline Poly byte_decode(const uint8_t* in, int d) {
  Poly f;
  for (size_t i = 0; i < kN; ++i) {
    int32_t x = 0;
    for (int b = 0; b < d; ++b) {
      size_t pos = i * d + b;
      x |= ((in[pos / 8] >> (pos % 8)) & 1) << b;
    }
    f[i] = (d == 12) ? mod_q(x) : x;
  }
  return f;
}

// Compress_d and Decompress_d, for x in [0, q).
inline int32_t compress(int32_t x, int d) {
  return static_cast<int32_t>(((int64_t{x} << d) + 1664) / kQ) &
         ((1 << d) - 1);
}

inline int32_t decompress(int32_t y, int d) {
  return static_cast<int32_t>((int64_t{kQ} * y + (1 << (d - 1))) >> d);
}

// SampleNTT (Algorithm 7) on the XOF stream SHAKE128(rho || j || i).
inline Poly sample_ntt(const uint8_t rho[32], uint8_t j, uint8_t i) {
  uint8_t in[34];
  std::memcpy(in, rho, 32);
  in[32] = j;
  in[33] = i;
  // SHAKE128's output does not depend on its length beyond its prefix:
  // squeeze more and parse again if the stream runs out.
  for (size_t len = 168 * 4;; len *= 2) {
    std::vector<uint8_t> buf(len);
    shake128(in, sizeof(in), buf.data(), len);
    Poly a;
    size_t k = 0;
    for (size_t p = 0; p + 3 <= len && k < kN; p += 3) {
      int32_t d1 = buf[p] + 256 * (buf[p + 1] & 15);
      int32_t d2 = (buf[p + 1] >> 4) + 16 * buf[p + 2];
      if (d1 < kQ) a[k++] = d1;
      if (d2 < kQ && k < kN) a[k++] = d2;
    }
    if (k == kN) return a;
  }
}

// SamplePolyCBD_2 (Algorithm 8): coefficient i is the difference of the
// weights of the two halves of nibble i. The result is in [-2, 2].
inline Poly cbd2(const uint8_t b[kPrfBytes]) {
  Poly f;
  for (size_t i = 0; i < kN; ++i) {
    int nib = (b[i / 2] >> (4 * (i % 2))) & 15;
    f[i] = (nib & 1) + ((nib >> 1) & 1) - ((nib >> 2) & 1) - ((nib >> 3) & 1);
  }
  return f;
}

// ---------- K-PKE and ML-KEM (Algorithms 13 to 18) ----------

struct KeyPair {
  uint8_t rho[32], sigma[32], z[32];
  PolyVec s, e;        // in [-2, 2]
  Matrix a_hat;        // a_hat[i][j] = SampleNTT(rho || j || i)
  PolyVec s_hat, t_hat;
  uint8_t ek[kEkBytes];
  uint8_t h[32];       // H(ek)
};

inline Matrix expand_a(const uint8_t rho[32]) {
  Matrix a;
  for (size_t i = 0; i < kK; ++i) {
    for (size_t j = 0; j < kK; ++j) {
      a[i][j] = sample_ntt(rho, static_cast<uint8_t>(j), static_cast<uint8_t>(i));
    }
  }
  return a;
}

// ML-KEM.KeyGen_internal(d, z).
inline KeyPair keygen(const uint8_t d[32], const uint8_t z[32]) {
  KeyPair kp;
  uint8_t in[33], g[64];
  std::memcpy(in, d, 32);
  in[32] = kK;
  sha3_512(in, 33, g);
  std::memcpy(kp.rho, g, 32);
  std::memcpy(kp.sigma, g + 32, 32);
  std::memcpy(kp.z, z, 32);
  kp.a_hat = expand_a(kp.rho);
  uint8_t buf[kPrfBytes];
  for (size_t i = 0; i < kK; ++i) {
    prf(kp.sigma, static_cast<uint8_t>(i), buf);
    kp.s[i] = cbd2(buf);
    prf(kp.sigma, static_cast<uint8_t>(kK + i), buf);
    kp.e[i] = cbd2(buf);
  }
  PolyVec e_hat;
  for (size_t i = 0; i < kK; ++i) {
    kp.s_hat[i] = ntt(reduce(kp.s[i]));
    e_hat[i] = ntt(reduce(kp.e[i]));
  }
  for (size_t i = 0; i < kK; ++i) {
    Poly acc = e_hat[i];
    for (size_t j = 0; j < kK; ++j) {
      acc = add(acc, ntt_mul(kp.a_hat[i][j], kp.s_hat[j]));
    }
    kp.t_hat[i] = acc;
    byte_encode(kp.t_hat[i], 12, kp.ek + 384 * i);
  }
  std::memcpy(kp.ek + 384 * kK, kp.rho, 32);
  sha3_256(kp.ek, kEkBytes, kp.h);
  return kp;
}

// K-PKE.Encrypt, with its noise and its values before compression.
struct Encryption {
  uint8_t prf[2 * kK + 1][kPrfBytes];  // PRF(r, N) for N = 0, ..., 6
  PolyVec y, e1;                       // in [-2, 2]
  Poly e2;                             // in [-2, 2]
  PolyVec u;                           // before Compress_10, in [0, q)
  Poly v;                              // before Compress_4, in [0, q)
  uint8_t c[kCtBytes];
};

inline Encryption encrypt(const Matrix& a_hat, const PolyVec& t_hat,
                          const uint8_t m[32], const uint8_t r[32]) {
  Encryption en;
  for (size_t n = 0; n < 2 * kK + 1; ++n) {
    prf(r, static_cast<uint8_t>(n), en.prf[n]);
  }
  PolyVec y_hat;
  for (size_t i = 0; i < kK; ++i) {
    en.y[i] = cbd2(en.prf[i]);
    en.e1[i] = cbd2(en.prf[kK + i]);
    y_hat[i] = ntt(reduce(en.y[i]));
  }
  en.e2 = cbd2(en.prf[2 * kK]);
  for (size_t i = 0; i < kK; ++i) {
    Poly acc{};
    for (size_t j = 0; j < kK; ++j) acc = add(acc, ntt_mul(a_hat[j][i], y_hat[j]));
    en.u[i] = add(intt(acc), reduce(en.e1[i]));
    Poly cu;
    for (size_t x = 0; x < kN; ++x) cu[x] = compress(en.u[i][x], kDu);
    byte_encode(cu, kDu, en.c + 32 * kDu * i);
  }
  Poly acc{}, mu;
  for (size_t j = 0; j < kK; ++j) acc = add(acc, ntt_mul(t_hat[j], y_hat[j]));
  for (size_t x = 0; x < kN; ++x) mu[x] = decompress((m[x / 8] >> (x % 8)) & 1, 1);
  en.v = add(add(intt(acc), reduce(en.e2)), mu);
  Poly cv;
  for (size_t x = 0; x < kN; ++x) cv[x] = compress(en.v[x], kDv);
  byte_encode(cv, kDv, en.c + 32 * kDu * kK);
  return en;
}

// K-PKE.Decrypt, with its decompressed inputs and w before Compress_1.
struct Decryption {
  PolyVec u;  // Decompress_10(c1)
  Poly v;     // Decompress_4(c2)
  Poly w;     // v - NTT^-1(s_hat^T NTT(u)), in [0, q)
  uint8_t m[32];
};

inline Decryption decrypt(const PolyVec& s_hat, const uint8_t c[kCtBytes]) {
  Decryption de;
  Poly acc{};
  for (size_t i = 0; i < kK; ++i) {
    Poly cu = byte_decode(c + 32 * kDu * i, kDu);
    for (size_t x = 0; x < kN; ++x) de.u[i][x] = decompress(cu[x], kDu);
    acc = add(acc, ntt_mul(s_hat[i], ntt(de.u[i])));
  }
  Poly cv = byte_decode(c + 32 * kDu * kK, kDv);
  for (size_t x = 0; x < kN; ++x) de.v[x] = decompress(cv[x], kDv);
  Poly sp = intt(acc);
  std::memset(de.m, 0, 32);
  for (size_t x = 0; x < kN; ++x) {
    de.w[x] = mod_q(de.v[x] - sp[x]);
    if (compress(de.w[x], 1)) de.m[x / 8] |= static_cast<uint8_t>(1 << (x % 8));
  }
  return de;
}

// A public key, parsed: t_hat, rho, A and H(ek).
struct PublicKey {
  PolyVec t_hat;
  uint8_t rho[32];
  Matrix a_hat;
  uint8_t h[32];
};

inline PublicKey parse_ek(const uint8_t ek[kEkBytes]) {
  PublicKey pk;
  for (size_t i = 0; i < kK; ++i) pk.t_hat[i] = byte_decode(ek + 384 * i, 12);
  std::memcpy(pk.rho, ek + 384 * kK, 32);
  pk.a_hat = expand_a(pk.rho);
  sha3_256(ek, kEkBytes, pk.h);
  return pk;
}

// ML-KEM.Encaps_internal(ek, m): (K, r) = G(m || H(ek)).
inline void encaps(const uint8_t ek[kEkBytes], const uint8_t m[32],
                   uint8_t c[kCtBytes], uint8_t k[32]) {
  PublicKey pk = parse_ek(ek);
  uint8_t in[64], g[64];
  std::memcpy(in, m, 32);
  std::memcpy(in + 32, pk.h, 32);
  sha3_512(in, 64, g);
  Encryption en = encrypt(pk.a_hat, pk.t_hat, m, g + 32);
  std::memcpy(c, en.c, kCtBytes);
  std::memcpy(k, g, 32);
}

// ML-KEM.Decaps_internal, with what the dispute's witness needs.
struct Decapsulation {
  Decryption de;
  uint8_t g_in[64], g[64];  // G(m' || h) = K' || r'
  Encryption re;            // the re-encryption of m' with r'
  bool fo_ok;               // the re-encryption gives c
  uint8_t k_bar[32];        // J(z || c)
  uint8_t k[32];            // the shared secret
};

inline Decapsulation decaps(const KeyPair& kp, const uint8_t c[kCtBytes]) {
  Decapsulation d;
  d.de = decrypt(kp.s_hat, c);
  std::memcpy(d.g_in, d.de.m, 32);
  std::memcpy(d.g_in + 32, kp.h, 32);
  sha3_512(d.g_in, 64, d.g);
  d.re = encrypt(kp.a_hat, kp.t_hat, d.de.m, d.g + 32);
  d.fo_ok = std::memcmp(d.re.c, c, kCtBytes) == 0;
  std::vector<uint8_t> j(32 + kCtBytes);
  std::memcpy(j.data(), kp.z, 32);
  std::memcpy(j.data() + 32, c, kCtBytes);
  shake256(j.data(), j.size(), d.k_bar, 32);
  std::memcpy(d.k, d.fo_ok ? d.g : d.k_bar, 32);
  return d;
}

// ---------- X-Wing ----------

constexpr size_t kXWingPkBytes = kEkBytes + 32;  // 1216
constexpr size_t kXWingCtBytes = kCtBytes + 32;  // 1120
constexpr uint8_t kXWingLabel[6] = {0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c};

// X25519(scalar, u), as RFC 7748 defines it.
using X25519Fn = void (*)(const uint8_t scalar[32], const uint8_t u[32],
                          uint8_t out[32]);

inline void x25519_base(X25519Fn x25519, const uint8_t scalar[32],
                        uint8_t out[32]) {
  uint8_t nine[32] = {9};
  x25519(scalar, nine, out);
}

// SHA3-256(ss_M || ss_X || ct_X || pk_X || label): 134 bytes, one block.
inline void combiner(const uint8_t ss_m[32], const uint8_t ss_x[32],
                     const uint8_t ct_x[32], const uint8_t pk_x[32],
                     uint8_t out[32]) {
  uint8_t in[134];
  std::memcpy(in, ss_m, 32);
  std::memcpy(in + 32, ss_x, 32);
  std::memcpy(in + 64, ct_x, 32);
  std::memcpy(in + 96, pk_x, 32);
  std::memcpy(in + 128, kXWingLabel, 6);
  sha3_256(in, sizeof(in), out);
}

struct XWingKey {
  uint8_t seed[32];
  KeyPair m;
  uint8_t sk_x[32], pk_x[32];
  uint8_t pk[kXWingPkBytes];
};

// The decapsulation key is a 32-byte seed that SHAKE256 expands into the
// ML-KEM-768 seed (d, z) and the X25519 scalar.
inline XWingKey xwing_keygen(const uint8_t seed[32], X25519Fn x25519) {
  XWingKey key;
  std::memcpy(key.seed, seed, 32);
  uint8_t e[96];
  shake256(seed, 32, e, sizeof(e));
  key.m = keygen(e, e + 32);
  std::memcpy(key.sk_x, e + 64, 32);
  x25519_base(x25519, key.sk_x, key.pk_x);
  std::memcpy(key.pk, key.m.ek, kEkBytes);
  std::memcpy(key.pk + kEkBytes, key.pk_x, 32);
  return key;
}

// Encapsulation with its 64 bytes of randomness: 32 for ML-KEM, 32 for the
// ephemeral X25519 key.
inline void xwing_encaps(const uint8_t pk[kXWingPkBytes],
                         const uint8_t eseed[64], X25519Fn x25519,
                         uint8_t ct[kXWingCtBytes], uint8_t ss[32]) {
  const uint8_t* pk_x = pk + kEkBytes;
  uint8_t* ct_x = ct + kCtBytes;
  uint8_t ss_m[32], ss_x[32];
  x25519_base(x25519, eseed + 32, ct_x);
  x25519(eseed + 32, pk_x, ss_x);
  encaps(pk, eseed, ct, ss_m);
  combiner(ss_m, ss_x, ct_x, pk_x, ss);
}

struct XWingDecapsulation {
  Decapsulation m;
  uint8_t ss_x[32];
  uint8_t combiner_in[134];
  uint8_t ss[32];
};

inline XWingDecapsulation xwing_decaps(const XWingKey& key,
                                       const uint8_t ct[kXWingCtBytes],
                                       X25519Fn x25519) {
  XWingDecapsulation d;
  const uint8_t* ct_x = ct + kCtBytes;
  d.m = decaps(key.m, ct);
  x25519(key.sk_x, ct_x, d.ss_x);
  std::memcpy(d.combiner_in, d.m.k, 32);
  std::memcpy(d.combiner_in + 32, d.ss_x, 32);
  std::memcpy(d.combiner_in + 64, ct_x, 32);
  std::memcpy(d.combiner_in + 96, key.pk_x, 32);
  std::memcpy(d.combiner_in + 128, kXWingLabel, 6);
  sha3_256(d.combiner_in, sizeof(d.combiner_in), d.ss);
  return d;
}

}  // namespace mlkem
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_MLKEM_REFERENCE_H_
