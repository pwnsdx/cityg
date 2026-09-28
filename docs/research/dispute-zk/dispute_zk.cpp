// Measures a zero-knowledge proof of a wrap dispute with emp-zk (QuickSilver
// over authenticated bits), and the cost of multiplications in its
// arithmetic backend. Companion of
// docs/research/preuves-et-mesures-2026-09-26.md.
//
// The boolean part of the dispute statement is: the Keccak-f[1600]
// permutations of X-Wing's key generation and decapsulation (26), the BLAKE3
// compressions of the two ExpandLabel calls (4), and one ChaCha20 block, the
// one that gives the Poly1305 key, which the prover reveals so that the
// verifier checks the tag itself. The costs of these circuits do not depend on
// the data, so each runs on secret random inputs. Every circuit is checked
// against a clear reference implementation on its first instance.
//
// The lattice part is the arithmetic of ML-KEM-768 (FIPS 203): the secret key
// against the public key (A s + e = t, with A public), the decryption, and
// the re-encryption of the Fujisaki-Okamoto transform, checked against the
// ciphertext, over bits, each product reduced modulo q with a quotient the
// prover supplies. The parts are measured side by side: the statement would
// wire the Keccak outputs into the lattice part's secret inputs, which adds
// no AND gate. The X25519 half is priced by its field multiplication.
//
// Usage (two processes, as emp-zk's ./run does):
//   dispute_zk 1 MODE [N] & dispute_zk 2 MODE [N]
// MODE: setup (an empty proof), dispute (the boolean part), mlkem (the
// lattice part), full (both), keccak N, blake3 N, chacha N, x25519mul N (N
// multiplications modulo 2^255 - 19 over bits), arith N (N multiplications in
// F_{2^61-1}).

#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>

using namespace emp;

using Ctx = ZKBoolSession::ctx_t;
using U64 = UInt_T<Ctx, 64>;
using U32 = UInt_T<Ctx, 32>;

// ---------- clear reference implementations ----------

static const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
// Rotation offsets of rho, indexed by x + 5 y.
static const int KECCAK_ROT[25] = {0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
                                   25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14};

static uint64_t rotl64c(uint64_t x, int r) { return r == 0 ? x : (x << r) | (x >> (64 - r)); }
static uint32_t rotr32c(uint32_t x, int r) { return (x >> r) | (x << (32 - r)); }
static uint32_t rotl32c(uint32_t x, int r) { return (x << r) | (x >> (32 - r)); }

static void keccak_clear(uint64_t a[25]) {
    for (int round = 0; round < 24; ++round) {
        uint64_t c[5], d[5], b[25];
        for (int x = 0; x < 5; ++x) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        for (int x = 0; x < 5; ++x) d[x] = c[(x + 4) % 5] ^ rotl64c(c[(x + 1) % 5], 1);
        for (int i = 0; i < 25; ++i) a[i] ^= d[i % 5];
        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y) b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64c(a[x + 5 * y], KECCAK_ROT[x + 5 * y]);
        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y)
                a[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
        a[0] ^= KECCAK_RC[round];
    }
}

static const uint32_t BLAKE3_IV[8] = {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                                      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};
static const int BLAKE3_PERM[16] = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};

static void blake3_g_clear(uint32_t s[16], int a, int b, int c, int d, uint32_t mx, uint32_t my) {
    s[a] = s[a] + s[b] + mx; s[d] = rotr32c(s[d] ^ s[a], 16);
    s[c] = s[c] + s[d];      s[b] = rotr32c(s[b] ^ s[c], 12);
    s[a] = s[a] + s[b] + my; s[d] = rotr32c(s[d] ^ s[a], 8);
    s[c] = s[c] + s[d];      s[b] = rotr32c(s[b] ^ s[c], 7);
}

// BLAKE3's compression function: 16 output words.
static void blake3_clear(const uint32_t cv[8], const uint32_t m_in[16], uint32_t counter_lo,
                         uint32_t block_len, uint32_t flags, uint32_t out[16]) {
    uint32_t s[16] = {cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
                      BLAKE3_IV[0], BLAKE3_IV[1], BLAKE3_IV[2], BLAKE3_IV[3], counter_lo, 0, block_len, flags};
    uint32_t m[16];
    memcpy(m, m_in, sizeof(m));
    for (int r = 0; r < 7; ++r) {
        blake3_g_clear(s, 0, 4, 8, 12, m[0], m[1]);   blake3_g_clear(s, 1, 5, 9, 13, m[2], m[3]);
        blake3_g_clear(s, 2, 6, 10, 14, m[4], m[5]);  blake3_g_clear(s, 3, 7, 11, 15, m[6], m[7]);
        blake3_g_clear(s, 0, 5, 10, 15, m[8], m[9]);  blake3_g_clear(s, 1, 6, 11, 12, m[10], m[11]);
        blake3_g_clear(s, 2, 7, 8, 13, m[12], m[13]); blake3_g_clear(s, 3, 4, 9, 14, m[14], m[15]);
        if (r < 6) {
            uint32_t t[16];
            for (int i = 0; i < 16; ++i) t[i] = m[BLAKE3_PERM[i]];
            memcpy(m, t, sizeof(m));
        }
    }
    for (int i = 0; i < 8; ++i) { out[i] = s[i] ^ s[i + 8]; out[i + 8] = s[i + 8] ^ cv[i]; }
}

static void chacha_qr_clear(uint32_t s[16], int a, int b, int c, int d) {
    s[a] += s[b]; s[d] = rotl32c(s[d] ^ s[a], 16);
    s[c] += s[d]; s[b] = rotl32c(s[b] ^ s[c], 12);
    s[a] += s[b]; s[d] = rotl32c(s[d] ^ s[a], 8);
    s[c] += s[d]; s[b] = rotl32c(s[b] ^ s[c], 7);
}

static void chacha_clear(const uint32_t key[8], uint32_t counter, const uint32_t nonce[3], uint32_t out[16]) {
    uint32_t init[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, key[0], key[1], key[2], key[3],
                         key[4], key[5], key[6], key[7], counter, nonce[0], nonce[1], nonce[2]};
    uint32_t s[16];
    memcpy(s, init, sizeof(s));
    for (int i = 0; i < 10; ++i) {
        chacha_qr_clear(s, 0, 4, 8, 12); chacha_qr_clear(s, 1, 5, 9, 13);
        chacha_qr_clear(s, 2, 6, 10, 14); chacha_qr_clear(s, 3, 7, 11, 15);
        chacha_qr_clear(s, 0, 5, 10, 15); chacha_qr_clear(s, 1, 6, 11, 12);
        chacha_qr_clear(s, 2, 7, 8, 13); chacha_qr_clear(s, 3, 4, 9, 14);
    }
    for (int i = 0; i < 16; ++i) out[i] = s[i] + init[i];
}

// ---------- circuits over authenticated bits ----------

static U64 rotl64(const U64& x, int r) {
    U64 y = x;
    for (int i = 0; i < 64; ++i) y.w[(i + r) % 64] = x.w[i];
    return y;
}
static U32 rotr32(const U32& x, int r) {
    U32 y = x;
    for (int i = 0; i < 32; ++i) y.w[i] = x.w[(i + r) % 32];
    return y;
}
static U32 rotl32(const U32& x, int r) { return rotr32(x, 32 - r); }

static void keccak_zk(ZKBoolSession& sess, std::array<U64, 25>& a) {
    for (int round = 0; round < 24; ++round) {
        std::array<U64, 5> c = {a[0], a[1], a[2], a[3], a[4]};
        for (int x = 0; x < 5; ++x) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        for (int x = 0; x < 5; ++x) {
            U64 d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
            for (int y = 0; y < 5; ++y) a[x + 5 * y] = a[x + 5 * y] ^ d;
        }
        std::array<U64, 25> b = a;
        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y) b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(a[x + 5 * y], KECCAK_ROT[x + 5 * y]);
        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y)
                a[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
        a[0] = a[0] ^ sess.input<U64>(PUBLIC, KECCAK_RC[round]);
    }
}

static void blake3_g(std::array<U32, 16>& s, int a, int b, int c, int d, const U32& mx, const U32& my) {
    s[a] = s[a] + s[b] + mx; s[d] = rotr32(s[d] ^ s[a], 16);
    s[c] = s[c] + s[d];      s[b] = rotr32(s[b] ^ s[c], 12);
    s[a] = s[a] + s[b] + my; s[d] = rotr32(s[d] ^ s[a], 8);
    s[c] = s[c] + s[d];      s[b] = rotr32(s[b] ^ s[c], 7);
}

static std::array<U32, 16> blake3_zk(ZKBoolSession& sess, const std::array<U32, 8>& cv, std::array<U32, 16> m,
                                     uint32_t counter_lo, uint32_t block_len, uint32_t flags) {
    std::array<U32, 16> s = {cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
                             sess.input<U32>(PUBLIC, BLAKE3_IV[0]), sess.input<U32>(PUBLIC, BLAKE3_IV[1]),
                             sess.input<U32>(PUBLIC, BLAKE3_IV[2]), sess.input<U32>(PUBLIC, BLAKE3_IV[3]),
                             sess.input<U32>(PUBLIC, counter_lo), sess.input<U32>(PUBLIC, 0),
                             sess.input<U32>(PUBLIC, block_len), sess.input<U32>(PUBLIC, flags)};
    for (int r = 0; r < 7; ++r) {
        blake3_g(s, 0, 4, 8, 12, m[0], m[1]);   blake3_g(s, 1, 5, 9, 13, m[2], m[3]);
        blake3_g(s, 2, 6, 10, 14, m[4], m[5]);  blake3_g(s, 3, 7, 11, 15, m[6], m[7]);
        blake3_g(s, 0, 5, 10, 15, m[8], m[9]);  blake3_g(s, 1, 6, 11, 12, m[10], m[11]);
        blake3_g(s, 2, 7, 8, 13, m[12], m[13]); blake3_g(s, 3, 4, 9, 14, m[14], m[15]);
        if (r < 6) {
            std::array<U32, 16> t = m;
            for (int i = 0; i < 16; ++i) t[i] = m[BLAKE3_PERM[i]];
            m = t;
        }
    }
    std::array<U32, 16> out = s;
    for (int i = 0; i < 8; ++i) { out[i] = s[i] ^ s[i + 8]; out[i + 8] = s[i + 8] ^ cv[i]; }
    return out;
}

static void chacha_qr(std::array<U32, 16>& s, int a, int b, int c, int d) {
    s[a] = s[a] + s[b]; s[d] = rotl32(s[d] ^ s[a], 16);
    s[c] = s[c] + s[d]; s[b] = rotl32(s[b] ^ s[c], 12);
    s[a] = s[a] + s[b]; s[d] = rotl32(s[d] ^ s[a], 8);
    s[c] = s[c] + s[d]; s[b] = rotl32(s[b] ^ s[c], 7);
}

static std::array<U32, 16> chacha_zk(ZKBoolSession& sess, const std::array<U32, 8>& key, uint32_t counter,
                                     const std::array<U32, 3>& nonce) {
    std::array<U32, 16> init = {sess.input<U32>(PUBLIC, 0x61707865), sess.input<U32>(PUBLIC, 0x3320646e),
                                sess.input<U32>(PUBLIC, 0x79622d32), sess.input<U32>(PUBLIC, 0x6b206574),
                                key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
                                sess.input<U32>(PUBLIC, counter), nonce[0], nonce[1], nonce[2]};
    std::array<U32, 16> s = init;
    for (int i = 0; i < 10; ++i) {
        chacha_qr(s, 0, 4, 8, 12); chacha_qr(s, 1, 5, 9, 13); chacha_qr(s, 2, 6, 10, 14); chacha_qr(s, 3, 7, 11, 15);
        chacha_qr(s, 0, 5, 10, 15); chacha_qr(s, 1, 6, 11, 12); chacha_qr(s, 2, 7, 8, 13); chacha_qr(s, 3, 4, 9, 14);
    }
    for (int i = 0; i < 16; ++i) s[i] = s[i] + init[i];
    return s;
}

// ---------- ML-KEM-768 arithmetic (FIPS 203): the lattice part of the statement ----------
//
// The public key (A, t) and the ciphertext (c1, c2) are public, so every
// multiplication has a public factor. The prover supplies each reduction
// modulo q as a witness (quotient and remainder), which the circuit checks.

static const int Q = 3329;
static int ZETAS[128], GAMMAS[128];
static int bitrev7(int x) { int r = 0; for (int i = 0; i < 7; ++i) if (x >> i & 1) r |= 1 << (6 - i); return r; }
static int powmod(long b, int e) { long r = 1; while (e) { if (e & 1) r = r * b % Q; b = b * b % Q; e >>= 1; } return (int)r; }
static void init_tables() {
    for (int i = 0; i < 128; ++i) { ZETAS[i] = powmod(17, bitrev7(i)); GAMMAS[i] = powmod(17, 2 * bitrev7(i) + 1); }
}

using Poly = std::array<int, 256>;
static void ntt_c(Poly& f) {
    int i = 1;
    for (int len = 128; len >= 2; len /= 2)
        for (int start = 0; start < 256; start += 2 * len) {
            long z = ZETAS[i++];
            for (int j = start; j < start + len; ++j) {
                int t = (int)(z * f[j + len] % Q);
                f[j + len] = (f[j] - t + Q) % Q; f[j] = (f[j] + t) % Q;
            }
        }
}
static void intt_c(Poly& f) {
    int i = 127;
    for (int len = 2; len <= 128; len *= 2)
        for (int start = 0; start < 256; start += 2 * len) {
            long z = ZETAS[i--];
            for (int j = start; j < start + len; ++j) {
                int t = f[j];
                f[j] = (t + f[j + len]) % Q; f[j + len] = (int)(z * ((f[j + len] - t + Q) % Q) % Q);
            }
        }
    for (int j = 0; j < 256; ++j) f[j] = (int)(3303L * f[j] % Q);
}
static Poly mulntt_c(const Poly& a, const Poly& b) {
    Poly c;
    for (int i = 0; i < 128; ++i) {
        long a0 = a[2 * i], a1 = a[2 * i + 1], b0 = b[2 * i], b1 = b[2 * i + 1];
        c[2 * i] = (int)((a0 * b0 + a1 * (b1 * GAMMAS[i] % Q)) % Q);
        c[2 * i + 1] = (int)((a0 * b1 + a1 * b0) % Q);
    }
    return c;
}
static Poly add_c(const Poly& a, const Poly& b) { Poly c; for (int j = 0; j < 256; ++j) c[j] = (a[j] + b[j]) % Q; return c; }
static int compress_c(int x, int d) { return (int)((((long)x << d) + 1664) / Q) & ((1 << d) - 1); }
static int decompress_c(int y, int d) { return (int)(((long)Q * y + (1L << (d - 1))) >> d); }
static int cbd_c(int nibble) { return ((nibble & 1) + (nibble >> 1 & 1) - (nibble >> 2 & 1) - (nibble >> 3 & 1) + Q) % Q; }

using U13 = UInt_T<Ctx, 13>;
using U24 = UInt_T<Ctx, 24>;
using U4 = UInt_T<Ctx, 4>;
using ZBit = Bit_T<Ctx>;

// A coefficient modulo q, with the prover's clear value (meaningless for the verifier).
struct Coef { U13 w; int v; };
using CPoly = std::vector<Coef>;

class Lattice {
public:
    ZKBoolSession& sess;
    ZBit witness_ok;   // every reduction supplied by the prover is right
    ZBit fo_ok;        // the re-encryption gives the public ciphertext
    ZBit key_ok;       // A s + e = t: the secret key is the public key's
    long mulc = 0, addc = 0;
    explicit Lattice(ZKBoolSession& s)
        : sess(s), witness_ok(ZBit::constant(s.ctx(), true)), fo_ok(ZBit::constant(s.ctx(), true)),
          key_ok(ZBit::constant(s.ctx(), true)) {}

    U13 c13(int v) { return U13::constant(sess.ctx(), (uint64_t)v); }
    U24 c24(long v) { return U24::constant(sess.ctx(), (uint64_t)v); }

    // c x mod q for a public c.
    Coef mulc_red(const Coef& x, int c) {
        c %= Q;
        if (c == 0) return {c13(0), 0};
        if (c == 1) return x;
        ++mulc;
        U24 xz = x.w.template zext<24>();
        U24 prod = c24(0);
        bool first = true;
        for (int i = 0; i < 12; ++i)
            if (c >> i & 1) { U24 t = xz << i; prod = first ? t : prod + t; first = false; }
        long pv = (long)c * x.v;
        U13 r = sess.input<U13>(ALICE, (uint64_t)(pv % Q));
        U13 k = sess.input<U13>(ALICE, (uint64_t)(pv / Q));
        U24 kz = k.template zext<24>();
        U24 kq = kz + (kz << 8) + (kz << 10) + (kz << 11);   // 3329 = 2^11 + 2^10 + 2^8 + 1
        witness_ok = witness_ok & ((kq + r.template zext<24>()) == prod) & (r < c13(Q));
        return {r, (int)(pv % Q)};
    }
    Coef reduce_once(const U13& s, int v) {
        ZBit ge = !(s < c13(Q));
        return {s.select(ge, s - c13(Q)), v % Q};
    }
    Coef add(const Coef& a, const Coef& b) { ++addc; return reduce_once(a.w + b.w, a.v + b.v); }
    Coef sub(const Coef& a, const Coef& b) { ++addc; return reduce_once((a.w + c13(Q)) - b.w, a.v - b.v + Q); }
    Coef cst(int v) { return {c13(v), v}; }

    void ntt(CPoly& f) {
        int i = 1;
        for (int len = 128; len >= 2; len /= 2)
            for (int start = 0; start < 256; start += 2 * len) {
                int z = ZETAS[i++];
                for (int j = start; j < start + len; ++j) {
                    Coef t = mulc_red(f[j + len], z);
                    f[j + len] = sub(f[j], t); f[j] = add(f[j], t);
                }
            }
    }
    void intt(CPoly& f) {
        int i = 127;
        for (int len = 2; len <= 128; len *= 2)
            for (int start = 0; start < 256; start += 2 * len) {
                int z = ZETAS[i--];
                for (int j = start; j < start + len; ++j) {
                    Coef t = f[j];
                    f[j] = add(t, f[j + len]); f[j + len] = mulc_red(sub(f[j + len], t), z);
                }
            }
        for (int j = 0; j < 256; ++j) f[j] = mulc_red(f[j], 3303);
    }
    // a (secret) times b (public), in the NTT domain.
    CPoly mulntt(const CPoly& a, const Poly& b) {
        CPoly c(256, cst(0));
        for (int i = 0; i < 128; ++i) {
            int b0 = b[2 * i], b1 = b[2 * i + 1], b1g = (int)((long)b1 * GAMMAS[i] % Q);
            c[2 * i] = add(mulc_red(a[2 * i], b0), mulc_red(a[2 * i + 1], b1g));
            c[2 * i + 1] = add(mulc_red(a[2 * i], b1), mulc_red(a[2 * i + 1], b0));
        }
        return c;
    }
    CPoly addp(const CPoly& a, const CPoly& b) { CPoly c(256, cst(0)); for (int j = 0; j < 256; ++j) c[j] = add(a[j], b[j]); return c; }
    // A coefficient of the centered binomial distribution with eta = 2, from 4 secret bits.
    Coef cbd(int nibble) {
        U4 b = sess.input<U4>(ALICE, (uint64_t)nibble);
        U13 a = c13(0), m = c13(0);
        a.w[0] = (b[0] ^ b[1]).w; a.w[1] = (b[0] & b[1]).w;
        m.w[0] = (b[2] ^ b[3]).w; m.w[1] = (b[2] & b[3]).w;
        return reduce_once((a + c13(Q)) - m, cbd_c(nibble) + Q);
    }
    // Check Compress_d(x) = c, for a public c.
    void check_compress(const Coef& x, int d, int c) {
        U24 y = (x.w.template zext<24>() << d) + c24(1664);
        ZBit ok = (y - c24((long)c * Q)) < c24(Q);
        if (c == 0) ok = ok | ((y - c24((long)Q << d)) < c24(Q));
        fo_ok = fo_ok & ok;
    }
};

// ---------- a multiplication modulo 2^255 - 19, over bits ----------
//
// Schoolbook, with two folds of the high half (2^255 = 19 mod p) and no final
// conditional subtraction: what X25519 would cost per field multiplication in
// a boolean-only proof.

using U512 = UInt_T<Ctx, 512>;
using U256 = UInt_T<Ctx, 256>;

static U256 mul25519_zk(ZKBoolSession& sess, const U256& a, const U256& b) {
    U512 prod = U512::constant(sess.ctx(), 0);
    for (int i = 0; i < 255; ++i) {
        U512 row = U512::constant(sess.ctx(), 0);
        for (int j = 0; j < 256; ++j) row.w[j] = (a[j] & b[i]).w;
        prod = prod + (row << i);
    }
    // Fold: low 255 bits + 19 * high bits, twice.
    for (int f = 0; f < 2; ++f) {
        U512 lo = prod, hi = prod >> 255;
        for (int j = 255; j < 512; ++j) lo.w[j] = U512::constant(sess.ctx(), 0).w[0];
        prod = lo + hi + (hi << 1) + (hi << 4);
    }
    return prod.template trunc<256>();
}

// ---------- the measurements ----------

static std::mt19937_64 rng(20260926);   // the prover's secret inputs; the verifier ignores them

// The lattice part of the statement: the key binding A s + e = t, the
// decryption of the ciphertext, and its re-encryption, checked against it.
static bool run_mlkem(ZKBoolSession& sess, int party, long* mulc, long* addc) {
    const int K = 3;
    init_tables();
    // Clear key and ciphertext (public A, t, c1, c2; secret s, e, m, y, e1, e2).
    std::array<std::array<Poly, K>, K> A;
    for (auto& row : A) for (auto& p : row) for (int& x : p) x = (int)(rng() % Q);
    auto nibbles = [](int n) { std::vector<int> v(n); for (int& x : v) x = (int)(rng() & 15); return v; };
    std::vector<int> sn = nibbles(K * 256), en = nibbles(K * 256), yn = nibbles(K * 256), e1n = nibbles(K * 256), e2n = nibbles(256);
    std::array<Poly, K> s_hat, e_hat, t_hat, y_hat;
    for (int i = 0; i < K; ++i) {
        for (int j = 0; j < 256; ++j) { s_hat[i][j] = cbd_c(sn[i * 256 + j]); e_hat[i][j] = cbd_c(en[i * 256 + j]); y_hat[i][j] = cbd_c(yn[i * 256 + j]); }
        ntt_c(s_hat[i]); ntt_c(e_hat[i]); ntt_c(y_hat[i]);
    }
    for (int i = 0; i < K; ++i) {
        Poly acc = e_hat[i];
        for (int j = 0; j < K; ++j) acc = add_c(acc, mulntt_c(A[i][j], s_hat[j]));
        t_hat[i] = acc;
    }
    std::array<int, 256> m;
    for (int& b : m) b = (int)(rng() & 1);
    std::array<std::array<int, 256>, K> c1;
    std::array<int, 256> c2;
    for (int i = 0; i < K; ++i) {
        Poly acc = {};
        for (int j = 0; j < K; ++j) acc = add_c(acc, mulntt_c(A[j][i], y_hat[j]));
        intt_c(acc);
        for (int x = 0; x < 256; ++x) c1[i][x] = compress_c((acc[x] + cbd_c(e1n[i * 256 + x])) % Q, 10);
    }
    {
        Poly acc = {};
        for (int j = 0; j < K; ++j) acc = add_c(acc, mulntt_c(t_hat[j], y_hat[j]));
        intt_c(acc);
        for (int x = 0; x < 256; ++x) c2[x] = compress_c((acc[x] + cbd_c(e2n[x]) + decompress_c(m[x], 1)) % Q, 4);
    }
    // Public values the verifier computes: NTT(Decompress(c1)) and Decompress(c2).
    std::array<Poly, K> u_hat;
    Poly v_pub;
    for (int i = 0; i < K; ++i) { for (int x = 0; x < 256; ++x) u_hat[i][x] = decompress_c(c1[i][x], 10); ntt_c(u_hat[i]); }
    for (int x = 0; x < 256; ++x) v_pub[x] = decompress_c(c2[x], 4);

    Lattice L(sess);
    // The key binding.
    std::array<CPoly, K> sz, ez;
    for (int i = 0; i < K; ++i) {
        sz[i].reserve(256); ez[i].reserve(256);
        for (int j = 0; j < 256; ++j) { sz[i].push_back(L.cbd(sn[i * 256 + j])); ez[i].push_back(L.cbd(en[i * 256 + j])); }
        L.ntt(sz[i]); L.ntt(ez[i]);
    }
    for (int i = 0; i < K; ++i) {
        CPoly acc = ez[i];
        for (int j = 0; j < K; ++j) acc = L.addp(acc, L.mulntt(sz[j], A[i][j]));
        for (int x = 0; x < 256; ++x) L.key_ok = L.key_ok & (acc[x].w == L.c13(t_hat[i][x]));
    }
    // The decryption: w = v - NTT^-1(s^T u), m' = Compress_1(w).
    CPoly w(256, L.cst(0));
    for (int j = 0; j < K; ++j) w = L.addp(w, L.mulntt(sz[j], u_hat[j]));
    L.intt(w);
    std::vector<ZBit> mz;
    for (int x = 0; x < 256; ++x) {
        Coef d = L.sub(L.cst(v_pub[x]), w[x]);
        mz.push_back((!(d.w < L.c13(833))) & (d.w < L.c13(2497)));
    }
    // The re-encryption with y, e1, e2, checked against c1 and c2.
    std::array<CPoly, K> yz;
    for (int i = 0; i < K; ++i) {
        yz[i].reserve(256);
        for (int j = 0; j < 256; ++j) yz[i].push_back(L.cbd(yn[i * 256 + j]));
        L.ntt(yz[i]);
    }
    for (int i = 0; i < K; ++i) {
        CPoly acc(256, L.cst(0));
        for (int j = 0; j < K; ++j) acc = L.addp(acc, L.mulntt(yz[j], A[j][i]));
        L.intt(acc);
        for (int x = 0; x < 256; ++x) L.check_compress(L.add(acc[x], L.cbd(e1n[i * 256 + x])), 10, c1[i][x]);
    }
    {
        CPoly acc(256, L.cst(0));
        for (int j = 0; j < K; ++j) acc = L.addp(acc, L.mulntt(yz[j], t_hat[j]));
        L.intt(acc);
        for (int x = 0; x < 256; ++x) {
            Coef dm = L.cst(0);                        // Decompress_1(m') = 1665 m'
            for (int b = 0; b < 13; ++b) if (1665 >> b & 1) dm.w.w[b] = mz[x].w;
            dm.v = 1665 * m[x];
            L.check_compress(L.add(L.add(acc[x], L.cbd(e2n[x])), dm), 4, c2[x]);
        }
    }
    auto wit = sess.reveal(L.witness_ok, PUBLIC), key = sess.reveal(L.key_ok, PUBLIC), fo = sess.reveal(L.fo_ok, PUBLIC);
    *mulc = L.mulc; *addc = L.addc;
    // The verifier's clear values are dummies, so only the prover's checks mean anything.
    return party != ALICE || (wit.value_or(false) && key.value_or(false) && fo.value_or(false));
}

struct Count { int keccak, blake3, chacha; };

static bool run_bool(ZKBoolSession& sess, int party, Count n) {
    bool ok = true;
    for (int k = 0; k < n.keccak; ++k) {
        uint64_t clear[25];
        std::array<U64, 25> a;
        for (int i = 0; i < 25; ++i) { clear[i] = rng(); a[i] = sess.input<U64>(ALICE, clear[i]); }
        keccak_zk(sess, a);
        if (k == 0) {
            keccak_clear(clear);
            for (int i = 0; i < 25; ++i) {
                auto v = sess.reveal(a[i], PUBLIC);
                if (party == ALICE && v && *v != clear[i]) ok = false;
            }
        }
    }
    for (int k = 0; k < n.blake3; ++k) {
        uint32_t cvc[8], mc[16], outc[16];
        std::array<U32, 8> cv;
        std::array<U32, 16> m;
        for (int i = 0; i < 8; ++i) { cvc[i] = (uint32_t)rng(); cv[i] = sess.input<U32>(ALICE, cvc[i]); }
        for (int i = 0; i < 16; ++i) { mc[i] = (uint32_t)rng(); m[i] = sess.input<U32>(ALICE, mc[i]); }
        auto out = blake3_zk(sess, cv, m, 0, 64, 1 | 2 | 8 | 16);
        if (k == 0) {
            blake3_clear(cvc, mc, 0, 64, 1 | 2 | 8 | 16, outc);
            for (int i = 0; i < 16; ++i) {
                auto v = sess.reveal(out[i], PUBLIC);
                if (party == ALICE && v && *v != outc[i]) ok = false;
            }
        }
    }
    for (int k = 0; k < n.chacha; ++k) {
        uint32_t keyc[8], noncec[3], outc[16];
        std::array<U32, 8> key;
        std::array<U32, 3> nonce;
        for (int i = 0; i < 8; ++i) { keyc[i] = (uint32_t)rng(); key[i] = sess.input<U32>(ALICE, keyc[i]); }
        for (int i = 0; i < 3; ++i) { noncec[i] = (uint32_t)rng(); nonce[i] = sess.input<U32>(ALICE, noncec[i]); }
        auto out = chacha_zk(sess, key, 0, nonce);
        // The prover reveals the Poly1305 key, the first 32 bytes of block 0.
        chacha_clear(keyc, 0, noncec, outc);
        for (int i = 0; i < 8; ++i) {
            auto v = sess.reveal(out[i], PUBLIC);
            if (party == ALICE && v && *v != outc[i]) ok = false;
        }
    }
    return ok;
}

int main(int argc, char** argv) {
    int party = parse_party(argv);
    std::string mode = argc > 2 ? argv[2] : "dispute";
    long n = argc > 3 ? atol(argv[3]) : 1;
    auto netio = (party == ALICE) ? NetIO::listen(peer_port()) : NetIO::connect(peer_ip(), peer_port());
    BoolIO io(netio.get(), party == ALICE);

    auto start = clock_start();
    bool ok = true;
    long and_gates = 0;
    if (mode == "x25519mul") {
        ZKBoolSession sess(&io, party, 200000L * n + 100000);
        auto secret256 = [&]() {
            bool bits[256];
            for (bool& x : bits) x = rng() & 1;
            auto w = sess.input_bits(ALICE, bits, 256);
            U256 v = U256::constant(sess.ctx(), 0);
            for (int i = 0; i < 256; ++i) v.w[i] = w[i];
            return v;
        };
        U256 a = secret256(), b = secret256();
        for (long i = 0; i < n; ++i) a = mul25519_zk(sess, a, b);
        and_gates = (long)sess.num_and();
        sess.finalize();
    } else if (mode == "arith") {
        setup_zk_arith(&io, party);
        double setup_ms = time_from(start) / 1000.0;
        uint64_t setup_bytes = netio->send_counter + netio->recv_counter;
        __uint128_t ar = 2, br = 3;
        IntFp a((uint64_t)ar, ALICE), b((uint64_t)br, ALICE);
        for (long i = 0; i < n; ++i) { br = (br + ar) % pr; ar = (br * ar) % pr; }
        for (long i = 0; i < n; ++i) { b = b + a; a = b * a; }
        ok = a.reveal((uint64_t)ar);
        finalize_zk_arith();
        if (party == ALICE)
            printf("arith n=%ld setup_ms=%.1f setup_bytes=%llu\n", n, setup_ms, (unsigned long long)setup_bytes);
    } else {
        Count c = {0, 0, 0};
        bool lattice = mode == "mlkem" || mode == "full";
        if (mode == "dispute" || mode == "full") c = {26, 4, 1};
        else if (mode == "keccak") c = {(int)n, 0, 0};
        else if (mode == "blake3") c = {0, (int)n, 0};
        else if (mode == "chacha") c = {0, 0, (int)n};
        // The prepaid AND gates: 1600 per Keccak round, at most 32 per 32-bit
        // addition, and under 11 million for the lattice part (measured).
        long hint = (long)c.keccak * 24 * 1600 + (long)c.blake3 * 7 * 8 * 6 * 32 + (long)c.chacha * (10 * 8 * 4 + 16) * 32;
        ZKBoolSession sess(&io, party, hint + (lattice ? 11000000 : 0) + 100000);
        ok = run_bool(sess, party, c);
        uint64_t hash_ands = sess.num_and();
        long mulc = 0, addc = 0;
        if (lattice) {
            ok = run_mlkem(sess, party, &mulc, &addc) && ok;
            if (party == ALICE) printf("lattice: %ld reductions of products, %ld additions mod q\n", mulc, addc);
        }
        and_gates = (long)sess.num_and();
        if (party == ALICE)
            printf("AND gates: %llu in hashing, %llu in the lattice part\n", (unsigned long long)hash_ands,
                   (unsigned long long)(and_gates - hash_ands));
        sess.finalize();
    }
    double ms = time_from(start) / 1000.0;
    uint64_t sent = netio->send_counter, recv = netio->recv_counter;
    if (party == ALICE)
        printf("mode=%s n=%ld and_gates=%ld ok=%d prover_ms=%.1f prover_sent=%llu prover_recv=%llu\n",
               mode.c_str(), n, and_gates, ok ? 1 : 0, ms, (unsigned long long)sent, (unsigned long long)recv);
    else
        printf("mode=%s verifier_ms=%.1f verifier_sent=%llu verifier_recv=%llu\n",
               mode.c_str(), ms, (unsigned long long)sent, (unsigned long long)recv);
    return ok ? 0 : 1;
}
