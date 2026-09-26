// The end of a wrap dispute's statement: ExpandLabel, which is BLAKE3 in
// keyed mode on inputs of one chunk, and the first block of ChaCha20,
// which gives the wrap's Poly1305 key. Research code.
//
// The functions are written once, over a backend. ArxClear computes in the
// clear and records the witness of each addition modulo 2^32: the 32 bits
// of the sum and its carry. ArxCircuit checks it in a Longfellow circuit
// over a prime field, where a sum of packed words is linear and a xor of
// bits costs one multiplication. The words that only xors change (b and d
// in BLAKE3's G and ChaCha20's quarter round) are also witnessed after
// each round, so that chains of xors stay shallow.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_ARX_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_ARX_H_

#include <stddef.h>
#include <stdint.h>

#include <array>
#include <vector>

namespace proofs {
namespace arx {

constexpr uint32_t kBlake3Iv[8] = {0x6A09E667, 0xBB67AE85, 0x3C6EF372,
                                   0xA54FF53A, 0x510E527F, 0x9B05688C,
                                   0x1F83D9AB, 0x5BE0CD19};
constexpr size_t kBlake3Perm[16] = {2, 6,  3,  10, 7,  0,  4,  13,
                                    1, 11, 12, 5,  9, 14, 15, 8};
constexpr uint32_t kChunkStart = 1, kChunkEnd = 2, kRoot = 8, kKeyedHash = 16;
constexpr uint32_t kChaCha[4] = {0x61707865, 0x3320646e, 0x79622d32,
                                 0x6b206574};

// Over a backend B that provides the types Word (a 32-bit word) and Msg (a
// public word), and konst, add (a + b), add_msg (a + b + m), xor_, rotr,
// rotl, checkpoint (the same word, witnessed), and feed_forward (checks
// x + init against a public output word).
template <class B>
class Arx {
 public:
  using Word = typename B::Word;
  using Msg = typename B::Msg;

  explicit Arx(B& b) : b_(b) {}

  // BLAKE3's compression function, counter 0: the 16 output words.
  std::array<Word, 16> compress(const std::array<Word, 8>& cv,
                                std::array<Msg, 16> m, const Word& block_len,
                                uint32_t flags) {
    // Filled by assignment: a circuit's words only copy explicitly.
    std::array<Word, 16> v;
    for (size_t i = 0; i < 8; ++i) v[i] = cv[i];
    for (size_t i = 0; i < 4; ++i) v[8 + i] = k(kBlake3Iv[i]);
    v[12] = k(0);
    v[13] = k(0);
    v[14] = block_len;
    v[15] = k(flags);
    for (size_t r = 0; r < 7; ++r) {
      g(v, 0, 4, 8, 12, m[0], m[1]);
      g(v, 1, 5, 9, 13, m[2], m[3]);
      g(v, 2, 6, 10, 14, m[4], m[5]);
      g(v, 3, 7, 11, 15, m[6], m[7]);
      g(v, 0, 5, 10, 15, m[8], m[9]);
      g(v, 1, 6, 11, 12, m[10], m[11]);
      g(v, 2, 7, 8, 13, m[12], m[13]);
      g(v, 3, 4, 9, 14, m[14], m[15]);
      for (size_t i : {4, 5, 6, 7, 12, 13, 14, 15}) {
        v[i] = b_.checkpoint(v[i]);
      }
      if (r < 6) {
        std::array<Msg, 16> t = m;
        for (size_t i = 0; i < 16; ++i) m[i] = t[kBlake3Perm[i]];
      }
    }
    std::array<Word, 16> out = v;
    for (size_t i = 0; i < 8; ++i) {
      out[i] = b_.xor_(v[i], v[i + 8]);
      out[i + 8] = b_.xor_(v[i + 8], cv[i]);
    }
    return out;
  }

  // BLAKE3's keyed hash of a two-block input (65 to 128 bytes, one chunk):
  // its first n output words. len1 is the second block's length.
  std::vector<Word> keyed_hash2(const std::array<Word, 8>& key,
                                const std::array<Msg, 16>& m0,
                                const std::array<Msg, 16>& m1,
                                const Word& len1, size_t n) {
    std::array<Word, 16> o0 = compress(key, m0, k(64), kKeyedHash | kChunkStart);
    std::array<Word, 8> cv;
    for (size_t i = 0; i < 8; ++i) cv[i] = o0[i];
    std::array<Word, 16> o1 =
        compress(cv, m1, len1, kKeyedHash | kChunkEnd | kRoot);
    return std::vector<Word>(o1.begin(), o1.begin() + n);
  }

  // The first block of ChaCha20 (RFC 8439), counter 0; its words 0 to 7,
  // the Poly1305 key, are checked against out.
  void poly1305_key(const std::array<Word, 8>& key,
                    const std::array<Word, 3>& nonce,
                    const std::array<Msg, 8>& out) {
    std::array<Word, 16> init;
    for (size_t i = 0; i < 4; ++i) init[i] = k(kChaCha[i]);
    for (size_t i = 0; i < 8; ++i) init[4 + i] = key[i];
    init[12] = k(0);
    for (size_t i = 0; i < 3; ++i) init[13 + i] = nonce[i];
    std::array<Word, 16> s = init;
    for (size_t i = 0; i < 10; ++i) {
      qr(s, 0, 4, 8, 12);
      qr(s, 1, 5, 9, 13);
      qr(s, 2, 6, 10, 14);
      qr(s, 3, 7, 11, 15);
      qr(s, 0, 5, 10, 15);
      qr(s, 1, 6, 11, 12);
      qr(s, 2, 7, 8, 13);
      qr(s, 3, 4, 9, 14);
      for (size_t j : {4, 5, 6, 7, 12, 13, 14, 15}) {
        s[j] = b_.checkpoint(s[j]);
      }
    }
    for (size_t i = 0; i < 8; ++i) b_.feed_forward(s[i], init[i], out[i]);
  }

 private:
  Word k(uint32_t x) { return b_.konst(x); }

  void g(std::array<Word, 16>& v, size_t a, size_t b, size_t c, size_t d,
         const Msg& mx, const Msg& my) {
    v[a] = b_.add_msg(v[a], v[b], mx);
    v[d] = b_.rotr(b_.xor_(v[d], v[a]), 16);
    v[c] = b_.add(v[c], v[d]);
    v[b] = b_.rotr(b_.xor_(v[b], v[c]), 12);
    v[a] = b_.add_msg(v[a], v[b], my);
    v[d] = b_.rotr(b_.xor_(v[d], v[a]), 8);
    v[c] = b_.add(v[c], v[d]);
    v[b] = b_.rotr(b_.xor_(v[b], v[c]), 7);
  }

  void qr(std::array<Word, 16>& s, size_t a, size_t b, size_t c, size_t d) {
    s[a] = b_.add(s[a], s[b]);
    s[d] = b_.rotl(b_.xor_(s[d], s[a]), 16);
    s[c] = b_.add(s[c], s[d]);
    s[b] = b_.rotl(b_.xor_(s[b], s[c]), 12);
    s[a] = b_.add(s[a], s[b]);
    s[d] = b_.rotl(b_.xor_(s[d], s[a]), 8);
    s[c] = b_.add(s[c], s[d]);
    s[b] = b_.rotl(b_.xor_(s[b], s[c]), 7);
  }

  B& b_;
};

// In the clear. The tape holds the witness: for each addition, the bits of
// the sum then of the carry (one bit, two for add_msg); for each word fed
// forward, its carry. outputs gets the words fed forward.
struct ArxClear {
  using Word = uint32_t;
  using Msg = uint32_t;

  std::vector<uint8_t> tape;
  std::vector<uint32_t> outputs;

  Word konst(uint32_t x) { return x; }
  Word add(Word a, Word b) { return record(uint64_t{a} + b, 1); }
  Word add_msg(Word a, Word b, Msg m) {
    return record(uint64_t{a} + b + m, 2);
  }
  Word xor_(Word a, Word b) { return a ^ b; }
  Word rotr(Word a, int r) { return (a >> r) | (a << (32 - r)); }
  Word rotl(Word a, int r) { return (a << r) | (a >> (32 - r)); }
  Word checkpoint(Word x) { return record(x, 0); }
  void feed_forward(Word x, Word init, Msg) {
    uint64_t s = uint64_t{x} + init;
    tape.push_back(static_cast<uint8_t>(s >> 32));
    outputs.push_back(static_cast<uint32_t>(s));
  }

 private:
  Word record(uint64_t s, int carry_bits) {
    for (int i = 0; i < 32; ++i) tape.push_back((s >> i) & 1);
    for (int i = 0; i < carry_bits; ++i) tape.push_back((s >> (32 + i)) & 1);
    return static_cast<uint32_t>(s);
  }
};

// In a circuit: next() yields the private inputs of the tape, in order.
template <class LogicCircuit, class Next>
class ArxCircuit {
  using EltW = typename LogicCircuit::EltW;
  using BitW = typename LogicCircuit::BitW;
  using Field = typename LogicCircuit::Field;
  using Elt = typename Field::Elt;

 public:
  using Word = typename LogicCircuit::v32;
  using Msg = EltW;

  ArxCircuit(const LogicCircuit& lc, const Field& f, Next next)
      : lc_(lc), f_(f), next_(next) {
    two32_ = f_.of_scalar(uint64_t{1} << 32);
  }

  Word konst(uint32_t x) { return lc_.template vbit<32>(x); }
  Word add(const Word& a, const Word& b) {
    return witnessed(lc_.add(packed(a), packed(b)), 1);
  }
  Word add_msg(const Word& a, const Word& b, const Msg& m) {
    return witnessed(lc_.add(lc_.add(packed(a), packed(b)), m), 2);
  }
  Word xor_(const Word& a, const Word& b) { return lc_.vxor(a, b); }
  Word rotr(const Word& a, int r) { return lc_.vrotr(a, r); }
  Word rotl(const Word& a, int r) { return lc_.vrotl(a, r); }
  Word checkpoint(const Word& x) { return witnessed(packed(x), 0); }
  void feed_forward(const Word& x, const Word& init, const Msg& out) {
    EltW c = bit();
    lc_.assert_eq(lc_.add(packed(x), packed(init)),
                  lc_.add(out, lc_.mul(two32_, c)));
  }

  EltW packed(const Word& w) const { return lc_.as_scalar(w); }

 private:
  EltW bit() {
    EltW b = next_();
    lc_.assert_is_bit(b);
    return b;
  }

  // The sum's bits and carry, with sum + 2^32 carry = total.
  Word witnessed(const EltW& total, int carry_bits) {
    Word s;
    for (size_t i = 0; i < 32; ++i) s[i] = BitW(bit(), f_);
    EltW carry = lc_.konst(f_.zero());
    for (int i = 0; i < carry_bits; ++i) {
      carry = lc_.axpy(carry, f_.of_scalar(uint64_t{1} << i), bit());
    }
    lc_.assert_eq(total, lc_.add(packed(s), lc_.mul(two32_, carry)));
    return s;
  }

  const LogicCircuit& lc_;
  const Field& f_;
  Next next_;
  Elt two32_;
};

}  // namespace arx
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_ARX_H_
