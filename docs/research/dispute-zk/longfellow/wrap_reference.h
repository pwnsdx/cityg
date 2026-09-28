// A City-G wrap's key schedule in the clear: its context and ExpandLabel
// inputs in deterministic CBOR, ExpandLabel (BLAKE3 in keyed mode), the
// Poly1305 key of its ChaCha20-Poly1305 seal, the keystream that opens the
// sealed secret, and the seed of the node key that the secret gives.
// Research code.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_WRAP_REFERENCE_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_WRAP_REFERENCE_H_

#include <stddef.h>
#include <stdint.h>

#include <array>
#include <cstring>
#include <string>
#include <vector>

#include "circuits/tests/x25519/arx.h"

namespace proofs {
namespace wrapref {

// CBOR_det heads (RFC 8949, section 4.2.1): shortest form.
inline void cbor_head(std::vector<uint8_t>& out, uint8_t major, uint64_t v) {
  uint8_t m = static_cast<uint8_t>(major << 5);
  if (v < 24) {
    out.push_back(m | static_cast<uint8_t>(v));
    return;
  }
  size_t n = v <= 0xff ? 1 : v <= 0xffff ? 2 : v <= 0xffffffffULL ? 4 : 8;
  out.push_back(m | (n == 1 ? 24 : n == 2 ? 25 : n == 4 ? 26 : 27));
  for (size_t i = n; i-- > 0;) out.push_back((v >> (8 * i)) & 0xff);
}

inline void cbor_bytes(std::vector<uint8_t>& out, const uint8_t* b, size_t n) {
  cbor_head(out, 2, n);
  out.insert(out.end(), b, b + n);
}

inline void cbor_text(std::vector<uint8_t>& out, const std::string& s) {
  cbor_head(out, 3, s.size());
  out.insert(out.end(), s.begin(), s.end());
}

// The wrap's context: [gid, epoch, node level, node index, target level,
// target index, H_L("kem-pk", [target pk])].
inline std::vector<uint8_t> wrap_context(const uint8_t gid[32], uint64_t epoch,
                                         uint64_t node_level,
                                         uint64_t node_index,
                                         uint64_t target_level,
                                         uint64_t target_index,
                                         const uint8_t pk_hash[32]) {
  std::vector<uint8_t> out;
  cbor_head(out, 4, 7);
  cbor_bytes(out, gid, 32);
  cbor_head(out, 0, epoch);
  cbor_head(out, 0, node_level);
  cbor_head(out, 0, node_index);
  cbor_head(out, 0, target_level);
  cbor_head(out, 0, target_index);
  cbor_bytes(out, pk_hash, 32);
  return out;
}

// ExpandLabel's input: ["city-g/v0.4 expand", label, context, length].
inline std::vector<uint8_t> expand_info(const std::string& label,
                                        const std::vector<uint8_t>& context,
                                        uint64_t length) {
  std::vector<uint8_t> out;
  cbor_head(out, 4, 4);
  cbor_text(out, "city-g/v0.4 expand");
  cbor_text(out, label);
  cbor_bytes(out, context.data(), context.size());
  cbor_head(out, 0, length);
  return out;
}

// An ExpandLabel input of 65 to 128 bytes, as BLAKE3 reads it: two blocks
// of 16 little-endian words, the second zero-padded, and its length.
struct Blocks {
  std::array<uint32_t, 16> m0, m1;
  uint32_t len1;
};

inline bool blocks(const std::vector<uint8_t>& info, Blocks& b) {
  if (info.size() <= 64 || info.size() > 128) return false;
  uint8_t buf[128] = {0};
  std::memcpy(buf, info.data(), info.size());
  for (size_t i = 0; i < 16; ++i) {
    b.m0[i] = b.m1[i] = 0;
    for (size_t j = 0; j < 4; ++j) {
      b.m0[i] |= uint32_t{buf[4 * i + j]} << (8 * j);
      b.m1[i] |= uint32_t{buf[64 + 4 * i + j]} << (8 * j);
    }
  }
  b.len1 = static_cast<uint32_t>(info.size() - 64);
  return true;
}

// An input of at most 64 bytes: one block and its length.
inline bool block(const std::vector<uint8_t>& info,
                  std::array<uint32_t, 16>& m0, uint32_t& len0) {
  if (info.size() > 64) return false;
  uint8_t buf[64] = {0};
  std::memcpy(buf, info.data(), info.size());
  for (size_t i = 0; i < 16; ++i) {
    m0[i] = 0;
    for (size_t j = 0; j < 4; ++j) m0[i] |= uint32_t{buf[4 * i + j]} << (8 * j);
  }
  len0 = static_cast<uint32_t>(info.size());
  return true;
}

// DeriveSecret-like input of the node key: ExpandLabel(secret,
// "tree node key", [], 32), 37 bytes.
inline std::vector<uint8_t> node_info() {
  return expand_info("tree node key", {}, 32);
}

inline std::array<uint32_t, 8> words(const uint8_t b[32]) {
  std::array<uint32_t, 8> w;
  for (size_t i = 0; i < 8; ++i) {
    w[i] = 0;
    for (size_t j = 0; j < 4; ++j) w[i] |= uint32_t{b[4 * i + j]} << (8 * j);
  }
  return w;
}

inline void bytes_of(const std::vector<uint32_t>& w, uint8_t* out, size_t n) {
  for (size_t i = 0; i < n; ++i) out[i] = (w[i / 4] >> (8 * (i % 4))) & 0xff;
}

// The key schedule of a wrap from its shared secret, recording the
// witness: ExpandLabel(ss, "wrap key", context, 32) and ExpandLabel(ss,
// "wrap nonce", context, 12), then, for branch 1, ChaCha20's first block,
// whose first 32 bytes are the Poly1305 key, or, for branch 2, the opening
// of the sealed secret and the seed of its node key.
struct Schedule {
  Blocks key_info, nonce_info;
  uint8_t key[32], nonce[12], poly1305_key[32];
  arx::ArxClear clear;  // the witness, and the Poly1305 key's words

  // The key and nonce, then the Poly1305 key.
  bool compute(const uint8_t ss[32], const std::vector<uint8_t>& context) {
    if (!expand(ss, context)) return false;
    arx::Arx<arx::ArxClear> a(clear);
    a.poly1305_key(words(key), nonce_words(), {});
    bytes_of(clear.outputs, poly1305_key, 32);
    return true;
  }

  // The key and nonce alone.
  bool expand(const uint8_t ss[32], const std::vector<uint8_t>& context) {
    if (!blocks(expand_info("wrap key", context, 32), key_info)) return false;
    if (!blocks(expand_info("wrap nonce", context, 12), nonce_info)) {
      return false;
    }
    clear = arx::ArxClear();
    arx::Arx<arx::ArxClear> a(clear);
    std::array<uint32_t, 8> s = words(ss);
    bytes_of(a.keyed_hash2(s, key_info.m0, key_info.m1, key_info.len1, 8), key,
             32);
    bytes_of(a.keyed_hash2(s, nonce_info.m0, nonce_info.m1, nonce_info.len1, 3),
             nonce, 12);
    return true;
  }

  // Branch 2, after expand(): the keystream of block 1 opens the sealed
  // secret, whose ExpandLabel(., "tree node key", [], 32) seeds the node
  // key. The witness goes on the same tape.
  uint8_t opened[32], node_seed[32];
  std::array<uint32_t, 16> node_m0;
  uint32_t node_len0;

  bool open(const uint8_t sealed_ct[32]) {
    arx::Arx<arx::ArxClear> a(clear);
    std::array<uint32_t, 8> stream = a.keystream(words(key), 1, nonce_words());
    std::vector<uint32_t> sw(stream.begin(), stream.end());
    uint8_t ks[32];
    bytes_of(sw, ks, 32);
    for (size_t i = 0; i < 32; ++i) opened[i] = sealed_ct[i] ^ ks[i];
    if (!block(node_info(), node_m0, node_len0)) return false;
    std::vector<uint32_t> seed =
        a.keyed_hash1(words(opened), node_m0, node_len0, 8);
    bytes_of(seed, node_seed, 32);
    return true;
  }

 private:
  std::array<uint32_t, 3> nonce_words() const {
    std::array<uint32_t, 3> w;
    for (size_t i = 0; i < 3; ++i) {
      w[i] = 0;
      for (size_t j = 0; j < 4; ++j) {
        w[i] |= uint32_t{nonce[4 * i + j]} << (8 * j);
      }
    }
    return w;
  }
};

// The seed of the node key of `secret`: ExpandLabel(secret, "tree node
// key", [], 32), as cityg-core's node_key.
inline void node_seed(const uint8_t secret[32], uint8_t out[32]) {
  arx::ArxClear clear;
  arx::Arx<arx::ArxClear> a(clear);
  std::array<uint32_t, 16> m0;
  uint32_t len0;
  block(node_info(), m0, len0);
  bytes_of(a.keyed_hash1(words(secret), m0, len0, 8), out, 32);
}

}  // namespace wrapref
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_X25519_WRAP_REFERENCE_H_
