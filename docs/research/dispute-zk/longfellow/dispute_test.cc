// Tests and benchmarks of a whole City-G wrap dispute, proved with Longfellow
// over F_{2^255-19}: ML-KEM-768's lattice part, X25519 and the Keccak
// permutations of X-Wing's decapsulation, in one circuit. Research code.

#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "algebra/crt.h"
#include "algebra/crt_convolution.h"
#include "algebra/fp.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/x25519/dispute_circuit.h"
#include "circuits/tests/x25519/dispute_witness.h"
#include "circuits/tests/x25519/lattice_circuit.h"
#include "circuits/tests/x25519/lattice_witness.h"
#include "circuits/tests/x25519/mlkem_reference.h"
#include "circuits/tests/x25519/wrap_reference.h"
#include "circuits/tests/x25519/x25519_check.h"
#include "proto/circuit_io.h"
#include "proto/circuit_reader.h"
#include "proto/circuit_writer.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"
#include "zstd.h"

namespace proofs {
namespace {

using F25519 = Fp<4, true>;
const F25519 f25519(
    "57896044618658097711785492504343953926634992332820282019728792003956564819"
    "949");
using Elt = F25519::Elt;
using ConvolutionFactory = CrtConvolutionFactory<CRT256<F25519>, F25519>;
using RSFactory = ReedSolomonFactory<F25519, ConvolutionFactory>;
using LatWitness = LatticeWitness<F25519>;

// Longfellow's parameters for its ECDSA benchmarks: rate 1/7, 132 queries.
constexpr size_t kRate = 7;
constexpr size_t kQueries = 132;

void openssl_x25519(const uint8_t sk[32], const uint8_t peer[32],
                    uint8_t out[32]) {
  EVP_PKEY* key =
      EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, sk, 32);
  EVP_PKEY* other =
      EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer, 32);
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, nullptr);
  size_t len = 32;
  bool ok = EVP_PKEY_derive_init(ctx) == 1 &&
            EVP_PKEY_derive_set_peer(ctx, other) == 1 &&
            EVP_PKEY_derive(ctx, out, &len) == 1 && len == 32;
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(other);
  EVP_PKEY_free(key);
  if (!ok) std::memset(out, 0, 32);
}

std::vector<uint8_t> unhex(const std::string& s) {
  std::vector<uint8_t> out(s.size() / 2);
  for (size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>(std::stoi(s.substr(2 * i, 2), nullptr, 16));
  }
  return out;
}

std::string hex(const uint8_t* b, size_t n) {
  static const char* digits = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; ++i) {
    s += digits[b[i] >> 4];
    s += digits[b[i] & 15];
  }
  return s;
}

// The test vectors of the X-Wing draft, as the x-wing crate ships them, with
// the public key and the ciphertext through their SHA3-256 digests.
struct XWingVector {
  const char *seed, *eseed, *ss, *pk_sha3, *ct_sha3;
};

const XWingVector kXWingVectors[] = {
    {"7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
     "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2"
     "35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2",
     "d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384",
     "5121745904643ad9dfacca7869292c19a8a69533b53e60666b7db910b4ad6367",
     "c0abd149f83f45324ac3a7ddc7606c71f257e5ea86113522834a0ee1bcb34e3e"},
    {"badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea",
     "17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdef"
     "aee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d",
     "f2e86241c64d60f6649fbc6c5b7d17180b780a3f34355e64a85749949c45f150",
     "799b6016e5daa56ffa1b5e79f7caf73413ceecd6df428642404cac41ddee4853",
     "7680b7ba47ae09bac4b43001edcef9d98e50df20026e70ba6a424447e1f2b961"},
    {"ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c9",
     "22a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619"
     "f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b",
     "953f7f4e8c5b5049bdc771d1dffada0dd961477d1a2ae0988baa7ea6898d893f",
     "1ef0c99a06026450564957a5402a788feffbbefdcce55d25de254d0a49eb095a",
     "3088688d63201d5d844170b79f148b2791c15f346ff6f8bd559807fbd442f91f"},
};

TEST(XWing, ReferenceMatchesTestVectors) {
  using namespace mlkem;
  for (const XWingVector& v : kXWingVectors) {
    std::vector<uint8_t> seed = unhex(v.seed), eseed = unhex(v.eseed);
    XWingKey key = xwing_keygen(seed.data(), openssl_x25519);
    uint8_t digest[32];
    sha3_256(key.pk, kXWingPkBytes, digest);
    EXPECT_EQ(hex(digest, 32), v.pk_sha3);

    uint8_t ct[kXWingCtBytes], ss[32];
    xwing_encaps(key.pk, eseed.data(), openssl_x25519, ct, ss);
    sha3_256(ct, kXWingCtBytes, digest);
    EXPECT_EQ(hex(digest, 32), v.ct_sha3);
    EXPECT_EQ(hex(ss, 32), v.ss);

    XWingDecapsulation d = xwing_decaps(key, ct, openssl_x25519);
    EXPECT_TRUE(d.m.fo_ok);
    EXPECT_EQ(hex(d.ss, 32), v.ss);
  }
}

// ---------- the wrap ----------

// ChaCha20-Poly1305 (RFC 8439) with OpenSSL: the ciphertext, then the tag.
std::vector<uint8_t> openssl_seal(const uint8_t key[32], const uint8_t nonce[12],
                                  const std::vector<uint8_t>& aad,
                                  const uint8_t* msg, size_t n) {
  std::vector<uint8_t> out(n + 16);
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  int len = 0;
  bool ok =
      EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr,
                         nullptr) == 1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1 &&
      EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1 &&
      EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(),
                        static_cast<int>(aad.size())) == 1 &&
      EVP_EncryptUpdate(ctx, out.data(), &len, msg, static_cast<int>(n)) == 1 &&
      EVP_EncryptFinal_ex(ctx, out.data() + len, &len) == 1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, out.data() + n) == 1;
  EVP_CIPHER_CTX_free(ctx);
  if (!ok) out.clear();
  return out;
}

// ChaCha20's keystream with OpenSSL, counter 0: its first 32 bytes are the
// Poly1305 key.
void openssl_poly1305_key(const uint8_t key[32], const uint8_t nonce[12],
                          uint8_t out[32]) {
  uint8_t iv[16] = {0}, zero[32] = {0};
  std::memcpy(iv + 4, nonce, 12);
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  int len = 0;
  bool ok =
      EVP_EncryptInit_ex(ctx, EVP_chacha20(), nullptr, key, iv) == 1 &&
      EVP_EncryptUpdate(ctx, out, &len, zero, sizeof(zero)) == 1;
  EVP_CIPHER_CTX_free(ctx);
  if (!ok) std::memset(out, 0, 32);
}

// The tag of ChaCha20-Poly1305 (RFC 8439, section 2.8) from a revealed
// Poly1305 key: what the verifier of a dispute computes.
std::vector<uint8_t> poly1305_tag(const uint8_t otk[32],
                                  const std::vector<uint8_t>& aad,
                                  const uint8_t* ct, size_t n) {
  std::vector<uint8_t> data(aad);
  data.resize((data.size() + 15) / 16 * 16, 0);
  data.insert(data.end(), ct, ct + n);
  data.resize((data.size() + 15) / 16 * 16, 0);
  for (uint64_t len : {uint64_t{aad.size()}, uint64_t{n}}) {
    for (size_t i = 0; i < 8; ++i) data.push_back((len >> (8 * i)) & 0xff);
  }
  std::vector<uint8_t> tag(16);
  EVP_MAC* mac = EVP_MAC_fetch(nullptr, "POLY1305", nullptr);
  EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
  size_t len = 0;
  bool ok = EVP_MAC_init(ctx, otk, 32, nullptr) == 1 &&
            EVP_MAC_update(ctx, data.data(), data.size()) == 1 &&
            EVP_MAC_final(ctx, tag.data(), &len, tag.size()) == 1;
  EVP_MAC_CTX_free(ctx);
  EVP_MAC_free(mac);
  if (!ok) tag.clear();
  return tag;
}

// A wrap that cityg-core's crypto::wrap made, with its key schedule.
struct WrapVector {
  const char *seed, *eseed, *gid, *secret, *pk_hash, *context, *info_key,
      *shared, *wrap_key, *wrap_nonce, *sealed;
  uint64_t epoch, node_level, node_index, target_level, target_index;
  // Three slices of node_key(secret)'s public key: t's first 32 bytes,
  // rho, and pk_X.
  const char *node_t_head, *node_rho, *node_pk_x;
};

const WrapVector kWrap = {
    "01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3da",
    "05121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98"
    "a5b2bfccd9e6f3000d1a2734414e5b6875828f9ca9b6c3d0ddeaf704111e2b38",
    "0205080b0e1114171a1d202326292c2f3235383b3e4144474a4d505356595c5f",
    "09141f2a35404b56616c77828d98a3aeb9c4cfdae5f0fb06111c27323d48535e",
    "5e54bb509aa640a4402ce0d81cfd36e71ec60c0fcd0023459c1e01cdde31ffe3",
    "8758200205080b0e1114171a1d202326292c2f3235383b3e4144474a4d505356"
    "595c5f1a000f424303182902185258205e54bb509aa640a4402ce0d81cfd36e7"
    "1ec60c0fcd0023459c1e01cdde31ffe3",
    "8472636974792d672f76302e3420657870616e646877726170206b6579585087"
    "58200205080b0e1114171a1d202326292c2f3235383b3e4144474a4d50535659"
    "5c5f1a000f424303182902185258205e54bb509aa640a4402ce0d81cfd36e71e"
    "c60c0fcd0023459c1e01cdde31ffe31820",
    "a88f1de549c0ffdffece225ba0320d0bd45a46940a11c82554a444bc71de6cb7",
    "df3abac9c1e626aebe6c9d092ad9a1a94b344558c14e5349095ab86b812aaaa2",
    "8d33d336e8fc2571fa1ccfcf",
    "d7033865a7d37255afd9b6b6b84d9390148286da9b98ee96ef034a8369db6e4b"
    "2d9e9a56b9e4679f4ff6033ed7b6c5e5",
    1000003, 3, 41, 2, 82,
    "3c90bba7aa95feabb22dd78c68314af5f2a735367221191a86ec541c95a1e82a",
    "3c4ee0cecaee87fe1ac500bfc59399c50485c6f5a44e9a9f87cf12d359981587",
    "7653a22e5afa36b330634b2565d08154c9736ebc8af1881c231aedd00e9ce82d"};

std::vector<uint8_t> vector_context() {
  std::vector<uint8_t> gid = unhex(kWrap.gid), pk_hash = unhex(kWrap.pk_hash);
  return wrapref::wrap_context(gid.data(), kWrap.epoch, kWrap.node_level,
                               kWrap.node_index, kWrap.target_level,
                               kWrap.target_index, pk_hash.data());
}

TEST(Wrap, ReferenceMatchesCitygCore) {
  using namespace mlkem;
  std::vector<uint8_t> seed = unhex(kWrap.seed), eseed = unhex(kWrap.eseed);
  XWingKey key = xwing_keygen(seed.data(), openssl_x25519);
  uint8_t ct[kXWingCtBytes], ss[32];
  xwing_encaps(key.pk, eseed.data(), openssl_x25519, ct, ss);
  EXPECT_EQ(hex(ss, 32), kWrap.shared);

  std::vector<uint8_t> context = vector_context();
  EXPECT_EQ(hex(context.data(), context.size()), kWrap.context);
  std::vector<uint8_t> info = wrapref::expand_info("wrap key", context, 32);
  EXPECT_EQ(hex(info.data(), info.size()), kWrap.info_key);

  wrapref::Schedule sch;
  ASSERT_TRUE(sch.compute(ss, context));
  EXPECT_EQ(hex(sch.key, 32), kWrap.wrap_key);
  EXPECT_EQ(hex(sch.nonce, 12), kWrap.wrap_nonce);
  std::vector<uint8_t> secret = unhex(kWrap.secret);
  std::vector<uint8_t> sealed =
      openssl_seal(sch.key, sch.nonce, context, secret.data(), 32);
  EXPECT_EQ(hex(sealed.data(), sealed.size()), kWrap.sealed);

  uint8_t otk[32];
  openssl_poly1305_key(sch.key, sch.nonce, otk);
  EXPECT_EQ(hex(sch.poly1305_key, 32), hex(otk, 32));
  // The revealed Poly1305 key gives the tag of the honest wrap, and not the
  // tag of a wrap whose ciphertext was altered.
  std::vector<uint8_t> tag = poly1305_tag(otk, context, sealed.data(), 32);
  EXPECT_EQ(hex(tag.data(), 16), hex(sealed.data() + 32, 16));
  // Block 1 of the keystream opens the secret, and the node key it seeds is
  // cityg-core's node_key.
  ASSERT_TRUE(sch.open(sealed.data()));
  EXPECT_EQ(hex(sch.opened, 32), kWrap.secret);
  XWingKey node = xwing_keygen(sch.node_seed, openssl_x25519);
  EXPECT_EQ(hex(node.pk, 32), kWrap.node_t_head);
  EXPECT_EQ(hex(node.pk + 1152, 32), kWrap.node_rho);
  EXPECT_EQ(hex(node.pk_x, 32), kWrap.node_pk_x);
  uint8_t seed2[32];
  wrapref::node_seed(secret.data(), seed2);
  EXPECT_EQ(hex(seed2, 32), hex(sch.node_seed, 32));

  sealed[3] ^= 1;
  tag = poly1305_tag(otk, context, sealed.data(), 32);
  EXPECT_NE(hex(tag.data(), 16), hex(sealed.data() + 32, 16));
}

// The public check of ct_X: honest ones pass; the dishonest ones of
// x25519_dleq.py fail, which are the points of order 2, 4 and 8, a point of
// mixed order, a point of the twist and a non-canonical encoding.
TEST(Wrap, PublicCheckOfCtX) {
  std::mt19937_64 rng(7748);
  for (size_t i = 0; i < 20; ++i) {
    uint8_t ek[32], ct_x[32];
    for (auto& b : ek) b = rng() & 0xff;
    mlkem::x25519_base(openssl_x25519, ek, ct_x);
    EXPECT_TRUE(ct_x_in_prime_subgroup(f25519, ct_x));
  }
  std::vector<uint8_t> honest = unhex(
      "ac9c25c71789068801508e09f0e8e7b2ed723ee6dac9b41dd08ef8db2cf69c03");
  EXPECT_TRUE(ct_x_in_prime_subgroup(f25519, honest.data()));
  for (const char* bad :
       {"0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "e616d26d06476919e9fae28f7b388bdd5233d38e71dfdfe2a8e6d3af03b6993b",
        "0200000000000000000000000000000000000000000000000000000000000000",
        "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"}) {
    std::vector<uint8_t> ct_x = unhex(bad);
    EXPECT_FALSE(ct_x_in_prime_subgroup(f25519, ct_x.data())) << bad;
  }
}

// A dispute's instance: an X-Wing key, a ciphertext, its decapsulation,
// and the wrap: its context and, for branch 2, its sealed secret and pk_v.
struct Instance {
  mlkem::XWingKey key;
  uint8_t ct[mlkem::kXWingCtBytes];
  uint8_t ss[32];
  mlkem::XWingDecapsulation d;
  DisputeWrap wrap;
  std::vector<uint8_t> sealed;  // the sealed secret, then its tag
};

// The context is the vector's, with SHA3-256(pk) standing for the hash of
// the key, which is public data like the rest.
std::unique_ptr<Instance> make_instance(const uint8_t seed[32],
                                        const uint8_t eseed[64]) {
  auto in = std::make_unique<Instance>();
  in->key = mlkem::xwing_keygen(seed, openssl_x25519);
  mlkem::xwing_encaps(in->key.pk, eseed, openssl_x25519, in->ct, in->ss);
  in->d = mlkem::xwing_decaps(in->key, in->ct, openssl_x25519);
  std::vector<uint8_t> gid = unhex(kWrap.gid);
  uint8_t pk_hash[32];
  mlkem::sha3_256(in->key.pk, mlkem::kXWingPkBytes, pk_hash);
  in->wrap.context = wrapref::wrap_context(
      gid.data(), kWrap.epoch, kWrap.node_level, kWrap.node_index,
      kWrap.target_level, kWrap.target_index, pk_hash);
  return in;
}

// The instance of the wrap that cityg-core made.
std::unique_ptr<Instance> wrap_instance() {
  std::vector<uint8_t> seed = unhex(kWrap.seed), eseed = unhex(kWrap.eseed);
  auto in = make_instance(seed.data(), eseed.data());
  in->wrap.context = vector_context();
  return in;
}

std::unique_ptr<Instance> random_instance(uint64_t n) {
  std::mt19937_64 rng(n);
  uint8_t seed[32], eseed[64];
  for (auto& b : seed) b = rng() & 0xff;
  for (auto& b : eseed) b = rng() & 0xff;
  return make_instance(seed, eseed);
}

std::unique_ptr<Instance> vector_instance(size_t i) {
  std::vector<uint8_t> seed = unhex(kXWingVectors[i].seed);
  std::vector<uint8_t> eseed = unhex(kXWingVectors[i].eseed);
  return make_instance(seed.data(), eseed.data());
}

// ---------- the lattice part alone ----------

TEST(Lattice, CompressIntervalsPartitionZq) {
  using mlkem::kQ;
  for (int d : {1, 4, 10}) {
    int32_t total = 0;
    for (int32_t c = 0; c < (1 << d); ++c) {
      CompressInterval iv = compress_interval(c, d);
      total += iv.w;
      // The top-bit split of LatticeCircuit covers the width.
      int32_t half = d == 1 ? 1024 : (d == 4 ? 128 : 2);
      EXPECT_GT(iv.w, half);
      EXPECT_LE(iv.w, 2 * half);
    }
    EXPECT_EQ(total, kQ);
    for (int32_t x = 0; x < kQ; ++x) {
      CompressInterval iv = compress_interval(mlkem::compress(x, d), d);
      EXPECT_LT(mlkem::mod_q(x - iv.lo), iv.w);
    }
  }
  EXPECT_EQ(compress_interval(0, 1).lo, -832);
  EXPECT_EQ(compress_interval(1, 1).lo, 833);
}

using EvalBackend = EvaluationBackend<F25519>;
using EvalLogic = Logic<F25519, EvalBackend>;
using EvalLattice = LatticeCircuit<EvalLogic>;

// Evaluates the lattice circuit in the clear at rho.
bool evaluate_lattice(const LatticeStatement& st, const Elt& rho,
                      const std::vector<Elt>& witness,
                      const std::vector<uint8_t>& prf,
                      Reencryption mode = Reencryption::kEqual) {
  const EvalBackend ebk(f25519, /*panic_on_assertion_failure=*/false);
  const EvalLogic l(&ebk, f25519);
  std::vector<Elt> pub = LatWitness::public_inputs(st, rho, f25519, mode);
  size_t ip = 0, iw = 0;
  EvalLattice::Public p;
  p.read([&] { return l.konst(pub[ip++]); }, mode);
  EvalLattice::Witness w;
  w.read([&] { return l.konst(witness[iw++]); }, mode);
  EXPECT_EQ(ip, pub.size());
  EXPECT_EQ(iw, witness.size());
  std::vector<EvalLogic::EltW> prfw;
  for (uint8_t b : prf) prfw.push_back(l.konst(b));
  EvalLattice(l, f25519, mode).assert_lattice(p, w, prfw);
  return !ebk.assertion_failed();
}

Elt random_elt(std::mt19937_64& rng) {
  uint8_t b[32];
  for (auto& x : b) x = rng() & 0xff;
  b[31] &= 0x3f;
  return f25519.to_montgomery(F25519::N::of_bytes(b));
}

TEST(Lattice, AcceptsHonestWitnesses) {
  std::mt19937_64 rng(3329);
  for (size_t i = 0; i < 6; ++i) {
    auto in = i < 3 ? vector_instance(i) : random_instance(i);
    ASSERT_TRUE(in->d.m.fo_ok);
    LatticeStatement st(in->key.pk, in->ct);
    LatWitness lw(f25519);
    for (Reencryption mode : {Reencryption::kNone, Reencryption::kEqual}) {
      ASSERT_TRUE(lw.compute(st, in->key.m.s, in->key.m.e, in->d.m, mode));
      for (size_t k = 0; k < 2; ++k) {
        EXPECT_TRUE(evaluate_lattice(st, random_elt(rng), lw.values(),
                                     lw.prf_bits(), mode));
      }
    }
    // The re-encryption gives the ciphertext back: nothing differs.
    EXPECT_FALSE(lw.compute(st, in->key.m.s, in->key.m.e, in->d.m,
                            Reencryption::kDiffers));
  }
}

// Offsets in the witness, in the order of LatticeCircuit::Witness::read.
constexpr size_t kN = 256, kK = 3;
constexpr size_t kOffS = 0;
constexpr size_t kOffNorm = 2 * kK * kN * 3;
constexpr size_t kOffKKey = kOffNorm + 22;
constexpr size_t kOffHKey = kOffKKey + kK * kN * 12;
constexpr size_t kOffM = kOffHKey + kK * 255;
constexpr size_t kOffDDec = kOffM + kN;

TEST(Lattice, RejectsWrongWitnesses) {
  auto in = vector_instance(0);
  LatticeStatement st(in->key.pk, in->ct);
  LatWitness lw(f25519);
  ASSERT_TRUE(lw.compute(st, in->key.m.s, in->key.m.e, in->d.m,
                         Reencryption::kEqual));
  std::mt19937_64 rng(1);
  const Elt rho = random_elt(rng);
  auto flipped = [&](size_t pos) {
    std::vector<Elt> w = lw.values();
    w[pos] = f25519.subf(f25519.one(), w[pos]);
    return w;
  };
  ASSERT_TRUE(evaluate_lattice(st, rho, lw.values(), lw.prf_bits()));
  // A bit of s, a bit of the norm's slack, a bit of a quotient, a bit of
  // m', a bit of the decryption's offset.
  for (size_t pos : {kOffS + 7, kOffNorm + 3, kOffKKey + 100, kOffM + 17,
                     kOffDDec + 5}) {
    EXPECT_FALSE(evaluate_lattice(st, rho, flipped(pos), lw.prf_bits()));
  }
  // A coefficient of a high half, off by one.
  {
    std::vector<Elt> w = lw.values();
    f25519.add(w[kOffHKey + 9], f25519.one());
    EXPECT_FALSE(evaluate_lattice(st, rho, w, lw.prf_bits()));
  }
  // A bit of the PRF output, which the re-encryption uses.
  {
    std::vector<uint8_t> prf = lw.prf_bits();
    prf[4 * 77] ^= 1;
    EXPECT_FALSE(evaluate_lattice(st, rho, lw.values(), prf));
  }
  // Another ciphertext: the re-encryption no longer matches c1.
  {
    uint8_t ct[mlkem::kXWingCtBytes];
    std::memcpy(ct, in->ct, sizeof(ct));
    ct[100] ^= 0x10;
    LatticeStatement other(in->key.pk, ct);
    EXPECT_FALSE(evaluate_lattice(other, rho, lw.values(), lw.prf_bits()));
  }
}

// A prover who knew rho in advance could satisfy the identities with a
// wrong key: shift s_0[0] by one and absorb the change in the high halves,
// which the circuit does not bound. The forgery passes at that rho and
// fails elsewhere: rho must come after the commitment.
TEST(Lattice, WitnessForgedForAKnownPointFailsElsewhere) {
  auto in = vector_instance(1);
  LatticeStatement st(in->key.pk, in->ct);
  mlkem::PolyVec s = in->key.m.s;
  ASSERT_LT(s[0][0], 3);
  LatWitness lw(f25519);
  ASSERT_TRUE(lw.compute(st, in->key.m.s, in->key.m.e, in->d.m,
                         Reencryption::kEqual));
  std::mt19937_64 rng(2);
  const Elt rho0 = random_elt(rng), rho1 = random_elt(rng);
  std::vector<Elt> pub =
      LatWitness::public_inputs(st, rho0, f25519, Reencryption::kEqual);
  const Elt z = pub[256];
  std::vector<Elt> w = lw.values();
  // s_0[0] + 1, with bits b0 + 2 b1 + 4 b2 = s + 4.
  int32_t v = s[0][0] + 5;
  for (size_t b = 0; b < 3; ++b) w[kOffS + b] = f25519.of_scalar((v >> b) & 1);
  // The norm of s grows by 2 s + 1; its slack shrinks by as much.
  int64_t slack = 0;
  for (size_t b = 0; b < 11; ++b) {
    slack |= int64_t{w[kOffNorm + b] == f25519.one()} << b;
  }
  slack -= 2 * s[0][0] + 1;
  for (size_t b = 0; b < 11; ++b) {
    w[kOffNorm + b] = f25519.of_scalar((slack >> b) & 1);
  }
  // Row i of the key binding gains A_i0(rho0) (public input 258 + 3 i); its
  // high half takes A_i0(rho0) / z. The decryption loses u_0(rho0) (public
  // input 270), which its high half gives back.
  const Elt zinv = f25519.invertf(z);
  for (size_t i = 0; i < kK; ++i) {
    f25519.add(w[kOffHKey + 255 * i], f25519.mulf(pub[258 + 3 * i], zinv));
  }
  const size_t off_h_dec = kOffDDec + kN * 11 + kN * 12;
  f25519.add(w[off_h_dec], f25519.mulf(pub[270], zinv));
  EXPECT_TRUE(evaluate_lattice(st, rho0, w, lw.prf_bits()));
  EXPECT_FALSE(evaluate_lattice(st, rho1, w, lw.prf_bits()));
}

// A ciphertext whose re-encryption fails: an honest one, one bit flipped
// in its ML-KEM part.
std::unique_ptr<Instance> tweaked_instance(uint64_t n, size_t byte) {
  auto in = random_instance(n);
  in->ct[byte] ^= 0x04;
  in->d = mlkem::xwing_decaps(in->key, in->ct, openssl_x25519);
  return in;
}

TEST(Lattice, ReencryptionThatDiffers) {
  std::mt19937_64 rng(4);
  for (size_t byte : {size_t{5}, size_t{1000}}) {
    auto in = tweaked_instance(11, byte);
    ASSERT_FALSE(in->d.m.fo_ok);
    LatticeStatement st(in->key.pk, in->ct);
    LatWitness lw(f25519);
    ASSERT_TRUE(lw.compute(st, in->key.m.s, in->key.m.e, in->d.m,
                           Reencryption::kDiffers));
    const Elt rho = random_elt(rng);
    EXPECT_TRUE(evaluate_lattice(st, rho, lw.values(), lw.prf_bits(),
                                 Reencryption::kDiffers));
    // The same witness against the honest ciphertext: the re-encryption
    // matches it, and its identities fail.
    auto honest = random_instance(11);
    LatticeStatement st0(honest->key.pk, honest->ct);
    EXPECT_FALSE(evaluate_lattice(st0, rho, lw.values(), lw.prf_bits(),
                                  Reencryption::kDiffers));
    // A selection where the coefficients agree has no inverse.
    size_t agree = SIZE_MAX;
    for (size_t k = 0; k < 1024 && agree == SIZE_MAX; ++k) {
      size_t i = k / 256, l = k % 256;
      int d = i < 3 ? mlkem::kDu : mlkem::kDv;
      const uint8_t* at = i < 3 ? in->ct + 320 * i : in->ct + 960;
      const uint8_t* re = i < 3 ? in->d.m.re.c + 320 * i : in->d.m.re.c + 960;
      if (mlkem::byte_decode(at, d)[l] == mlkem::byte_decode(re, d)[l]) {
        agree = k;
      }
    }
    ASSERT_NE(agree, SIZE_MAX);
    EXPECT_FALSE(lw.compute(st, in->key.m.s, in->key.m.e, in->d.m,
                            Reencryption::kDiffers, agree));
    EXPECT_FALSE(evaluate_lattice(st, rho, lw.values(), lw.prf_bits(),
                                  Reencryption::kDiffers));
  }
}

using CompilerBackendType = CompilerBackend<F25519>;
using LogicCircuit = Logic<F25519, CompilerBackendType>;
using EltW = LogicCircuit::EltW;
using Lattice = LatticeCircuit<LogicCircuit>;

std::unique_ptr<Circuit<F25519>> make_lattice_circuit(Reencryption mode) {
  QuadCircuit<F25519> Q(f25519);
  const CompilerBackendType cbk(&Q);
  const LogicCircuit lc(&cbk, f25519);
  Lattice::Public p;
  p.read([&] { return lc.eltw_input(); }, mode);
  Q.private_input();
  Lattice::Witness w;
  w.read([&] { return lc.eltw_input(); }, mode);
  std::vector<EltW> prf(Lattice::kPrfs * Lattice::kPrfBits);
  for (auto& b : prf) {
    b = lc.eltw_input();
    lc.assert_is_bit(b);
  }
  Lattice(lc, f25519, mode).assert_lattice(p, w, prf);
  auto c = Q.mkcircuit(/*nc=*/1);
  dump_info("lattice", Q);
  return c;
}

// Fiat-Shamir starts from the statement: the public key and the ciphertext.
std::vector<uint8_t> statement_digest(const Instance& in) {
  std::vector<uint8_t> buf(in.key.pk, in.key.pk + mlkem::kXWingPkBytes);
  buf.insert(buf.end(), in.ct, in.ct + mlkem::kXWingCtBytes);
  std::vector<uint8_t> digest(32);
  mlkem::sha3_256(buf.data(), buf.size(), digest.data());
  return digest;
}

struct LatticeProof {
  Reencryption mode;
  std::unique_ptr<Circuit<F25519>> circuit;
  ConvolutionFactory factory{f25519};
  RSFactory rsf{factory, f25519};
  std::unique_ptr<ZkProof<F25519>> proof;
};

// Commit to the witness, draw rho from the transcript, then prove with the
// public inputs rho gives.
void prove_lattice(LatticeProof& lp, const Instance& in,
                   const LatWitness& lw) {
  const Circuit<F25519>& c = *lp.circuit;
  LatticeStatement st(in.key.pk, in.ct);
  Dense<F25519> W(1, c.ninputs);
  DenseFiller<F25519> filler(W);
  filler.push_back(f25519.one());
  for (size_t i = 1; i < c.npub_in; ++i) filler.push_back(f25519.zero());
  lw.fill_witness(filler);
  lw.fill_prf(filler);
  ASSERT_EQ(filler.size(), c.ninputs);
  lp.proof = std::make_unique<ZkProof<F25519>>(c, kRate, kQueries);
  std::vector<uint8_t> digest = statement_digest(in);
  Transcript tp(digest.data(), digest.size());
  SecureRandomEngine rng;
  ZkProver<F25519, RSFactory> prover(c, f25519, lp.rsf);
  prover.commit(*lp.proof, W, tp, rng);
  const Elt rho = tp.elt(f25519);
  std::vector<Elt> pub = LatWitness::public_inputs(st, rho, f25519, lp.mode);
  ASSERT_EQ(pub.size() + 1, c.npub_in);
  for (size_t i = 0; i < pub.size(); ++i) W.v_[1 + i] = pub[i];
  ASSERT_TRUE(prover.prove(*lp.proof, W, tp));
}

bool verify_lattice(const LatticeProof& lp, const Instance& in) {
  const Circuit<F25519>& c = *lp.circuit;
  std::vector<uint8_t> digest = statement_digest(in);
  Transcript tv(digest.data(), digest.size());
  ZkVerifier<F25519, RSFactory> verifier(c, lp.rsf, kRate, kQueries, f25519);
  verifier.recv_commitment(*lp.proof, tv);
  const Elt rho = tv.elt(f25519);
  LatticeStatement st(in.key.pk, in.ct);
  std::vector<Elt> pub = LatWitness::public_inputs(st, rho, f25519, lp.mode);
  Dense<F25519> P(1, c.npub_in);
  DenseFiller<F25519> filler(P);
  filler.push_back(f25519.one());
  for (const Elt& x : pub) filler.push_back(x);
  return verifier.verify(*lp.proof, P, tv);
}

TEST(Lattice, ZkProverVerifier) {
  set_log_level(INFO);
  for (Reencryption mode : {Reencryption::kNone, Reencryption::kEqual}) {
    LatticeProof lp;
    lp.mode = mode;
    lp.circuit = make_lattice_circuit(mode);
    auto in = vector_instance(0);
    LatticeStatement st(in->key.pk, in->ct);
    LatWitness lw(f25519);
    ASSERT_TRUE(lw.compute(st, in->key.m.s, in->key.m.e, in->d.m, mode));
    prove_lattice(lp, *in, lw);
    std::vector<uint8_t> buf;
    lp.proof->write(buf, f25519);
    log(INFO, "lattice, mode %d: %zu inputs (%zu public), proof %zu bytes",
        static_cast<int>(mode), lp.circuit->ninputs, lp.circuit->npub_in,
        buf.size());
    EXPECT_TRUE(verify_lattice(lp, *in));
    // The verifier of another ciphertext rejects it.
    auto other = vector_instance(1);
    EXPECT_FALSE(verify_lattice(lp, *other));
  }
}

// ---------- the whole dispute ----------

using Dispute = DisputeCircuit<LogicCircuit, F25519>;
using DWitness = DisputeWitness<F25519>;

const char* statement_name(Statement st) {
  switch (st) {
    case Statement::kWrap:
      return "the wrap does not open (G, X25519, combiner)";
    case Statement::kWrongSecret:
      return "the wrap opens to the wrong secret";
    case Statement::kWrongSecretShort:
      return "the wrap opens to the wrong secret, short";
    case Statement::kWholeDecapsulation:
      return "the whole decapsulation (and its re-encryption)";
    case Statement::kReencryptionDiffers:
      return "a re-encryption that differs";
  }
  return "";
}

std::unique_ptr<Circuit<F25519>> make_dispute_circuit(Statement st) {
  QuadCircuit<F25519> Q(f25519);
  const CompilerBackendType cbk(&Q);
  const LogicCircuit lc(&cbk, f25519);
  Dispute::Public p;
  p.read([&] { return lc.eltw_input(); }, st);
  Q.private_input();
  auto w = std::make_unique<Dispute::Witness>();
  w->input(lc, st);
  Dispute(lc, f25519, st).assert_dispute(p, *w);
  auto c = Q.mkcircuit(/*nc=*/1);
  dump_info(statement_name(st), Q);
  return c;
}

// Each statement's circuit, compiled once for the tests.
const Circuit<F25519>* dispute_circuit(Statement st) {
  static std::unique_ptr<Circuit<F25519>> circuits[5];
  std::unique_ptr<Circuit<F25519>>& c = circuits[static_cast<size_t>(st)];
  if (c == nullptr) c = make_dispute_circuit(st);
  return c.get();
}

// The public inputs before those that rho gives: the constant one, then
// pk_X and ct_X as field elements, three strings of 256 bits and
// ExpandLabel's inputs (two blocks of 16 words and a length on 32 bits,
// twice); then the Poly1305 key's 8 words (branch 1), or the sealed
// secret's 256 bits and pk_v, 256 bits of its seed, pk_X,v and, unless the
// statement is short, the 768 coefficients of t_v (branch 2). Or only
// H(ek).
size_t fixed_public(Statement st) {
  if (!dispute_combines(st)) return 1 + 256;
  size_t n = 1 + 2 + 3 * 256 + 2 * (32 + 32);
  if (!dispute_opens(st)) return n + 8;
  return n + 256 + 256 + 1 + (dispute_node_t(st) ? 768 : 0);
}

// Fiat-Shamir starts from the statement: the public key, the ciphertext,
// the wrap's context and, for branch 2, its sealed secret and pk_v.
std::vector<uint8_t> dispute_digest(const Instance& in, Statement st) {
  std::vector<uint8_t> buf(in.key.pk, in.key.pk + mlkem::kXWingPkBytes);
  buf.insert(buf.end(), in.ct, in.ct + mlkem::kXWingCtBytes);
  buf.insert(buf.end(), in.wrap.context.begin(), in.wrap.context.end());
  if (dispute_opens(st)) {
    buf.insert(buf.end(), in.wrap.sealed.begin(), in.wrap.sealed.end());
    buf.insert(buf.end(), in.wrap.pk_v.begin(), in.wrap.pk_v.end());
  }
  std::vector<uint8_t> digest(32);
  mlkem::sha3_256(buf.data(), buf.size(), digest.data());
  return digest;
}

struct DisputeProof {
  Statement st;
  size_t block_enc = 0;  // Ligero's row length; 0: the smallest proof
  const Circuit<F25519>* circuit = nullptr;
  ConvolutionFactory factory{f25519};
  RSFactory rsf{factory, f25519};
  std::unique_ptr<ZkProof<F25519>> proof;
};

// Commit, draw rho, then prove; false if the witness does not satisfy the
// circuit. flip, if set, flips that private input before committing.
bool prove_dispute(DisputeProof& dp, const Instance& in, const DWitness& dw,
                   size_t flip = SIZE_MAX) {
  const Circuit<F25519>& c = *dp.circuit;
  const size_t fixed = fixed_public(dp.st);
  Dense<F25519> W(1, c.ninputs);
  DenseFiller<F25519> filler(W);
  filler.push_back(f25519.one());
  dw.fill_public(filler);
  EXPECT_EQ(filler.size(), fixed);
  while (filler.size() < c.npub_in) filler.push_back(f25519.zero());
  dw.fill_witness(filler);
  EXPECT_EQ(filler.size(), c.ninputs);
  if (flip != SIZE_MAX) {
    size_t i = c.npub_in + flip;
    W.v_[i] = f25519.subf(f25519.one(), W.v_[i]);
  }
  dp.proof = dp.block_enc == 0
                 ? std::make_unique<ZkProof<F25519>>(c, kRate, kQueries)
                 : std::make_unique<ZkProof<F25519>>(c, kRate, kQueries,
                                                     dp.block_enc);
  std::vector<uint8_t> digest = dispute_digest(in, dp.st);
  Transcript tp(digest.data(), digest.size());
  SecureRandomEngine rng;
  ZkProver<F25519, RSFactory> prover(c, f25519, dp.rsf);
  prover.commit(*dp.proof, W, tp, rng);
  std::vector<Elt> lat = dw.lattice_public(tp.elt(f25519));
  EXPECT_EQ(fixed + lat.size(), c.npub_in);
  for (size_t i = 0; i < lat.size(); ++i) W.v_[fixed + i] = lat[i];
  return prover.prove(*dp.proof, W, tp);
}

// The verifier knows the statement: the public key, the ciphertext, the
// wrap and, in these tests only, the shared secret.
bool verify_dispute(const DisputeProof& dp, const Instance& in,
                    const DWitness& dw) {
  const Circuit<F25519>& c = *dp.circuit;
  std::vector<uint8_t> digest = dispute_digest(in, dp.st);
  Transcript tv(digest.data(), digest.size());
  std::unique_ptr<ZkVerifier<F25519, RSFactory>> v =
      dp.block_enc == 0
          ? std::make_unique<ZkVerifier<F25519, RSFactory>>(
                c, dp.rsf, kRate, kQueries, f25519)
          : std::make_unique<ZkVerifier<F25519, RSFactory>>(
                c, dp.rsf, kRate, kQueries, dp.block_enc, f25519);
  ZkVerifier<F25519, RSFactory>& verifier = *v;
  verifier.recv_commitment(*dp.proof, tv);
  std::vector<Elt> lat = dw.lattice_public(tv.elt(f25519));
  Dense<F25519> P(1, c.npub_in);
  DenseFiller<F25519> filler(P);
  filler.push_back(f25519.one());
  dw.fill_public(filler);
  for (const Elt& x : lat) filler.push_back(x);
  return verifier.verify(*dp.proof, P, tv);
}

// In the order of DISPUTE_STATEMENT and of the benchmarks' arguments.
const Statement kStatements[] = {
    Statement::kWrap, Statement::kWholeDecapsulation,
    Statement::kReencryptionDiffers, Statement::kWrongSecret,
    Statement::kWrongSecretShort};
constexpr size_t kNumStatements = sizeof(kStatements) / sizeof(kStatements[0]);

// The node key of a secret, as cityg-core's node_key derives it.
std::vector<uint8_t> node_public_key(const uint8_t secret[32]) {
  uint8_t seed[32];
  wrapref::node_seed(secret, seed);
  mlkem::XWingKey k = mlkem::xwing_keygen(seed, openssl_x25519);
  return std::vector<uint8_t>(k.pk, k.pk + mlkem::kXWingPkBytes);
}

// Where the published pk_v differs from the node key of the sealed secret.
enum class Wrong { kNothing, kSeed, kT, kPkX, kNotCanonical };

// Branch 2: the committer seals a secret in the wrap, and publishes as pk_v
// the node key of another secret (kSeed), the secret's node key with one
// coefficient of t_hat, or pk_X, changed, or the node key of another
// secret with a coefficient of t_hat encoded above q (kNotCanonical).
// Instance 0 is cityg-core's wrap, whose sealed secret is the vector's.
std::unique_ptr<Instance> wrong_secret_instance(uint64_t n,
                                                Wrong wrong = Wrong::kSeed) {
  auto in = n == 0 ? wrap_instance() : random_instance(n);
  std::mt19937_64 rng(n + 1000);
  uint8_t secret[32];
  if (n == 0) {
    std::vector<uint8_t> s = unhex(kWrap.secret);
    std::memcpy(secret, s.data(), 32);
  } else {
    for (auto& b : secret) b = rng() & 0xff;
  }
  wrapref::Schedule sch;
  if (!sch.expand(in->ss, in->wrap.context)) return nullptr;
  in->sealed = openssl_seal(sch.key, sch.nonce, in->wrap.context, secret, 32);
  std::memcpy(in->wrap.sealed.data(), in->sealed.data(), 32);

  std::vector<uint8_t>& pk_v = in->wrap.pk_v;
  uint8_t other[32];
  std::memcpy(other, secret, 32);
  other[0] ^= 1;
  const bool another = wrong == Wrong::kSeed || wrong == Wrong::kNotCanonical;
  pk_v = node_public_key(another ? other : secret);
  uint8_t* t1 = pk_v.data() + 384;  // t_hat_1
  mlkem::Poly t_hat = mlkem::byte_decode(t1, 12);
  if (wrong == Wrong::kT) {
    t_hat[17] = (t_hat[17] + 1) % mlkem::kQ;
    mlkem::byte_encode(t_hat, 12, t1);
  } else if (wrong == Wrong::kNotCanonical) {
    // The same value modulo q, on 12 bits.
    for (size_t l = 0; l < mlkem::kN; ++l) {
      if (t_hat[l] < 4096 - mlkem::kQ) {
        t_hat[l] += mlkem::kQ;
        break;
      }
    }
    mlkem::byte_encode(t_hat, 12, t1);
  } else if (wrong == Wrong::kPkX) {
    uint8_t scalar[32];
    for (auto& b : scalar) b = rng() & 0xff;
    mlkem::x25519_base(openssl_x25519, scalar, pk_v.data() + mlkem::kEkBytes);
  }
  return in;
}

// An instance for each statement: honest, with a re-encryption that fails,
// or with a wrap that opens to the wrong secret.
std::unique_ptr<Instance> statement_instance(Statement st, uint64_t n) {
  if (st == Statement::kReencryptionDiffers) return tweaked_instance(n, 700);
  if (dispute_opens(st)) return wrong_secret_instance(n);
  return n < 3 ? vector_instance(n) : random_instance(n);
}

void check_statement(Statement st) {
  set_log_level(INFO);
  DisputeProof dp;
  dp.st = st;
  dp.circuit = dispute_circuit(st);
  auto in = statement_instance(st, 0);
  ASSERT_NE(in, nullptr);
  DWitness dw(f25519);
  ASSERT_TRUE(dw.compute(in->key, in->ct, in->d, st, in->wrap));
  ASSERT_TRUE(prove_dispute(dp, *in, dw));
  std::vector<uint8_t> buf;
  dp.proof->write(buf, f25519);
  log(INFO, "dispute, %s: %zu inputs (%zu public), proof %zu bytes",
      statement_name(st), dp.circuit->ninputs, dp.circuit->npub_in,
      buf.size());
  EXPECT_TRUE(verify_dispute(dp, *in, dw));

  // Another statement: the same proof does not verify.
  auto other = statement_instance(st, 2);
  ASSERT_NE(other, nullptr);
  DWitness dw2(f25519);
  ASSERT_TRUE(dw2.compute(other->key, other->ct, other->d, st, other->wrap));
  EXPECT_FALSE(verify_dispute(dp, *other, dw2));
}

TEST(Dispute, TheWrap) { check_statement(Statement::kWrap); }

// The wrap that cityg-core made, and the same wrap with its ciphertext
// altered: the proof is the same, and the tag that the verifier computes
// from the revealed Poly1305 key tells them apart.
TEST(Dispute, TheWrapConvictsAnAlteredWrap) {
  set_log_level(ERROR);
  const Statement st = Statement::kWrap;
  DisputeProof dp;
  dp.st = st;
  dp.circuit = dispute_circuit(st);
  auto in = wrap_instance();
  DWitness dw(f25519);
  ASSERT_TRUE(dw.compute(in->key, in->ct, in->d, st, in->wrap));
  ASSERT_TRUE(prove_dispute(dp, *in, dw));
  ASSERT_TRUE(verify_dispute(dp, *in, dw));
  std::vector<uint8_t> sealed = unhex(kWrap.sealed);
  std::vector<uint8_t> tag =
      poly1305_tag(dw.poly1305_key(), in->wrap.context, sealed.data(), 32);
  EXPECT_EQ(hex(tag.data(), 16), hex(sealed.data() + 32, 16));
  sealed[17] ^= 0x80;
  tag = poly1305_tag(dw.poly1305_key(), in->wrap.context, sealed.data(), 32);
  EXPECT_NE(hex(tag.data(), 16), hex(sealed.data() + 32, 16));
}

TEST(Dispute, TheWholeDecapsulation) {
  check_statement(Statement::kWholeDecapsulation);
}
TEST(Dispute, AReencryptionThatDiffers) {
  check_statement(Statement::kReencryptionDiffers);
}
TEST(Dispute, TheWrapOpensToTheWrongSecret) {
  check_statement(Statement::kWrongSecret);
}
TEST(Dispute, TheWrapOpensToTheWrongSecretShort) {
  check_statement(Statement::kWrongSecretShort);
}

// Branch 2 on cityg-core's wrap. The witness opens the vector's secret and
// derives cityg-core's node key from it; the proof finds where pk_v
// differs from that key, in the matrix seed, in t or in pk_X. An honest
// pk_v, or one that no key generation gives, has no witness, and a place
// where the keys agree gives no proof.
TEST(Dispute, TheWrongSecretAtEachPlace) {
  set_log_level(ERROR);
  const Statement st = Statement::kWrongSecret;
  DisputeProof dp;
  dp.st = st;
  dp.circuit = dispute_circuit(st);
  const size_t seed_end = 256, t_end = 256 + 768;
  for (Wrong wrong : {Wrong::kSeed, Wrong::kT, Wrong::kPkX}) {
    auto in = wrong_secret_instance(0, wrong);
    ASSERT_NE(in, nullptr);
    EXPECT_EQ(hex(in->sealed.data(), in->sealed.size()), kWrap.sealed);
    DWitness dw(f25519);
    ASSERT_TRUE(dw.compute(in->key, in->ct, in->d, st, in->wrap));
    EXPECT_EQ(hex(dw.opened(), 32), kWrap.secret);
    EXPECT_EQ(hex(dw.node().ek, 32), kWrap.node_t_head);
    EXPECT_EQ(hex(dw.node().rho, 32), kWrap.node_rho);
    EXPECT_EQ(hex(dw.node_pk_x(), 32), kWrap.node_pk_x);
    const size_t place = dw.place();
    if (wrong == Wrong::kSeed) EXPECT_LT(place, seed_end);
    if (wrong == Wrong::kT) {
      EXPECT_GE(place, seed_end);
      EXPECT_LT(place, t_end);
    }
    if (wrong == Wrong::kPkX) EXPECT_EQ(place, t_end);
    ASSERT_TRUE(prove_dispute(dp, *in, dw));
    EXPECT_TRUE(verify_dispute(dp, *in, dw));
  }
  auto honest = wrong_secret_instance(0, Wrong::kNothing);
  ASSERT_NE(honest, nullptr);
  DWitness dw(f25519);
  EXPECT_FALSE(dw.compute(honest->key, honest->ct, honest->d, st,
                          honest->wrap));
  // Forced to select pk_X, where the keys agree: the difference has no
  // inverse.
  EXPECT_FALSE(dw.compute(honest->key, honest->ct, honest->d, st,
                          honest->wrap, t_end));
  EXPECT_FALSE(prove_dispute(dp, *honest, dw));
  auto odd = wrong_secret_instance(0, Wrong::kNotCanonical);
  ASSERT_NE(odd, nullptr);
  EXPECT_FALSE(NodeStatement(odd->wrap.pk_v.data()).t_canonical);
  EXPECT_FALSE(dw.compute(odd->key, odd->ct, odd->d, st, odd->wrap));
}

// The short statement of branch 2 on the same wraps: it convicts when the
// matrix seed or pk_X differs, at a place among those 257 that it does not
// reveal; when only t differs, it has no witness, and the full statement
// is needed.
TEST(Dispute, TheShortStatementCoversTheSeedAndPkX) {
  set_log_level(ERROR);
  const Statement st = Statement::kWrongSecretShort;
  DisputeProof dp;
  dp.st = st;
  dp.circuit = dispute_circuit(st);
  const size_t seed_end = 256;
  for (Wrong wrong : {Wrong::kSeed, Wrong::kPkX}) {
    auto in = wrong_secret_instance(0, wrong);
    ASSERT_NE(in, nullptr);
    DWitness dw(f25519);
    ASSERT_TRUE(dw.compute(in->key, in->ct, in->d, st, in->wrap));
    EXPECT_EQ(hex(dw.node().rho, 32), kWrap.node_rho);
    EXPECT_EQ(hex(dw.node_pk_x(), 32), kWrap.node_pk_x);
    if (wrong == Wrong::kSeed) EXPECT_LT(dw.place(), seed_end);
    if (wrong == Wrong::kPkX) EXPECT_EQ(dw.place(), seed_end);
    ASSERT_TRUE(prove_dispute(dp, *in, dw));
    EXPECT_TRUE(verify_dispute(dp, *in, dw));
  }
  auto only_t = wrong_secret_instance(0, Wrong::kT);
  ASSERT_NE(only_t, nullptr);
  DWitness dw(f25519);
  EXPECT_FALSE(dw.compute(only_t->key, only_t->ct, only_t->d, st,
                          only_t->wrap));
  auto honest = wrong_secret_instance(0, Wrong::kNothing);
  ASSERT_NE(honest, nullptr);
  EXPECT_FALSE(dw.compute(honest->key, honest->ct, honest->d, st,
                          honest->wrap));
  EXPECT_FALSE(dw.compute(honest->key, honest->ct, honest->d, st,
                          honest->wrap, seed_end));
  EXPECT_FALSE(prove_dispute(dp, *honest, dw));
}

TEST(Dispute, WrongWitnessesGiveNoProof) {
  set_log_level(ERROR);
  const Statement st = Statement::kWrap;
  DisputeProof dp;
  dp.st = st;
  dp.circuit = dispute_circuit(st);
  auto in = random_instance(7);
  DWitness dw(f25519);
  ASSERT_TRUE(dw.compute(in->key, in->ct, in->d, st, in->wrap));
  // A bit of sk_X, a bit of G's last state, a bit of the combiner's last
  // state, the first bit of s, the last carry of ChaCha20.
  const size_t x25519_inputs = 256 + 2 * 4 * 255 + 1 + 255;
  const size_t block = 4 * 25 * 64;
  const size_t last = dp.circuit->ninputs - dp.circuit->npub_in - 1;
  for (size_t flip : {size_t{10}, x25519_inputs + block - 1,
                      x25519_inputs + 2 * block - 3,
                      x25519_inputs + 2 * block, last}) {
    EXPECT_FALSE(prove_dispute(dp, *in, dw, flip));
    EXPECT_FALSE(verify_dispute(dp, *in, dw));
  }
}

// Ligero's row length trades the proof's size against the verifier's time,
// which the Reed-Solomon encoding over F_{2^255-19} dominates. Run with
// --gtest_also_run_disabled_tests.
TEST(Dispute, DISABLED_RowLengths) {
  set_log_level(ERROR);
  for (Statement st : kStatements) {
    DisputeProof dp;
    dp.st = st;
    dp.circuit = dispute_circuit(st);
    auto in = statement_instance(st, 1);
    DWitness dw(f25519);
    ASSERT_TRUE(dw.compute(in->key, in->ct, in->d, st, in->wrap));
    for (size_t be : {size_t{0}, size_t{4096}, size_t{8192}, size_t{16384},
                      size_t{32768}}) {
      dp.block_enc = be;
      using Clock = std::chrono::steady_clock;
      auto t0 = Clock::now();
      ASSERT_TRUE(prove_dispute(dp, *in, dw));
      auto t1 = Clock::now();
      EXPECT_TRUE(verify_dispute(dp, *in, dw));
      auto t2 = Clock::now();
      std::vector<uint8_t> buf;
      dp.proof->write(buf, f25519);
      auto ms = [](auto d) {
        return std::chrono::duration<double, std::milli>(d).count();
      };
      printf("%s, block_enc %zu (%zu): prover %.0f ms, verifier %.0f ms, "
             "proof %zu bytes\n",
             statement_name(st), be, dp.proof->param.block_enc, ms(t1 - t0),
             ms(t2 - t1), buf.size());
    }
  }
}

// The resident memory at its peak, in MB, since the last reset of the
// peak (Linux).
long peak_rss_mb() {
  FILE* f = fopen("/proc/self/status", "r");
  if (f == nullptr) return -1;
  char line[256];
  long kb = -1;
  while (fgets(line, sizeof(line), f) != nullptr) {
    if (strncmp(line, "VmHWM:", 6) == 0) kb = atol(line + 6);
  }
  fclose(f);
  return kb / 1024;
}

void reset_peak_rss() {
  FILE* f = fopen("/proc/self/clear_refs", "w");
  if (f != nullptr) {
    fputs("5", f);
    fclose(f);
  }
}

// The statement that DISPUTE_STATEMENT names by its index in kStatements,
// 0 to 4; the first by default.
Statement env_statement() {
  const char* env = getenv("DISPUTE_STATEMENT");
  size_t m = env == nullptr ? 0 : static_cast<size_t>(atoi(env));
  return kStatements[m % kNumStatements];
}

// The memory of the compiler, the prover and the verifier, each measured
// from its own start, for the statement DISPUTE_STATEMENT alone, so that a
// process measures one statement. Run with --gtest_also_run_disabled_tests.
TEST(Dispute, DISABLED_Memory) {
  set_log_level(ERROR);
  const Statement st = env_statement();
  reset_peak_rss();
  std::unique_ptr<Circuit<F25519>> circuit = make_dispute_circuit(st);
  long compiled = peak_rss_mb();
  DisputeProof dp;
  dp.st = st;
  dp.circuit = circuit.get();
  auto in = statement_instance(st, 1);
  DWitness dw(f25519);
  ASSERT_TRUE(dw.compute(in->key, in->ct, in->d, st, in->wrap));
  reset_peak_rss();
  long base = peak_rss_mb();
  ASSERT_TRUE(prove_dispute(dp, *in, dw));
  long prover = peak_rss_mb();
  reset_peak_rss();
  EXPECT_TRUE(verify_dispute(dp, *in, dw));
  long verifier = peak_rss_mb();
  printf("%s: compiler %ld MB; with the circuit loaded (%ld MB), prover "
         "%ld MB, verifier %ld MB\n",
         statement_name(st), compiled, base, prover, verifier);
}

// The circuit as a phone would get it: serialized and compressed with zstd,
// as Longfellow's mdoc circuits are, then loaded by a process that never
// compiled it. With DISPUTE_CIRCUIT naming a file that does not exist, the
// test compiles the circuit of DISPUTE_STATEMENT and writes it there; run
// again, it loads it, proves and verifies, and prints the memory at each
// step; without DISPUTE_CIRCUIT, it is skipped. Run with
// --gtest_also_run_disabled_tests.
TEST(Dispute, DISABLED_Serialized) {
  set_log_level(ERROR);
  const Statement st = env_statement();
  const char* path = getenv("DISPUTE_CIRCUIT");
  if (path == nullptr) GTEST_SKIP() << "DISPUTE_CIRCUIT is not set";
  FILE* file = fopen(path, "rb");
  if (file == nullptr) {
    std::unique_ptr<Circuit<F25519>> c = make_dispute_circuit(st);
    std::vector<uint8_t> bytes;
    CircuitWriter<F25519>(f25519, FieldID::NONE).to_bytes(*c, bytes);
    std::vector<uint8_t> z(ZSTD_compressBound(bytes.size()));
    size_t zl =
        ZSTD_compress(z.data(), z.size(), bytes.data(), bytes.size(), 16);
    ASSERT_FALSE(ZSTD_isError(zl));
    file = fopen(path, "wb");
    ASSERT_NE(file, nullptr);
    ASSERT_EQ(fwrite(z.data(), 1, zl, file), zl);
    fclose(file);
    printf("%s: circuit %zu bytes, %zu with zstd\n", statement_name(st),
           bytes.size(), zl);
    return;
  }
  reset_peak_rss();
  long start = peak_rss_mb();
  auto t0 = std::chrono::steady_clock::now();
  std::vector<uint8_t> z;
  uint8_t buf[1 << 16];
  for (size_t n; (n = fread(buf, 1, sizeof(buf), file)) > 0;) {
    z.insert(z.end(), buf, buf + n);
  }
  fclose(file);
  std::unique_ptr<Circuit<F25519>> circuit;
  {
    std::vector<uint8_t> bytes(ZSTD_getFrameContentSize(z.data(), z.size()));
    size_t n = ZSTD_decompress(bytes.data(), bytes.size(), z.data(), z.size());
    ASSERT_EQ(n, bytes.size());
    ReadBuffer rb(bytes);
    circuit = CircuitReader<F25519>(f25519, FieldID::NONE)
                  .from_bytes(rb, /*enforce_circuit_id=*/true);
    ASSERT_NE(circuit, nullptr);
  }
  z = std::vector<uint8_t>();
  double load_ms = std::chrono::duration<double, std::milli>(
                       std::chrono::steady_clock::now() - t0)
                       .count();
  long loading = peak_rss_mb();
  DisputeProof dp;
  dp.st = st;
  dp.circuit = circuit.get();
  auto in = statement_instance(st, 1);
  DWitness dw(f25519);
  ASSERT_TRUE(dw.compute(in->key, in->ct, in->d, st, in->wrap));
  reset_peak_rss();
  long loaded = peak_rss_mb();
  ASSERT_TRUE(prove_dispute(dp, *in, dw));
  long prover = peak_rss_mb();
  reset_peak_rss();
  EXPECT_TRUE(verify_dispute(dp, *in, dw));
  long verifier = peak_rss_mb();
  printf("%s: at start %ld MB; loading %.0f ms and %ld MB, loaded %ld MB; "
         "prover %ld MB, verifier %ld MB\n",
         statement_name(st), start, load_ms, loading, loaded, prover,
         verifier);
}

// ---------- benchmarks ----------

void BM_DisputeProver(benchmark::State& state) {
  set_log_level(ERROR);
  const Statement st = kStatements[state.range(0)];
  DisputeProof dp;
  dp.st = st;
  dp.circuit = dispute_circuit(st);
  auto in = statement_instance(st, 1);
  DWitness dw(f25519);
  if (!dw.compute(in->key, in->ct, in->d, st, in->wrap)) {
    state.SkipWithError("witness");
  }
  for (auto s : state) {
    benchmark::DoNotOptimize(prove_dispute(dp, *in, dw));
  }
}
BENCHMARK(BM_DisputeProver)
    ->DenseRange(0, kNumStatements - 1)
    ->Iterations(3)
    ->Unit(benchmark::kMillisecond);

void BM_DisputeVerifier(benchmark::State& state) {
  set_log_level(ERROR);
  const Statement st = kStatements[state.range(0)];
  DisputeProof dp;
  dp.st = st;
  dp.circuit = dispute_circuit(st);
  auto in = statement_instance(st, 1);
  DWitness dw(f25519);
  if (!dw.compute(in->key, in->ct, in->d, st, in->wrap)) {
    state.SkipWithError("witness");
  }
  prove_dispute(dp, *in, dw);
  for (auto s : state) {
    benchmark::DoNotOptimize(verify_dispute(dp, *in, dw));
  }
}
BENCHMARK(BM_DisputeVerifier)
    ->DenseRange(0, kNumStatements - 1)
    ->Iterations(3)
    ->Unit(benchmark::kMillisecond);

void BM_DisputeWitness(benchmark::State& state) {
  const Statement st = kStatements[state.range(0)];
  auto in = statement_instance(st, 1);
  for (auto s : state) {
    DWitness dw(f25519);
    benchmark::DoNotOptimize(dw.compute(in->key, in->ct, in->d, st, in->wrap));
  }
}
BENCHMARK(BM_DisputeWitness)
    ->DenseRange(0, kNumStatements - 1)
    ->Unit(benchmark::kMillisecond);

}  // namespace
}  // namespace proofs
