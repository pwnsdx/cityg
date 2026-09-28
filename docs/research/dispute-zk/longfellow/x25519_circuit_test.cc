// Tests and benchmarks of the X25519 half of a City-G wrap dispute, proved
// with Longfellow (sumcheck and Ligero) over F_{2^255-19}. Research code.

#include "circuits/tests/x25519/x25519_circuit.h"

#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>

#include <cstring>
#include <memory>
#include <random>
#include <vector>

#include "algebra/convolution.h"
#include "algebra/crt.h"
#include "algebra/crt_convolution.h"
#include "algebra/fp.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/ecdsa/verify_witness.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/x25519/x25519_witness.h"
#include "ec/p256.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

using F25519 = Fp<4, true>;
const F25519 f25519(
    "57896044618658097711785492504343953926634992332820282019728792003956564819"
    "949");

using Elt = F25519::Elt;
using Crt = CRT256<F25519>;
using ConvolutionFactory = CrtConvolutionFactory<Crt, F25519>;
using RSFactory = ReedSolomonFactory<F25519, ConvolutionFactory>;
using Witness = X25519Witness<F25519>;

// The parameters of Longfellow's ECDSA benchmarks: rate 1/7 and 132
// queries, "109+ bits of security".
constexpr size_t kRate = 7;
constexpr size_t kQueries = 132;

void openssl_x25519(const uint8_t sk[32], const uint8_t peer[32],
                    uint8_t out[32]) {
  EVP_PKEY* key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, sk, 32);
  EVP_PKEY* other =
      EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer, 32);
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, nullptr);
  size_t len = 32;
  ASSERT_EQ(EVP_PKEY_derive_init(ctx), 1);
  ASSERT_EQ(EVP_PKEY_derive_set_peer(ctx, other), 1);
  ASSERT_EQ(EVP_PKEY_derive(ctx, out, &len), 1);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(other);
  EVP_PKEY_free(key);
}

void openssl_public(const uint8_t sk[32], uint8_t out[32]) {
  EVP_PKEY* key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, sk, 32);
  size_t len = 32;
  ASSERT_EQ(EVP_PKEY_get_raw_public_key(key, out, &len), 1);
  EVP_PKEY_free(key);
}

// A key and an honest ciphertext: the public key of a random ephemeral key.
struct Instance {
  uint8_t sk[32], ct[32];
};

Instance random_instance(std::mt19937_64& rng) {
  Instance in;
  uint8_t eph[32];
  for (size_t i = 0; i < 32; ++i) {
    in.sk[i] = rng() & 0xff;
    eph[i] = rng() & 0xff;
  }
  openssl_public(eph, in.ct);
  return in;
}

template <class LogicType>
typename X25519Circuit<LogicType, F25519>::Witness konst_witness(
    const LogicType& l, const Witness& w) {
  typename X25519Circuit<LogicType, F25519>::Witness cw;
  for (size_t i = 0; i < 256; ++i) cw.sk[i] = l.konst(f25519.of_scalar(w.sk_[i]));
  for (size_t t = 0; t < Witness::kSteps; ++t) {
    cw.pk_ladder.x2[t] = l.konst(w.pk_ladder_.x2[t]);
    cw.pk_ladder.z2[t] = l.konst(w.pk_ladder_.z2[t]);
    cw.pk_ladder.x3[t] = l.konst(w.pk_ladder_.x3[t]);
    cw.pk_ladder.z3[t] = l.konst(w.pk_ladder_.z3[t]);
    cw.ss_ladder.x2[t] = l.konst(w.ss_ladder_.x2[t]);
    cw.ss_ladder.z2[t] = l.konst(w.ss_ladder_.z2[t]);
    cw.ss_ladder.x3[t] = l.konst(w.ss_ladder_.x3[t]);
    cw.ss_ladder.z3[t] = l.konst(w.ss_ladder_.z3[t]);
  }
  cw.inv = l.konst(w.inv_);
  for (size_t i = 0; i < 255; ++i) {
    cw.ss[i] = l.konst(f25519.of_scalar(w.ss_bits_[i]));
  }
  return cw;
}

// Evaluates the circuit in the clear; true when every assertion holds.
bool evaluate(const Witness& w, const Elt& pk, const Elt& u) {
  using EvalBackend = EvaluationBackend<F25519>;
  using LogicType = Logic<F25519, EvalBackend>;
  const EvalBackend ebk(f25519, /*panic_on_assertion_failure=*/false);
  const LogicType l(&ebk, f25519);
  X25519Circuit<LogicType, F25519> circuit(l, f25519);
  circuit.assert_dispute(l.konst(pk), l.konst(u), konst_witness(l, w));
  return !ebk.assertion_failed();
}

TEST(X25519, WitnessMatchesOpenSSLAndRfc7748) {
  // RFC 7748, section 6.1: Alice's key and Bob's public key.
  const uint8_t alice[32] = {
      0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
      0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
      0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a};
  const uint8_t bob_pk[32] = {
      0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61,
      0xc2, 0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78,
      0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f};
  const uint8_t alice_pk[32] = {
      0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d,
      0xdc, 0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38,
      0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a};
  const uint8_t shared[32] = {
      0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b,
      0xf4, 0x80, 0x35, 0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1,
      0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42};
  Witness w(f25519);
  ASSERT_TRUE(w.compute(alice, bob_pk));
  uint8_t pk[32], ss[32];
  w.pk_bytes(pk);
  w.ss_bytes(ss);
  EXPECT_EQ(0, memcmp(pk, alice_pk, 32));
  EXPECT_EQ(0, memcmp(ss, shared, 32));

  std::mt19937_64 rng(25519);
  for (int i = 0; i < 20; ++i) {
    Instance in = random_instance(rng);
    uint8_t want_pk[32], want_ss[32];
    openssl_public(in.sk, want_pk);
    openssl_x25519(in.sk, in.ct, want_ss);
    Witness wi(f25519);
    ASSERT_TRUE(wi.compute(in.sk, in.ct));
    wi.pk_bytes(pk);
    wi.ss_bytes(ss);
    EXPECT_EQ(0, memcmp(pk, want_pk, 32));
    EXPECT_EQ(0, memcmp(ss, want_ss, 32));
  }
}

TEST(X25519, CircuitAcceptsHonestWitnessesOnly) {
  std::mt19937_64 rng(7748);
  for (int i = 0; i < 3; ++i) {
    Instance in = random_instance(rng);
    Witness w(f25519);
    ASSERT_TRUE(w.compute(in.sk, in.ct));
    EXPECT_TRUE(evaluate(w, w.pk_, w.u_));

    // Another public key.
    EXPECT_FALSE(evaluate(w, f25519.addf(w.pk_, f25519.one()), w.u_));
    // A flipped bit of the scalar, of ss_X, or a wrong state.
    {
      Witness bad = w;
      bad.sk_[100] ^= 1;
      EXPECT_FALSE(evaluate(bad, w.pk_, w.u_));
    }
    {
      Witness bad = w;
      bad.ss_bits_[17] ^= 1;
      EXPECT_FALSE(evaluate(bad, w.pk_, w.u_));
    }
    {
      Witness bad = w;
      bad.ss_ladder_.z3[128] =
          f25519.addf(bad.ss_ladder_.z3[128], f25519.one());
      EXPECT_FALSE(evaluate(bad, w.pk_, w.u_));
    }
    // A bit that is not a bit.
    {
      Witness bad = w;
      bad.ss_bits_[3] = 2;
      EXPECT_FALSE(evaluate(bad, w.pk_, w.u_));
    }
  }
  // A ciphertext of small order, u = 0: z_2 is 0 and ss_X is 0.
  uint8_t sk[32], zero[32] = {0};
  for (size_t i = 0; i < 32; ++i) sk[i] = 3 * i + 1;
  Witness w(f25519);
  ASSERT_TRUE(w.compute(sk, zero));
  EXPECT_EQ(w.ss_, f25519.zero());
  EXPECT_TRUE(evaluate(w, w.pk_, w.u_));
}

std::unique_ptr<Circuit<F25519>> make_circuit() {
  using CompilerBackendType = CompilerBackend<F25519>;
  using LogicCircuit = Logic<F25519, CompilerBackendType>;
  using EltW = LogicCircuit::EltW;
  QuadCircuit<F25519> Q(f25519);
  const CompilerBackendType cbk(&Q);
  const LogicCircuit lc(&cbk, f25519);
  X25519Circuit<LogicCircuit, F25519> circuit(lc, f25519);
  EltW pk = lc.eltw_input();
  EltW u = lc.eltw_input();
  Q.private_input();
  auto cw = std::make_unique<X25519Circuit<LogicCircuit, F25519>::Witness>();
  cw->input(lc);
  circuit.assert_dispute(pk, u, *cw);
  auto c = Q.mkcircuit(/*nc=*/1);
  dump_info("x25519 dispute", Q);
  return c;
}

void fill(Dense<F25519>& W, const Witness& w, bool prover) {
  DenseFiller<F25519> filler(W);
  filler.push_back(f25519.one());
  w.fill_public(filler);
  if (prover) w.fill_witness(filler);
}

struct Proved {
  std::unique_ptr<Circuit<F25519>> circuit;
  ConvolutionFactory factory{f25519};
  RSFactory rsf{factory, f25519};
  Witness w{f25519};
  std::unique_ptr<Dense<F25519>> W;
  std::unique_ptr<ZkProof<F25519>> proof;
};

std::unique_ptr<Proved> prove(uint64_t seed, bool tamper) {
  auto p = std::make_unique<Proved>();
  p->circuit = make_circuit();
  std::mt19937_64 rng(seed);
  Instance in = random_instance(rng);
  EXPECT_TRUE(p->w.compute(in.sk, in.ct));
  p->W = std::make_unique<Dense<F25519>>(1, p->circuit->ninputs);
  fill(*p->W, p->w, true);
  if (tamper) {
    // The last input is the most significant bit of ss_X.
    size_t last = p->circuit->ninputs - 1;
    p->W->v_[last] = f25519.subf(f25519.one(), p->W->v_[last]);
  }
  p->proof = std::make_unique<ZkProof<F25519>>(*p->circuit, kRate, kQueries);
  Transcript tp((uint8_t*)"x25519", 6);
  SecureRandomEngine rng2;
  ZkProver<F25519, RSFactory> prover(*p->circuit, f25519, p->rsf);
  prover.commit(*p->proof, *p->W, tp, rng2);
  prover.prove(*p->proof, *p->W, tp);
  return p;
}

bool verify(const Proved& p) {
  Transcript tv((uint8_t*)"x25519", 6);
  Dense<F25519> pub(1, p.circuit->npub_in);
  fill(pub, p.w, false);
  ZkVerifier<F25519, RSFactory> verifier(*p.circuit, p.rsf, kRate, kQueries,
                                         f25519);
  verifier.recv_commitment(*p.proof, tv);
  return verifier.verify(*p.proof, pub, tv);
}

TEST(X25519, ZkProverVerifier) {
  set_log_level(INFO);
  auto p = prove(1, false);
  std::vector<uint8_t> buf;
  p->proof->write(buf, f25519);
  log(INFO, "x25519 dispute: %zu inputs (%zu public), proof %zu bytes",
      p->circuit->ninputs, p->circuit->npub_in, buf.size());
  EXPECT_TRUE(verify(*p));
  // A witness whose last bit of ss_X is flipped yields no valid proof.
  auto bad = prove(1, true);
  EXPECT_FALSE(verify(*bad));
}

// Longfellow's ECDSA circuit under the same parameters, for its proof size.
TEST(X25519, EcdsaProofSizeForComparison) {
  using CompilerBackendType = CompilerBackend<Fp256Base>;
  using LogicCircuit = Logic<Fp256Base, CompilerBackendType>;
  using Verc = VerifyCircuit<LogicCircuit, Fp256Base, P256>;
  using f2_p256 = Fp2<Fp256Base>;
  using FftExt = FFTExtConvolutionFactory<Fp256Base, f2_p256>;
  using RSF = ReedSolomonFactory<Fp256Base, FftExt>;
  QuadCircuit<Fp256Base> Q(p256_base);
  const CompilerBackendType cbk(&Q);
  const LogicCircuit lc(&cbk, p256_base);
  Verc verc(lc, p256, n256_order);
  Verc::Witness vwc;
  auto pkx = lc.eltw_input(), pky = lc.eltw_input(), e = lc.eltw_input();
  Q.private_input();
  vwc.input(lc);
  verc.verify_signature3(pkx, pky, e, vwc);
  auto circuit = Q.mkcircuit(1);

  // The first test vector of verify_test.cc.
  auto pk_x = p256_base.of_string(
      "0x88903e4e1339bde78dd5b3d7baf3efdd72eb5bf5aaaf686c8f9ff5e7c6368d9c");
  auto pk_y = p256_base.of_string(
      "0xeb8341fc38bb802138498d5f4c03733f457ebbafd0b2fe38e6f58626767f9e75");
  Fp256Base::N en(
      "0x2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae");
  Fp256Base::N rn(
      "0xc71bcbfb28bbe06299a225f057797aaf5f22669e90475de5f64176b2612671");
  Fp256Base::N sn(
      "0x42ad2f2ec7b6e91360b53427690dddfe578c10d8cf480a66a6c2410ff4f6dd40");
  VerifyWitness3<P256, Fp256Scalar> vw(p256_scalar, p256);
  vw.compute_witness(pk_x, pk_y, en, rn, sn);
  Dense<Fp256Base> W(1, circuit->ninputs);
  DenseFiller<Fp256Base> filler(W);
  filler.push_back(p256_base.one());
  filler.push_back(pk_x);
  filler.push_back(pk_y);
  filler.push_back(p256_base.to_montgomery(en));
  vw.fill_witness(filler);

  const f2_p256 p256_2(p256_base);
  const auto omega = p256_2.of_string(
      "112649224146410281873500457609690258373018840430489408729223714171582664"
      "680802",
      "840879943585409076957404614278186605601821689971823787493130182544504602"
      "12908");
  const FftExt fft(p256_base, p256_2, omega, 1ull << 31);
  const RSF rsf(fft, p256_base);
  Transcript tp((uint8_t*)"ecdsa", 5);
  SecureRandomEngine rng;
  ZkProof<Fp256Base> zkpr(*circuit, kRate, kQueries);
  ZkProver<Fp256Base, RSF> prover(*circuit, p256_base, rsf);
  prover.commit(zkpr, W, tp, rng);
  prover.prove(zkpr, W, tp);
  std::vector<uint8_t> buf;
  zkpr.write(buf, p256_base);
  log(INFO, "ecdsa verify3: %zu inputs, proof %zu bytes", circuit->ninputs,
      buf.size());
}

// ================ Benchmarks ================================================

void BM_X25519ZKProver(benchmark::State& state) {
  set_log_level(ERROR);
  auto circuit = make_circuit();
  ConvolutionFactory factory(f25519);
  RSFactory rsf(factory, f25519);
  std::mt19937_64 rng(1);
  Instance in = random_instance(rng);
  Witness w(f25519);
  w.compute(in.sk, in.ct);
  Dense<F25519> W(1, circuit->ninputs);
  fill(W, w, true);
  Transcript tp((uint8_t*)"x25519", 6);
  SecureRandomEngine rng2;
  ZkProof<F25519> zkpr(*circuit, kRate, kQueries);
  ZkProver<F25519, RSFactory> prover(*circuit, f25519, rsf);
  for (auto s : state) {
    prover.commit(zkpr, W, tp, rng2);
    prover.prove(zkpr, W, tp);
  }
}
BENCHMARK(BM_X25519ZKProver)->Unit(benchmark::kMillisecond);

void BM_X25519ZKVerifier(benchmark::State& state) {
  set_log_level(ERROR);
  auto p = prove(1, false);
  for (auto s : state) {
    benchmark::DoNotOptimize(verify(*p));
  }
}
BENCHMARK(BM_X25519ZKVerifier)->Unit(benchmark::kMillisecond);

void BM_X25519Witness(benchmark::State& state) {
  std::mt19937_64 rng(1);
  Instance in = random_instance(rng);
  for (auto s : state) {
    Witness w(f25519);
    benchmark::DoNotOptimize(w.compute(in.sk, in.ct));
  }
}
BENCHMARK(BM_X25519Witness)->Unit(benchmark::kMillisecond);

}  // namespace
}  // namespace proofs
