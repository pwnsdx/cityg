// The hashing of a City-G wrap dispute, priced with Longfellow: N chained
// Keccak-f[1600] permutations, with the intermediate states that
// Longfellow's SHA-3 circuit takes as witnesses, over GF(2^128) and over
// F_{2^255-19}, the field of X25519 and of the lattice part. The statement
// that emp-zk measured hashes with 26 permutations; those of
// dispute_test.cc, over F_{2^255-19}, with 2 to 9. Research code.

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <random>
#include <vector>

#include "algebra/crt.h"
#include "algebra/crt_convolution.h"
#include "algebra/fp.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/sha3/sha3_circuit.h"
#include "circuits/tests/sha3/sha3_reference.h"
#include "circuits/tests/sha3/sha3_witness.h"
#include "gf2k/gf2_128.h"
#include "gf2k/lch14_reed_solomon.h"
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

constexpr size_t kRate = 7;
constexpr size_t kQueries = 132;

using GF128 = GF2_128<>;
const GF128 gf128;
using F25519 = Fp<4, true>;
const F25519 f25519(
    "57896044618658097711785492504343953926634992332820282019728792003956564819"
    "949");

struct BinaryTraits {
  using Field = GF128;
  using RSFactory = LCH14ReedSolomonFactory<GF128>;
  static const Field& field() { return gf128; }
  static const char* name() { return "GF(2^128)"; }
};

struct PrimeTraits {
  using Field = F25519;
  using ConvolutionFactory = CrtConvolutionFactory<CRT256<F25519>, F25519>;
  using RSFactory = ReedSolomonFactory<F25519, ConvolutionFactory>;
  static const Field& field() { return f25519; }
  static const char* name() { return "F_{2^255-19}"; }
};

// A Reed-Solomon factory and whatever it depends on.
template <class Traits>
struct Codes;

template <>
struct Codes<BinaryTraits> {
  BinaryTraits::RSFactory rsf{gf128};
};

template <>
struct Codes<PrimeTraits> {
  PrimeTraits::ConvolutionFactory conv{f25519};
  PrimeTraits::RSFactory rsf{conv, f25519};
};

template <class Traits>
std::unique_ptr<Circuit<typename Traits::Field>> make_chain(size_t n) {
  using Field = typename Traits::Field;
  using CompilerBackendType = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackendType>;
  using v64 = typename LogicCircuit::v64;
  const Field& F = Traits::field();
  QuadCircuit<Field> Q(F);
  const CompilerBackendType cbk(&Q);
  const LogicCircuit lc(&cbk, F);
  Sha3Circuit<LogicCircuit> sha3(lc);
  struct State {
    v64 a[5][5];
  };
  auto s = std::make_unique<State>();
  for (size_t x = 0; x < 5; ++x) {
    for (size_t y = 0; y < 5; ++y) s->a[x][y] = lc.template vinput<64>();
  }
  for (size_t i = 0; i < n; ++i) {
    auto bw =
        std::make_unique<typename Sha3Circuit<LogicCircuit>::BlockWitness>();
    bw->input(lc);
    sha3.keccak_f_1600(s->a, *bw);
  }
  auto c = Q.mkcircuit(/*nc=*/1);
  dump_info(Traits::name(), n, Q);
  return c;
}

template <class Traits>
void fill(Dense<typename Traits::Field>& W, size_t n) {
  using Field = typename Traits::Field;
  const Field& F = Traits::field();
  DenseFiller<Field> filler(W);
  filler.push_back(F.one());
  std::mt19937_64 rng(1600);
  uint64_t a[5][5];
  for (size_t x = 0; x < 5; ++x) {
    for (size_t y = 0; y < 5; ++y) {
      a[x][y] = rng();
      filler.push_back(a[x][y], 64, F);
    }
  }
  for (size_t i = 0; i < n; ++i) {
    Sha3Witness::BlockWitness bw;
    Sha3Witness::compute_witness_block(a, bw);
    Sha3Witness::fill_witness(filler, bw, F);
  }
}

template <class Traits>
struct Proved {
  using Field = typename Traits::Field;
  std::unique_ptr<Circuit<Field>> circuit;
  Codes<Traits> codes;
  std::unique_ptr<ZkProof<Field>> proof;
};

template <class Traits>
std::unique_ptr<Proved<Traits>> prove(size_t n, bool tamper) {
  using Field = typename Traits::Field;
  const Field& F = Traits::field();
  auto p = std::make_unique<Proved<Traits>>();
  p->circuit = make_chain<Traits>(n);
  Dense<Field> W(1, p->circuit->ninputs);
  fill<Traits>(W, n);
  if (tamper) {
    // Flip the last bit of the last witnessed state.
    size_t last = p->circuit->ninputs - 1;
    W.v_[last] = F.subf(F.one(), W.v_[last]);
  }
  p->proof = std::make_unique<ZkProof<Field>>(*p->circuit, kRate, kQueries);
  Transcript tp((uint8_t*)"keccak", 6);
  SecureRandomEngine rng;
  ZkProver<Field, typename Traits::RSFactory> prover(*p->circuit, F,
                                                     p->codes.rsf);
  prover.commit(*p->proof, W, tp, rng);
  prover.prove(*p->proof, W, tp);
  return p;
}

template <class Traits>
bool verify(const Proved<Traits>& p) {
  using Field = typename Traits::Field;
  Transcript tv((uint8_t*)"keccak", 6);
  Dense<Field> pub(1, 0);
  ZkVerifier<Field, typename Traits::RSFactory> verifier(
      *p.circuit, p.codes.rsf, kRate, kQueries, Traits::field());
  verifier.recv_commitment(*p.proof, tv);
  return verifier.verify(*p.proof, pub, tv);
}

template <class Traits>
void check_chains(std::initializer_list<size_t> sizes) {
  set_log_level(INFO);
  for (size_t n : sizes) {
    auto p = prove<Traits>(n, false);
    std::vector<uint8_t> buf;
    p->proof->write(buf, Traits::field());
    log(INFO, "keccak chain of %zu over %s: %zu inputs, proof %zu bytes", n,
        Traits::name(), p->circuit->ninputs, buf.size());
    EXPECT_TRUE(verify(*p));
  }
  // A wrong bit in the last witnessed state yields no valid proof.
  auto bad = prove<Traits>(2, true);
  EXPECT_FALSE(verify(*bad));
}

TEST(KeccakChain, BinaryField) { check_chains<BinaryTraits>({1, 26}); }

TEST(KeccakChain, PrimeField) { check_chains<PrimeTraits>({1}); }

template <class Traits>
void BM_KeccakChainProver(benchmark::State& state) {
  using Field = typename Traits::Field;
  set_log_level(ERROR);
  size_t n = state.range(0);
  auto circuit = make_chain<Traits>(n);
  Dense<Field> W(1, circuit->ninputs);
  fill<Traits>(W, n);
  Codes<Traits> codes;
  Transcript tp((uint8_t*)"keccak", 6);
  SecureRandomEngine rng;
  ZkProof<Field> zkpr(*circuit, kRate, kQueries);
  ZkProver<Field, typename Traits::RSFactory> prover(*circuit, Traits::field(),
                                                     codes.rsf);
  for (auto s : state) {
    prover.commit(zkpr, W, tp, rng);
    prover.prove(zkpr, W, tp);
  }
}

template <class Traits>
void BM_KeccakChainVerifier(benchmark::State& state) {
  set_log_level(ERROR);
  auto p = prove<Traits>(state.range(0), false);
  for (auto s : state) {
    benchmark::DoNotOptimize(verify(*p));
  }
}

BENCHMARK(BM_KeccakChainProver<BinaryTraits>)
    ->Arg(1)
    ->Arg(26)
    ->Unit(benchmark::kMillisecond);
BENCHMARK(BM_KeccakChainVerifier<BinaryTraits>)
    ->Arg(1)
    ->Arg(26)
    ->Unit(benchmark::kMillisecond);
BENCHMARK(BM_KeccakChainProver<PrimeTraits>)
    ->Arg(1)
    ->Unit(benchmark::kMillisecond);
BENCHMARK(BM_KeccakChainVerifier<PrimeTraits>)
    ->Arg(1)
    ->Unit(benchmark::kMillisecond);

}  // namespace
}  // namespace proofs
