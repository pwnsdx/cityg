// The hashing of a City-G wrap dispute, priced with Longfellow: N chained
// Keccak-f[1600] permutations over GF(2^128), with the intermediate states
// that Longfellow's SHA-3 circuit takes as witnesses. The dispute hashes
// with 26 permutations. Research code.

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <random>
#include <vector>

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

using Field = GF2_128<>;
const Field F;
using RSFactory = LCH14ReedSolomonFactory<Field>;
constexpr size_t kRate = 7;
constexpr size_t kQueries = 132;

std::unique_ptr<Circuit<Field>> make_chain(size_t n) {
  using CompilerBackendType = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackendType>;
  using v64 = LogicCircuit::v64;
  QuadCircuit<Field> Q(F);
  const CompilerBackendType cbk(&Q);
  const LogicCircuit lc(&cbk, F);
  Sha3Circuit<LogicCircuit> sha3(lc);
  struct State {
    v64 a[5][5];
  };
  auto s = std::make_unique<State>();
  for (size_t x = 0; x < 5; ++x) {
    for (size_t y = 0; y < 5; ++y) s->a[x][y] = lc.vinput<64>();
  }
  for (size_t i = 0; i < n; ++i) {
    auto bw = std::make_unique<Sha3Circuit<LogicCircuit>::BlockWitness>();
    bw->input(lc);
    sha3.keccak_f_1600(s->a, *bw);
  }
  auto c = Q.mkcircuit(/*nc=*/1);
  dump_info("keccak chain", n, Q);
  return c;
}

void fill(Dense<Field>& W, size_t n) {
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

struct Proved {
  std::unique_ptr<Circuit<Field>> circuit;
  RSFactory rsf{F};
  std::unique_ptr<ZkProof<Field>> proof;
};

std::unique_ptr<Proved> prove(size_t n, bool tamper) {
  auto p = std::make_unique<Proved>();
  p->circuit = make_chain(n);
  Dense<Field> W(1, p->circuit->ninputs);
  fill(W, n);
  if (tamper) W.v_[p->circuit->ninputs - 1] = F.addf(W.v_[p->circuit->ninputs - 1], F.one());
  p->proof = std::make_unique<ZkProof<Field>>(*p->circuit, kRate, kQueries);
  Transcript tp((uint8_t*)"keccak", 6);
  SecureRandomEngine rng;
  ZkProver<Field, RSFactory> prover(*p->circuit, F, p->rsf);
  prover.commit(*p->proof, W, tp, rng);
  prover.prove(*p->proof, W, tp);
  return p;
}

bool verify(const Proved& p) {
  Transcript tv((uint8_t*)"keccak", 6);
  Dense<Field> pub(1, 0);
  ZkVerifier<Field, RSFactory> verifier(*p.circuit, p.rsf, kRate, kQueries, F);
  verifier.recv_commitment(*p.proof, tv);
  return verifier.verify(*p.proof, pub, tv);
}

TEST(KeccakChain, ZkProverVerifier) {
  set_log_level(INFO);
  for (size_t n : {1, 26}) {
    auto p = prove(n, false);
    std::vector<uint8_t> buf;
    p->proof->write(buf, F);
    log(INFO, "keccak chain of %zu: %zu inputs, proof %zu bytes", n,
        p->circuit->ninputs, buf.size());
    EXPECT_TRUE(verify(*p));
  }
  // A wrong bit in the last witnessed state yields no valid proof.
  auto bad = prove(2, true);
  EXPECT_FALSE(verify(*bad));
}

void BM_KeccakChainProver(benchmark::State& state) {
  set_log_level(ERROR);
  size_t n = state.range(0);
  auto circuit = make_chain(n);
  Dense<Field> W(1, circuit->ninputs);
  fill(W, n);
  const RSFactory rsf(F);
  Transcript tp((uint8_t*)"keccak", 6);
  SecureRandomEngine rng;
  ZkProof<Field> zkpr(*circuit, kRate, kQueries);
  ZkProver<Field, RSFactory> prover(*circuit, F, rsf);
  for (auto s : state) {
    prover.commit(zkpr, W, tp, rng);
    prover.prove(zkpr, W, tp);
  }
}
BENCHMARK(BM_KeccakChainProver)->Arg(1)->Arg(26)->Unit(benchmark::kMillisecond);

void BM_KeccakChainVerifier(benchmark::State& state) {
  set_log_level(ERROR);
  auto p = prove(state.range(0), false);
  for (auto s : state) {
    benchmark::DoNotOptimize(verify(*p));
  }
}
BENCHMARK(BM_KeccakChainVerifier)->Arg(1)->Arg(26)->Unit(benchmark::kMillisecond);

}  // namespace
}  // namespace proofs
