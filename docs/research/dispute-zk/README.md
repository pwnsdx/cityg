# Zero-knowledge proof of a wrap dispute (research)

A measurement of the proof a member gives when it cannot open an X-Wing
wrap (specification, section 7.2). The research notes
[`problemes-ouverts-2026-09-26.md`](../problemes-ouverts-2026-09-26.md),
[`preuves-et-mesures-2026-09-26.md`](../preuves-et-mesures-2026-09-26.md),
[`litige-x25519-2026-09-26.md`](../litige-x25519-2026-09-26.md),
[`litige-sans-mise-en-place-2026-09-26.md`](../litige-sans-mise-en-place-2026-09-26.md),
[`litige-entier-2026-09-26.md`](../litige-entier-2026-09-26.md)
and [`litige-deux-branches-2026-09-27.md`](../litige-deux-branches-2026-09-27.md)
(in French) propose that the member convicts a committer that sends a bad
wrap with a zero-knowledge proof about the wrap, in its context, which
reveals neither its node key nor what that key protected before. None of it
is part of profile `city-g/v0.4`.

Three libraries prove parts of it here:

* [emp-zk](https://github.com/emp-toolkit/emp-zk) proves the hashing and
  the lattice part over authenticated bits;
* [Diet Mac'n'Cheese](https://github.com/GaloisInc/swanky) proves the
  X25519 half in the field of X25519, `F_{2^255-19}`, with conversions to
  and from bits;
* [Longfellow](https://github.com/google/longfellow-zk) proves, without any
  setup, the X25519 half in that field and the hashing in `GF(2^128)`, then
  both branches of a dispute in `F_{2^255-19}` alone: ML-KEM's lattice
  part, X25519, the hashing, `ExpandLabel` and ChaCha20, and, for the
  second branch, the node key that the wrap's secret gives.

The first two are interactive [QuickSilver](https://eprint.iacr.org/2021/076)
proofs, whose designated verifier is the server; Longfellow's proofs, with
sumcheck and Ligero, are single messages that anyone can verify.

## What it proves

| Part | Content | Prover |
| --- | --- | --- |
| Hashing | The 26 Keccak-f[1600] permutations of X-Wing's key generation from its seed and of its decapsulation, the 4 BLAKE3 compressions of the two `ExpandLabel` calls that give the wrap's AEAD key and nonce, and the ChaCha20 block that gives the Poly1305 key, which the prover reveals so that the verifier checks the tag itself. | `dispute_zk dispute` |
| Lattice | The arithmetic of ML-KEM-768 (FIPS 203): the secret key against the public key (`A s + e = t`, with `A` public, so the matrix's sampling stays outside), the decryption, and the re-encryption of the Fujisaki-Okamoto transform, checked against the ciphertext. Every product has a public factor; the prover supplies each reduction modulo `q` and the circuit checks it. | `dispute_zk mlkem` |
| Both | The two parts above in one proof. | `dispute_zk full` |
| X25519 | From the 256 bits of `sk_X`, the two Montgomery ladders of RFC 7748 in `F_{2^255-19}`: `pk_X = X25519(sk_X, 9)`, checked against the public key, and `ss_X = X25519(sk_X, ct_X)`, output as 255 canonical bits for the SHA3-256 combiner. 5,048 multiplications in the field, 254 AND gates, and 507 bit conversions padded to 1,024. | [`x25519_ir.py`](x25519_ir.py), `dietmc` |
| Pricing only | One multiplication modulo `2^255 - 19` over bits; `N` multiplications in emp-zk's field `F_{2^61-1}`; `N` multiplications in `F_{2^255-19}`. | `dispute_zk x25519mul N`, `dispute_zk arith N`, `x25519_ir.py chain` |
| X25519, without setup | The same statement as a Longfellow circuit over `F_{2^255-19}`: the state after each step of both ladders is a witness, so that each step is checked on its own and the circuit is 9 layers deep. | [`longfellow/x25519_circuit.h`](longfellow/x25519_circuit.h), `x25519_circuit_test` |
| Hashing, without setup | 26 chained Keccak-f[1600] permutations over `GF(2^128)`, with Longfellow's SHA-3 circuit, which takes the state every 6 rounds as a witness; one permutation over `F_{2^255-19}`. | [`longfellow/keccak_chain_test.cc`](longfellow/keccak_chain_test.cc) |
| Lattice, without setup | ML-KEM-768 in the normal domain over `F_{2^255-19}`: the key binding `t = A s + e` with `s`, `e` small and of bounded norm, the decryption, and the re-encryption, each an identity between polynomials checked at a point `rho` that the verifier draws after the prover has committed to the witness; the prover supplies each quotient by `q`, each offset of `Compress` and each product's high half. | [`longfellow/lattice_circuit.h`](longfellow/lattice_circuit.h), `dispute_test` |
| The whole dispute, without setup | Four statements over `F_{2^255-19}`, in one circuit each. *The wrap does not open* (branch 1): the lattice part's key binding and decryption, `G`, X25519, the combiner, `ExpandLabel` (BLAKE3) and ChaCha20's first block, whose first 32 bytes, the wrap's Poly1305 key, are revealed so that the verifier computes the tag itself. *The wrap opens to the wrong secret* (branch 2): as the first up to the wrap's key and nonce, then ChaCha20's second block opens the sealed secret, `ExpandLabel` seeds its node key, X-Wing's key generation gives that key (SHAKE256, `G`, six PRF calls, `t' = A_v s' + e'` with the public matrix of `pk_v`, a third X25519 ladder), and the key differs from the published `pk_v` at a place that the proof does not reveal. *The re-encryption differs*: the re-encryption with the noise of the seven PRF calls differs from the ciphertext in a coefficient that the proof does not reveal. *The whole decapsulation*, as a reference: the first statement and a re-encryption that gives the ciphertext back. The member's seed stays out of every statement. | [`longfellow/dispute_circuit.h`](longfellow/dispute_circuit.h), `dispute_test` |
| The verifier's public checks | `ct_X` is the canonical u-coordinate of a point of prime order `l` (RFC 7748's ladder with the unclamped scalar `l` ends with `z = 0`), and `pk_v` is canonically encoded; otherwise the committer is convicted without a proof. | [`longfellow/x25519_check.h`](longfellow/x25519_check.h) |
| Decryption failures | The decryption failure rate of ML-KEM-768 for the worst key that the lattice part's norm bounds admit, computed exactly in the model of the Kyber team's scripts. Needs numpy. | [`decryption_failure.py`](decryption_failure.py) |

The emp-zk parts are measured side by side: the full statement wires the
Keccak outputs into the lattice part's secret inputs and the BLAKE3 outputs
into the ChaCha20 key, which adds no AND gate. Each circuit is checked
against a clear reference implementation on its first instance, and each
run ends with the verifier's verdict (`ok=1`). The inputs are random: the
cost of the hashing circuits does not depend on the data, and that of the
lattice part only by a few hundred gates, through the public coefficients
that set its multiplications by constants.

The X25519 relation is written in the SIEVE IR 2.0 text format that
`dietmc` reads. Its generator carries an RFC 7748 reference, checked
against the RFC's vectors, its 1,000 iterations and OpenSSL, and evaluates
the relation as it builds it, against that reference, including for a
ciphertext of small order. The swap bits `k_{t+1} xor k_t` are computed
over bits, where the xor is free, and converted one at a time; public
values fold into constants; the inverse is a hint with its checks. Its
docstring explains each choice.

## Building and running it

### The hashing and the lattice part (emp-zk)

emp-toolkit, built from its sources (the new API with `ZKBoolSession`; the
measurements used emp-tool `bd036a9`, emp-ot `2fca139` and emp-zk
`08490d7`), OpenSSL 3, CMake 3.16 or later and a C++20 compiler. From the
repository's root, with emp-toolkit outside it:

```bash
EMP="$HOME/emp"
mkdir -p "$EMP"
for r in emp-tool emp-ot emp-zk; do
  git clone https://github.com/emp-toolkit/$r.git "$EMP/$r"
  cmake -S "$EMP/$r" -B "$EMP/$r/build" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$EMP/install" -DCMAKE_PREFIX_PATH="$EMP/install"
  cmake --build "$EMP/$r/build" -j && cmake --install "$EMP/$r/build"
done
cmake -S docs/research/dispute-zk -B docs/research/dispute-zk/build \
  -DCMAKE_PREFIX_PATH="$EMP/install"
cmake --build docs/research/dispute-zk/build
```

The prover (party 1) and the verifier (party 2) are two processes; they
meet on `$EMP_PORT` (12345 by default) and `$EMP_PEER_IP` (127.0.0.1):

```bash
cd docs/research/dispute-zk/build
./dispute_zk 1 full & ./dispute_zk 2 full; wait
```

Each process prints its time and what it sent and received; the prover
also prints the AND gates of each part.

### The X25519 half (Diet Mac'n'Cheese)

swanky has no `F_{2^255-19}`, and the code generator of its `ff` fork has
no square root for a prime equal to 5 modulo 8. Two patches, in
[`patches/`](patches/), add both: Atkin's square root to `ff_codegen`, and
the field `F25519` to `field-ff-primes` and to Diet Mac'n'Cheese, with a
`[patch]` section that points swanky to the patched `ff`. A Rust toolchain
(the measurements used 1.94) and about 1 GB of disk, outside the
repository:

```bash
CITYG="$PWD"
cd "$HOME"
git clone https://github.com/GaloisInc/swanky.git
git -C swanky checkout e0f4a621ba39b3035e4400f443ad87634aaf3dce
git clone https://github.com/GaloisInc/ff.git
git -C ff checkout 91d0746bdfd3b5a3ca2bfca71271e47d5f1e25de
git -C ff apply "$CITYG/docs/research/dispute-zk/patches/ff-sqrt-5-mod-8.patch"
git -C swanky apply \
  "$CITYG/docs/research/dispute-zk/patches/swanky-f25519.patch"
cargo build --release --manifest-path swanky/Cargo.toml \
  -p diet-mac-and-cheese --bin dietmc
```

Then generate a relation for a random key and ciphertext, check it in the
clear, and prove it; the verifier listens, the prover connects:

```bash
DIETMC="$HOME/swanky/target/release/dietmc"
python3 docs/research/dispute-zk/x25519_ir.py check
python3 docs/research/dispute-zk/x25519_ir.py dispute /tmp/x25519
$DIETMC --text --plaintext --relation /tmp/x25519/relation.txt \
  --instance /dev/null --witness /tmp/x25519/witness
$DIETMC --text --relation /tmp/x25519/relation.txt --instance /dev/null &
$DIETMC --text --relation /tmp/x25519/relation.txt --instance /dev/null \
  --witness /tmp/x25519/witness; wait
```

`--pad 0` leaves the 507 conversions unpadded, and `dietmc` then warns that
its conversion check is insecure. `x25519_ir.py chain DIR N` writes `N`
multiplications in the field instead, and `--config FILE` with
`lpn = 'small'` selects smaller LPN parameters.

### Bytes, flights and a mobile link

[`link.py`](link.py) sits between the two processes: it forwards one TCP
connection, counts the bytes each way and the flights (runs of bytes in one
direction), and can delay and pace each direction as a link would. Diet
Mac'n'Cheese's prover connects to it, with the verifier behind; emp-zk's
verifier does, with the prover behind:

```bash
# Diet Mac'n'Cheese over a 4G-like link: 25 ms each way, 10 Mbit/s up, 30 down.
$DIETMC --text --relation /tmp/x25519/relation.txt --instance /dev/null \
  -c 127.0.0.1:5600 &
sleep 1
python3 docs/research/dispute-zk/link.py 5601 5600 \
  --latency-ms 25 --rate-mbit 10 30 &
$DIETMC --text --relation /tmp/x25519/relation.txt --instance /dev/null \
  --witness /tmp/x25519/witness -c 127.0.0.1:5601; wait
# emp-zk: the uplink is the direction from the prover, the second rate.
cd docs/research/dispute-zk/build
EMP_PORT=5700 ./dispute_zk 1 full &
sleep 1
python3 ../link.py 5701 5700 --latency-ms 25 --rate-mbit 30 10 &
sleep 1
EMP_PORT=5701 ./dispute_zk 2 full; wait
```

### Without setup (Longfellow)

[`longfellow/`](longfellow/) holds a Longfellow test directory: the X25519
circuit, its witness, their tests and benchmarks against OpenSSL and RFC
7748; the chain of Keccak permutations; a reference of ML-KEM-768 and
X-Wing, checked against the X-Wing draft's vectors; the lattice part, the
whole dispute and its end (BLAKE3 and ChaCha20, written once over a clear
backend that records the witness and a circuit backend that checks it),
with their witnesses, tests and benchmarks; and the verifier's public
check of `ct_X`.
[`longfellow.patch`](longfellow/longfellow.patch) adds the directory to
Longfellow's build and makes its ML-DSA test use the same Ligero
parameters as the others (rate 1/7, 132 queries) and print its proof size. Longfellow needs clang, CMake, OpenSSL, zstd, googletest and
google-benchmark (`libzstd-dev libgtest-dev libbenchmark-dev` on Debian or
Ubuntu); from the repository's root, with Longfellow outside it:

```bash
CITYG="$PWD"
git clone https://github.com/google/longfellow-zk.git "$HOME/longfellow-zk"
cd "$HOME/longfellow-zk"
git checkout b762b93b4ebfc67f2df311d96dbca132390d3cd1
git apply "$CITYG/docs/research/dispute-zk/longfellow/longfellow.patch"
mkdir lib/circuits/tests/x25519
cp "$CITYG"/docs/research/dispute-zk/longfellow/{*.h,*.cc,CMakeLists.txt} \
  lib/circuits/tests/x25519/
CXX=clang++ cmake -D CMAKE_BUILD_TYPE=Release -S lib -B build
cmake --build build -j --target x25519_circuit_test keccak_chain_test \
  dispute_test ml_dsa_circuit_test verify_test
cd build/circuits/tests/x25519
./x25519_circuit_test                       # tests, sizes, a proof
./x25519_circuit_test --gtest_filter=-* --benchmark_filter=BM_
./keccak_chain_test --gtest_filter=-* --benchmark_filter=BM_
./dispute_test                              # both branches
./dispute_test --gtest_filter=-* --benchmark_filter=BM_Dispute
DISPUTE_STATEMENT=0 ./dispute_test --gtest_also_run_disabled_tests \
  --gtest_filter='Dispute.DISABLED_*'       # row lengths, memory
for run in write load; do                   # the circuit, serialized
  DISPUTE_STATEMENT=3 DISPUTE_CIRCUIT=/tmp/branch2.zst ./dispute_test \
    --gtest_also_run_disabled_tests --gtest_filter=Dispute.DISABLED_Serialized
done
```

`DISPUTE_STATEMENT` and the benchmarks' argument pick the statement: 0 is
the first branch, 1 the whole decapsulation, 2 the re-encryption that
differs, 3 the second branch. The first run of `DISABLED_Serialized`
compiles the circuit and writes it, compressed; the second loads it in a
fresh process, then proves and verifies.

Each test prints its circuit's size and proof size; the ECDSA test of
Longfellow (`circuits/ecdsa/verify_test --benchmark_filter=BM_ECDSAZK`)
calibrates the machine against the published measurements. The wrap that
`dispute_test` checks the key schedule against was made by `cityg-core`;
[`../bench/src/bin/wrap_vector.rs`](../bench/src/bin/wrap_vector.rs) prints
it again, with slices of the node key that its secret gives:

```bash
cargo run --release --manifest-path docs/research/bench/Cargo.toml \
  --bin wrap_vector
```

CI builds none of the provers: emp-toolkit, swanky and Longfellow are built
from their sources.

## Results

On an Intel Xeon at 2.10 GHz (4 vCPUs), both processes on one machine.

### Hashing and lattice (emp-zk)

| Proof | AND gates | Sent by the prover | Sent by the verifier | Time |
| --- | ---: | ---: | ---: | ---: |
| Setup alone (`setup`) | 0 | 146,309 B | 501,728 B | 0.18 s |
| Hashing (`dispute`) | 1,050,480 | 289,733 B | 501,728 B | 0.26 to 0.31 s |
| Hashing and lattice (`full`) | 9,724,459 | 1,473,733 B | 501,728 B | 0.82 to 0.89 s |
| One multiplication modulo `2^255 - 19` | 198,651 | 24.8 KB (slope) | | 14 ms (slope) |

* Past the setup, a proof costs about 1.06 bits per AND gate, at 14 to 17
  million AND gates a second on this machine.
* The lattice part is 8,673,979 AND gates: 26,108 products reduced modulo
  `q` and 38,912 additions modulo `q`. It is linear with public factors, so
  a proof over `F_q` would make it almost free, at the price of converting
  the secret bits into field elements.
* The full proof takes 9 flights; its prover uses about a second of CPU
  and 115 MB of memory.
* Over bits, the 5,048 multiplications of the X25519 half would take a
  billion AND gates, about 130 MB and a minute: it needs its own field.

### X25519 in its field (Diet Mac'n'Cheese)

With the default (`medium`) LPN parameters:

| Relation | Sent by the prover | Sent by the verifier | Flights | Time |
| --- | ---: | ---: | ---: | ---: |
| One multiplication, `F_{2^255-19}` alone | 16,578,022 B | 2,063,760 B | 106 | 1.4 s |
| One multiplication, both fields declared | 17,230,742 B | 3,373,180 B | 130 | 1.5 s |
| 5,048 multiplications | 17,392,246 B | 3,373,180 B | 130 | 1.6 s |
| 50,000 multiplications | 18,830,710 B | 3,373,180 B | 130 | 1.7 s |
| X25519 half, 507 conversions (unsound batch) | 18,274,939 B | 4,610,566 B | 178 | 2.7 s |
| X25519 half, 1,024 conversions | 18,470,212 B | 4,610,566 B | 178 | 2.4 to 2.8 s |

* The setup of the 255-bit field dominates. Its LPN setup needs 1,821 base
  correlations, and swanky obtains each with COPEe, which sends one field
  element per bit of the field: 1,821 × 255 × 32 bytes, 14.9 MB from the
  prover.
* Past the setup, a multiplication costs 32 bytes: the two ladders, 0.16 MB.
* The prover uses 0.9 s of CPU and 72 MB of memory; the verifier 0.65 s and
  41 MB.
* With `lpn = 'small'`, the X25519 half sends 18,045,412 and 4,095,126
  bytes in 468 flights and takes 4.5 s: a multiplication then costs 100
  bytes, through many small extensions.

### Over an emulated mobile link

Until the verifier's verdict, with `link.py`. The two links are
assumptions, not measurements: a 4G-like link (50 ms round trip, 10 Mbit/s
up, 30 Mbit/s down) and a poor one (150 ms, 2 up, 8 down). The member's
phone is the prover, so its uplink carries what the prover sends.

| Proof | Up | Down | Flights | Local | 4G-like | Poor |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Hashing and lattice (emp-zk) | 1.47 MB | 0.50 MB | 9 | 1.1 to 1.3 s | 1.8 s | 7.3 s |
| X25519 half (Diet Mac'n'Cheese) | 18.5 MB | 4.6 MB | 178 | 2.7 s | 21.6 s | 92.8 s |

No phone was measured. The computation is about a second of CPU for each
prover here; on a mobile link the uplink sets the time.

### X25519 and hashing without setup (Longfellow)

Rate 1/7 and 132 queries, about 109 bits of statistical security by
Longfellow's own count, as in its ECDSA benchmarks; each proof is one
message:

| Proof | Field | Terms | Proof | Prover | Verifier |
| --- | --- | ---: | ---: | ---: | ---: |
| ECDSA P-256 verification, Longfellow's own (calibration) | `F_p256` | 49,646 | 143,980 B | 52 ms | 30 ms |
| X25519 half | `F_{2^255-19}` | 35,511 | 162,060 B | 65 ms | 48 ms |
| One Keccak-f[1600] | `GF(2^128)` | 1,186,043 | 128,936 B | 34 ms | 11 ms |
| 26 chained Keccak-f[1600], the dispute's hashing | `GF(2^128)` | 30,716,943 | 565,064 B | 0.69 s | 0.27 s |
| ML-DSA-65 verification, Longfellow's (a lattice anchor) | `F_{8380417^6}` | 8,009,000 | 808,696 B | 3.2 s | 1.85 s |

* `2^255 - 19` has no large power-of-two root of unity, in its field or in
  its quadratic extension: the Reed-Solomon code uses Longfellow's CRT
  convolution, as for secp256k1.
* Calibration: the paper of Longfellow measures its ECDSA prover and
  verifier at 53.3 and 33.5 ms on a Pixel 9, 38.4 and 24.9 ms on a Xeon
  Platinum 8581C core; this machine runs the same benchmark in 52 and
  30 ms. The times above are thus close to what a Pixel 9 would take, as
  long as the code has not changed much since the paper.
* The anchor of the lattice part, the verification of an ML-DSA-65
  signature, computes the same kind of products by a public matrix, NTTs
  and roundings. Written for Longfellow and checked at a point, ML-KEM's
  lattice part turns out much cheaper (next section).

### The whole dispute in one field (Longfellow)

The same parameters, one core, the mean of three runs; that day, this
machine ran Longfellow's ECDSA benchmark in 55 and 34 ms:

| Statement | Keccak-f | Inputs (public) | Terms | Proof | Prover | Verifier |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| The wrap does not open (branch 1) | 2 | 87,855 (1,181) | 1,716,288 | 587,116 B | 1.41 s | 0.99 s |
| The wrap opens to the wrong secret (branch 2) | 10 | 171,133 (2,463) | 5,922,950 | 805,484 B | 3.72 s | 2.26 s |
| The re-encryption differs | 8 | 100,409 (1,555) | 4,161,118 | 628,908 B | 2.53 s | 1.52 s |
| The whole decapsulation (reference) | 9 | 150,575 (2,209) | 5,227,062 | 753,292 B | 3.23 s | 1.98 s |
| Lattice part alone: key binding and decryption | 0 | 28,453 (275) | 108,963 | 332,972 B | | |
| Lattice part alone, with the re-encryption | 0 | 46,373 (1,303) | 184,279 | 412,012 B | | |
| One Keccak-f[1600] over `F_{2^255-19}` | 1 | 8,001 | 532,756 | 290,668 B | 0.35 s | 0.20 s |

* Checked at a point, the lattice part takes 8 to 9 times fewer terms than
  its dense negacyclic products (about 1.57 million); its quotients by `q`
  now dominate it. Alone, it takes as inputs the 7,168 bits of the PRF,
  which the dispute gets from Keccak. A witness forged for a point known
  in advance passes at that point and fails elsewhere: the point must come
  after the commitment.
* `ExpandLabel` and ChaCha20 add 50,312 witness elements and 550,447 terms
  to the first statement. The words that only xors change are witnessed
  after each round: without that, the circuit is 60 layers deep instead of
  38, and the copies between layers add 0.84 million terms.
* The second branch adds 4.2 million terms to the first, mostly its eight
  more permutations, and 37% to the proof. It does not check the wrap's
  tag, so it reveals no Poly1305 key: if the tag is wrong, the wrap does
  not open, which convicts the committer as well. It uses the matrix of
  `pk_v`, which the verifier derives from `pk_v`'s seed: if the node key's
  seed differs from it, the keys differ anyway; if not, that matrix is the
  node key's.
* The witness takes 1.9 ms for the first branch and 3.3 ms for the second.
  For the first statement, the prover spends 0.73 s on Ligero's
  commitment, 0.55 s on sumcheck and 0.14 s on Ligero's proof; the
  verifier about 0.3 s on sumcheck and 0.66 s on Ligero, whose
  Reed-Solomon code goes through the CRT convolution. Ligero's row length
  does not help: from 4,096 to 32,768 elements a row, the verifier takes
  0.92 to 1.16 s, and the default (16,384) gives the smallest proof.
* The lattice part bounds `|s|^2` and `|e|^2` by 1,100 each, which costs
  11 inputs and 47 terms more than the joint bound it replaces (next
  section).
* The references agree with the three vectors of the X-Wing draft and with
  a wrap made by `cityg-core`, whose seal OpenSSL redoes; the altered wrap
  is convicted by the tag that the verifier computes from the revealed
  Poly1305 key, and the original is not. On that wrap, the second branch's
  witness derives the node key that `cityg-core` derives; a `pk_v` taken
  from another secret, or wrong in one coefficient of `t` or in `pk_X`, is
  convicted, the honest one has no witness, and a place where the keys
  agree gives no proof.

The circuit does not depend on the dispute: it compiles once, where the
application is built, and ships serialized, as Longfellow's mdoc circuits
do. `DISABLED_Serialized` writes it with Longfellow's `CircuitWriter`,
compressed with zstd at level 16 as the mdoc circuits are; a fresh process
loads it, then proves and verifies:

| Statement | Serialized | With zstd | Loading | Loaded | Prover | Verifier |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Branch 1 | 20,605,926 B | 576,978 B | 0.21 s | 20 MB | 104 MB | 50 MB |
| Branch 2 | 71,086,190 B | 1,506,552 B | 0.72 s | 41 MB | 251 MB | 90 MB |
| The re-encryption differs | 49,936,046 B | 1,001,097 B | 0.52 s | 32 MB | 172 MB | 57 MB |
| The whole decapsulation | 62,735,246 B | 1,337,812 B | 0.64 s | 38 MB | 228 MB | 119 MB |

* "Loaded" is the resident memory once the circuit is loaded and the
  witness computed; the prover's and the verifier's are peaks, each
  measured from its own start.
* Measured in the process that compiled the circuit, the peaks counted the
  heap that the compiler leaves behind: 289 to 837 MB. The compiler itself
  peaks at 420 MB for the first branch and 1,360 MB for the second.

### Decryption failures

The lattice part takes the member's ML-KEM key `(s, e)` as a witness,
without its seed, and bounds its coefficients to `[-4, 3]` and its norm: a
member who picked a key with larger coefficients than honest ones could
make honest ciphertexts fail to decrypt, and then convict an honest
committer. [`decryption_failure.py`](decryption_failure.py) computes the
failure rate of a ciphertext for the worst key that a bound admits, in the
model of the Kyber team's scripts
([security-estimates](https://github.com/pq-crystals/security-estimates)),
with exact convolutions, and checks itself against FIPS 203: `2^-165.2`
for honest keys on average, against the published `2^-164.8`. It needs
numpy and runs in a few minutes:

| Bound | An honest key breaks it | Worst admitted key | Its failure rate |
| --- | ---: | --- | ---: |
| `\|s\|^2 + \|e\|^2 <= 2047`, the earlier joint bound | `2^-77.0` | all in `s`: 339 of ±1, 427 of ±2 | `2^-98.9` |
| `\|s\|^2 <= 1024` and `\|e\|^2 <= 1024` | `2^-39.6` | 680 of ±1, 86 of ±2 in each | `2^-130.3` |
| `\|s\|^2 <= 1100` and `\|e\|^2 <= 1100`, the circuit's | `2^-62.9` | 656 of ±1, 111 of ±2 in each | `2^-121.2` |
| Coefficients in `[-4, 3]` alone | 0 | all at -4 | `2^-7.3` |

`s` multiplies `e1 + du`, of variance 1.92, where `e` multiplies `r`, of
variance 1: under a joint bound the worst key puts all of it into `s`,
which a bound on each part prevents.

### The shortcut, priced

[`x25519_dleq.py`](x25519_dleq.py) prices the shortcut that the notes
reject: revealing `ss_X` with a Chaum-Pedersen proof on Edwards25519, 97
bytes in all, instead of proving X25519. It makes the member a static
Diffie-Hellman oracle: whoever copies the `ct_X` of an honest wrap into a
bad one obtains, from the dispute, the X25519 half of the honest wrap's
secret. The script keeps one part that holds: a `ct_X` that is not the
u-coordinate of a point of prime order `l`, which no honest encapsulation
gives, convicts the committer without any proof; it checks this on the four
points of small order, a point of mixed order, a point of the twist and a
non-canonical encoding.

A dispute with its X25519 half thus takes 25 MB and nearly 190 flights with
the two VOLE-based libraries, of which 21 MB are paid before the first
gate, whatever the statement. Without setup and in one field, each branch
of a dispute takes one message, which anyone can verify, on a machine that
runs Longfellow's ECDSA benchmark at a Pixel 9's speed: 573 KB, 1.41 s to
prove and 0.99 s to verify for the first; 787 KB, 3.72 s and 2.26 s for the
second. With the circuit loaded from its serialized form, the prover needs
104 and 251 MB. What remains is a measurement on a phone, a lighter second
branch for the common case where the node key's seed already differs from
`pk_v`'s, and a human review.
