# Zero-knowledge proof of a wrap dispute (research)

A measurement, with [emp-zk](https://github.com/emp-toolkit/emp-zk), of the
proof a member gives when it cannot open an X-Wing wrap (specification,
section 7.2): the research notes
[`problemes-ouverts-2026-09-26.md`](../problemes-ouverts-2026-09-26.md) and
[`preuves-et-mesures-2026-09-26.md`](../preuves-et-mesures-2026-09-26.md)
(in French) propose that the member convicts a committer that sends a bad
wrap with a zero-knowledge proof about the wrap, in its context, which
reveals neither its node key nor what that key protected before. The proof
has a designated verifier, the server, so it is an interactive
[QuickSilver](https://eprint.iacr.org/2021/076) proof over authenticated
bits. None of it is part of profile `city-g/v0.4`.

## What it proves

| Part | Content | Mode |
| --- | --- | --- |
| Hashing | The 26 Keccak-f[1600] permutations of X-Wing's key generation from its seed and of its decapsulation, the 4 BLAKE3 compressions of the two `ExpandLabel` calls that give the wrap's AEAD key and nonce, and the ChaCha20 block that gives the Poly1305 key, which the prover reveals so that the verifier checks the tag itself. | `dispute` |
| Lattice | The arithmetic of ML-KEM-768 (FIPS 203): the secret key against the public key (`A s + e = t`, with `A` public, so the matrix's sampling stays outside), the decryption, and the re-encryption of the Fujisaki-Okamoto transform, checked against the ciphertext. Every product has a public factor; the prover supplies each reduction modulo `q` and the circuit checks it. | `mlkem` |
| Both | The two parts above in one proof. | `full` |
| X25519 | One multiplication modulo `2^255 - 19` over bits, to price the X25519 half: two Montgomery ladders take 6,140 of them. | `x25519mul N` |
| Arithmetic | `N` multiplications in the field `F_{2^61-1}` of emp-zk's arithmetic backend. | `arith N` |

The parts are measured side by side: the full statement wires the Keccak
outputs into the lattice part's secret inputs and the BLAKE3 outputs into
the ChaCha20 key, which adds no AND gate. Each circuit is checked against a
clear reference implementation on its first instance, and each run ends
with the verifier's verdict (`ok=1`). The inputs are random: the cost of
the hashing circuits does not depend on the data, and that of the lattice
part only by a few hundred gates, through the public coefficients that set
its multiplications by constants.

## Building and running it

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
also prints the AND gates of each part. CI does not build the prover:
emp-toolkit is built from its sources.

## Results

On an Intel Xeon at 2.10 GHz (4 vCPUs), both processes on one machine:

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
* The X25519 half is out of reach over bits: 6,140 multiplications would
  take about 150 MB and 90 seconds. It needs a proof over `F_{2^255-19}`,
  where QuickSilver sends one field element per multiplication, about
  200 KB, plus a setup sized for so few multiplications. emp-zk's
  arithmetic backend offers only `F_{2^61-1}`, where one multiplication
  costs 8 bytes and 0.15 µs after a setup, sized for millions of them, of
  32.9 MB (`arith 1000000`).

A dispute without its X25519 half thus takes under a second and 2 MB, of
which 0.65 MB is the setup. The note draws the conclusions.
