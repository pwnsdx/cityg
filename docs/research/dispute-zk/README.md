# Zero-knowledge proof of a wrap dispute (research)

A measurement of the proof a member gives when it cannot open an X-Wing
wrap (specification, section 7.2). The research notes
[`problemes-ouverts-2026-09-26.md`](../problemes-ouverts-2026-09-26.md),
[`preuves-et-mesures-2026-09-26.md`](../preuves-et-mesures-2026-09-26.md)
and [`litige-x25519-2026-09-26.md`](../litige-x25519-2026-09-26.md) (in
French) propose that the member convicts a committer that sends a bad wrap
with a zero-knowledge proof about the wrap, in its context, which reveals
neither its node key nor what that key protected before. The proof has a
designated verifier, the server, so it is an interactive
[QuickSilver](https://eprint.iacr.org/2021/076) proof. None of it is part
of profile `city-g/v0.4`.

Two libraries prove it here: [emp-zk](https://github.com/emp-toolkit/emp-zk)
proves the hashing and the lattice part over authenticated bits, and
[Diet Mac'n'Cheese](https://github.com/GaloisInc/swanky) proves the X25519
half in the field of X25519, `F_{2^255-19}`, with conversions to and from
bits.

## What it proves

| Part | Content | Prover |
| --- | --- | --- |
| Hashing | The 26 Keccak-f[1600] permutations of X-Wing's key generation from its seed and of its decapsulation, the 4 BLAKE3 compressions of the two `ExpandLabel` calls that give the wrap's AEAD key and nonce, and the ChaCha20 block that gives the Poly1305 key, which the prover reveals so that the verifier checks the tag itself. | `dispute_zk dispute` |
| Lattice | The arithmetic of ML-KEM-768 (FIPS 203): the secret key against the public key (`A s + e = t`, with `A` public, so the matrix's sampling stays outside), the decryption, and the re-encryption of the Fujisaki-Okamoto transform, checked against the ciphertext. Every product has a public factor; the prover supplies each reduction modulo `q` and the circuit checks it. | `dispute_zk mlkem` |
| Both | The two parts above in one proof. | `dispute_zk full` |
| X25519 | From the 256 bits of `sk_X`, the two Montgomery ladders of RFC 7748 in `F_{2^255-19}`: `pk_X = X25519(sk_X, 9)`, checked against the public key, and `ss_X = X25519(sk_X, ct_X)`, output as 255 canonical bits for the SHA3-256 combiner. 5,048 multiplications in the field, 254 AND gates, and 507 bit conversions padded to 1,024. | [`x25519_ir.py`](x25519_ir.py), `dietmc` |
| Pricing only | One multiplication modulo `2^255 - 19` over bits; `N` multiplications in emp-zk's field `F_{2^61-1}`; `N` multiplications in `F_{2^255-19}`. | `dispute_zk x25519mul N`, `dispute_zk arith N`, `x25519_ir.py chain` |

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

CI builds neither prover: emp-toolkit and swanky are built from their
sources.

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

A dispute with its X25519 half thus takes 25 MB with these two libraries,
of which 21 MB are paid before the first gate, whatever the statement: a
proof without setup, over the two fields, is the next thing to measure.
