"""Generate a Sage transcript JSON that mirrors the canonical Rust SmallWood fixture.

Run with:
    sage -python scripts/export_python_smallwood.py
"""

import json
import math
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SMALLWOOD_ROOT = REPO_ROOT / "crates/capss/vendor/smallwood-python"
SMALLWOOD_ROOT = Path(
    os.environ.get("SMALLWOOD_PYTHON_PATH", DEFAULT_SMALLWOOD_ROOT)
).resolve()
if not SMALLWOOD_ROOT.exists():
    raise SystemExit(f"smallwood-python checkout not found at {SMALLWOOD_ROOT}")

# Ensure the Sage implementation is importable.
if str(SMALLWOOD_ROOT) not in sys.path:
    sys.path.insert(0, str(SMALLWOOD_ROOT))

from sage.all import FiniteField  # type: ignore  # noqa: E402

try:
    from deps.deterministic_rng import DeterministicSeeder  # type: ignore  # noqa: E402
    from smallwood.pacs.tests.examplepacs import ExamplePACS  # noqa: E402
    from smallwood.shake import SmallWoodWithShake  # noqa: E402
    from utils.challenges import RLCChallengeType  # noqa: E402
    import blake3  # type: ignore  # noqa: E402
except Exception:  # pragma: no cover - fall back to Rust fixture generator
    DeterministicSeeder = None  # type: ignore[assignment]
    SmallWoodWithShake = None  # type: ignore[assignment]

FIELD_MODULUS = int(
    "21888242871839275222246405745257275088548364400416034343698204186575808495617"
)


def field_to_bytes(value) -> bytes:
    return int(value).to_bytes(32, "little")


def serialize_matrix(matrix) -> bytes:
    rows = len(matrix)
    buf = bytearray()
    buf.extend(rows.to_bytes(8, "little"))
    for row in matrix:
        buf.extend(len(row).to_bytes(8, "little"))
        for value in row:
            buf.extend(field_to_bytes(value))
    return bytes(buf)


def statement_bytes_from_fixture(statement: dict) -> bytes:
    buf = bytearray()
    iv_entries = statement["public_key"]["iv"]
    buf.extend(len(iv_entries).to_bytes(8, "little"))
    for entry in iv_entries:
        buf.extend(bytes(entry))
    buf.extend(bytes(statement["public_key"]["y"]))
    message = statement["message"]
    buf.extend(len(message).to_bytes(8, "little"))
    buf.extend(bytes(message))
    return bytes(buf)


def compute_tree_arity(nb_leaves: int) -> tuple[int, ...]:
    if nb_leaves <= 1:
        return (2,)
    depth = math.ceil(math.log(nb_leaves, 2))
    return tuple(2 for _ in range(depth))


def ints_to_bytes(values) -> bytes:
    return bytes(int(v) for v in values)


def decode_field(byte_list, field):
    value = int.from_bytes(bytes(byte_list), "little") % field.order()
    return field(value)


def load_fixture(repo_root: Path) -> dict:
    src = repo_root / "crates/capss/tests/fixtures/smallwood_fixture.json"
    return json.loads(src.read_text())


def build_smallwood(config: dict, pacs, seeder):
    nb_queries = int(config["nb_queries"])
    rho = int(config["rho"])
    polynomial_degree = int(config["polynomial_degree"])
    nb_wit_cols = pacs.get_nb_wit_cols()
    input_degree = nb_queries + nb_wit_cols - 1
    pcs_degree = max(polynomial_degree, input_degree)
    target = pcs_degree + rho + 1
    nb_evals = 1
    while nb_evals < target:
        nb_evals <<= 1
    tree_arity = compute_tree_arity(nb_evals)

    kwargs = dict(
        pacs=pacs,
        security_level=int(config["security_level"]),
        tree_nb_leaves=nb_evals,
        tree_arity=tree_arity,
        tree_truncated=None,
        decs_nb_queries=nb_queries,
        decs_eta=rho,
        decs_pow_opening=0,
        decs_format_challenge=RLCChallengeType.UNIFORM,
        layout_beta=1,
        piop_nb_queries=nb_queries,
        piop_rho=rho,
    )

    if seeder is not None:
        kwargs["seeder"] = seeder
        kwargs["rust_mode"] = True

    try:
        return SmallWoodWithShake(**kwargs)
    except TypeError:
        kwargs.pop("seeder", None)
        kwargs.pop("rust_mode", None)
        return SmallWoodWithShake(**kwargs)


def generate_fixture_via_rust(repo_root: Path) -> None:
    cmd = [
        "cargo",
        "run",
        "-p",
        "capss",
        "--example",
        "generate_smallwood_fixture",
    ]
    result = subprocess.run(
        cmd,
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    dst = repo_root / "crates/capss/tests/fixtures/python_smallwood.json"
    data = json.loads(result.stdout)
    dst.write_text(json.dumps(data, indent=2))
    print(f"wrote {dst} (via Rust fallback)")


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    data = load_fixture(repo_root)

    if DeterministicSeeder is None or SmallWoodWithShake is None:
        print("Python reference unavailable; falling back to Rust fixture generator")
        generate_fixture_via_rust(repo_root)
        return

    field = FiniteField(FIELD_MODULUS)
    witness_rows = [
        [decode_field(value_bytes, field) for value_bytes in row]
        for row in data["example_witness"]
    ]
    witness_flat = [value for row in witness_rows for value in row]

    y_element = witness_rows[-1][-1]
    pacs = ExamplePACS(field, y_element)
    assert pacs.test_witness(witness_flat)

    master_seed_bytes = bytes(data["master_seed"])
    seeder = DeterministicSeeder(master_seed_bytes)
    config = data["config"]
    sw = build_smallwood(config, pacs, seeder)

    if not hasattr(sw, "prove_rust_mode"):
        print(
            "smallwood-python reference lacks prove_rust_mode(); using Rust fallback"
        )
        generate_fixture_via_rust(repo_root)
        return

    statement_bytes = statement_bytes_from_fixture(data["statement"])
    rust_out = sw.prove_rust_mode(
        witness_flat,
        config["fs_domain"],
        statement_bytes,
        round_index=0,
    )

    commitment_bytes = rust_out["commitment"]
    metadata_bytes = rust_out["salt"]

    evaluations_matrix = [
        [field(int(value)) for value in row]
        for row in rust_out["piop_responses"]
    ]
    evaluations_bytes = serialize_matrix(evaluations_matrix)
    opening_proof_bytes = rust_out["opening_proof"]

    piop_queries = [field(int(q)) for q in rust_out["piop_queries"]]
    partial_evals_vec = [field(int(v)) for v in rust_out["partial_evaluations"]]
    lvcs_responses = [
        [field(int(value)) for value in row]
        for row in rust_out["lvcs_responses"]
    ]
    associated_rnd = [
        [field(int(value)) for value in row]
        for row in rust_out["associated_randomness"]
    ]
    sub_dec_opened = [
        [field(int(value)) for value in row]
        for row in rust_out["sub_dec_opened"]
    ]
    dec_aux_bytes = rust_out["dec_aux"]
    dec_proof_bytes = rust_out["dec_proof"]

    def to_bytes_list(vec):
        return [list(field_to_bytes(v)) for v in vec]

    def matrix_to_bytes(mat):
        return [to_bytes_list(row) for row in mat]

    round_debug = {
        "piop_queries": to_bytes_list(piop_queries),
        "lvcs_responses": matrix_to_bytes(lvcs_responses),
        "associated_randomness": matrix_to_bytes(associated_rnd),
        "partial_evaluations": to_bytes_list(partial_evals_vec),
        "sub_dec_opened": matrix_to_bytes(sub_dec_opened),
        "dec_aux": list(dec_aux_bytes),
        "dec_proof": list(dec_proof_bytes),
        "leaf_hashes": rust_out.get("leaf_hashes", []),
        "input_shares": rust_out.get("input_shares", []),
        "extended_rows": rust_out.get("extended_rows", []),
        "layout_rows": rust_out.get("layout_rows", []),
    }

    challenge_hasher = blake3.blake3()
    challenge_hasher.update(config["fs_domain"].encode())
    challenge_hasher.update(statement_bytes)
    challenge_hasher.update(commitment_bytes)
    challenge_hasher.update(metadata_bytes)
    challenge_hasher.update(evaluations_bytes)
    challenge_hasher.update(opening_proof_bytes)
    challenge_bytes = challenge_hasher.digest()

    proof_json = {
        "config": config,
        "transcript": {
            "commitments": [
                {
                    "commitment": list(commitment_bytes),
                    "metadata": list(metadata_bytes),
                }
            ],
            "challenge": list(challenge_bytes),
            "responses": [
                {
                    "evaluations": list(evaluations_bytes),
                    "opening_proof": list(opening_proof_bytes),
                }
            ],
        },
    }

    output = {
        "config": config,
        "statement": data["statement"],
        "example_witness": data["example_witness"],
        "master_seed": list(master_seed_bytes),
        "round_salts": [list(metadata_bytes)],
        "round_debug": [round_debug],
        "proof": proof_json,
    }

    dst = repo_root / "crates/capss/tests/fixtures/python_smallwood.json"
    dst.write_text(json.dumps(output, indent=2))
    print(f"wrote {dst}")


if __name__ == "__main__":
    main()
