"""
Generate ExamplePACS witness data using Sage so Rust tests can cross-check the
ported implementation.

Run with:
    sage -python scripts/export_python_example_pacs.py
"""

import json
import random
from pathlib import Path

from sage.all import FiniteField


class ExamplePACS:
    def __init__(self, field, y):
        self._field = field
        self.y = y

    @classmethod
    def random_instance(cls, field):
        x = field.random_element()
        y = x ** (2 ** 4)
        witness = [
            [x, x**4],
            [x**2, x**8],
            [x**4, x**16],
        ]

        # Flatten row-major to match the Sage tests.
        flat = []
        for row in witness:
            flat.extend(row)
        return cls(field, y), flat


def main():
    repo_root = Path(__file__).resolve().parents[1]
    fixture_path = repo_root / "crates/capss/tests/fixtures/example_pacs_python.json"

    random.seed(0)
    modulus = int(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617"
    )
    field = FiniteField(modulus)

    pacs, witness = ExamplePACS.random_instance(field)
    data = {
        "field_modulus": modulus,
        "y": str(int(pacs.y)),
        "witness": [str(int(value)) for value in witness],
    }

    fixture_path.write_text(json.dumps(data, indent=2))
    print(f"wrote {fixture_path}")


if __name__ == "__main__":
    main()
