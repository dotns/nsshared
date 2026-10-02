"""Check literal boundary and rejection coverage required by phase 2."""

from pathlib import Path
import unittest


FIXTURES = Path(__file__).parent / "fixtures" / "keynet-v1"


def bindings():
    text = (FIXTURES / "key_bindings.vec").read_text()
    return [
        dict(
            line.split("=", 1)
            for line in block.splitlines()
            if line and not line.startswith("#")
        )
        for block in text.strip().split("\n\n")
    ]


class LiteralCoverage(unittest.TestCase):
    def test_r2_integer_width_boundaries_have_literal_bytes(self):
        required = {23, 24, 255, 256, 65535, 65536, 4294967295, 4294967296}
        observed = {
            int(vector[field])
            for vector in bindings()
            for field in ("generation", "not_before", "not_after")
        }
        self.assertFalse(
            required - observed,
            f"missing literal integer-width boundaries: {sorted(required - observed)}",
        )

    def test_r2_literal_vectors_exercise_a_rejection(self):
        vectors = bindings()
        outcomes = [(v["case"], v["expected_error"]) for v in vectors]
        self.assertTrue(
            any(error != "none" for _, error in outcomes),
            f"no literal error case; observed {outcomes}",
        )

    def test_r2_literal_vectors_exercise_a_conflict_transition(self):
        decisions = {v["expected_decision"] for v in bindings()}
        self.assertTrue(
            any("conflict" in decision.lower() for decision in decisions),
            f"no literal conflict decision; observed {sorted(decisions)}",
        )


if __name__ == "__main__":
    unittest.main()
