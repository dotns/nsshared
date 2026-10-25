"""Rendering and filtering tests for scripts/api_surface.py."""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import api_surface  # noqa: E402


def path(name, *types):
    args = {"angle_bracketed": {"args": [{"type": t} for t in types], "constraints": []}} if types else None
    return {"resolved_path": {"path": name, "id": 1, "args": args}}


class TypeRendering(unittest.TestCase):
    def test_paths_render_by_last_segment(self):
        self.assertEqual(api_surface.ty(path("crate::codec::CborError")), "CborError")
        self.assertEqual(
            api_surface.ty(path("Result", {"primitive": "u64"}, path("nsshared_codec::cbor::CborError"))),
            "Result<u64, CborError>",
        )

    def test_references_slices_and_arrays(self):
        borrowed = {"borrowed_ref": {"lifetime": "'a", "is_mutable": True, "type": {"slice": {"primitive": "u8"}}}}
        self.assertEqual(api_surface.ty(borrowed), "&'a mut [u8]")
        self.assertEqual(api_surface.ty({"array": {"type": {"primitive": "u8"}, "len": "32"}}), "[u8; 32]")
        self.assertEqual(api_surface.ty({"tuple": []}), "()")

    def test_function_signature(self):
        inner = {
            "sig": {"inputs": [["self", {"borrowed_ref": {"lifetime": None, "is_mutable": False, "type": {"generic": "Self"}}}],
                               ["value", {"primitive": "u64"}]],
                    "output": path("Vec", {"primitive": "u8"})},
            "generics": {"params": [], "where_predicates": []},
            "header": {"is_const": True, "is_async": False, "is_unsafe": False},
        }
        self.assertEqual(api_surface.function(inner), "(&Self, u64) -> Vec<u8> [const]")


class Filtering(unittest.TestCase):
    def test_exclusions_match_the_item_path(self):
        self.assertTrue(api_surface.excluded("struct nsshared_proto::account::Roster", ["nsshared_proto::account"]))
        self.assertFalse(api_surface.excluded("fn nsshared_proto::keys::f() -> Account", ["nsshared_proto::account"]))
        self.assertTrue(api_surface.excluded("impl Send for nsshared_proto::account::Roster", ["nsshared_proto::account"]))


if __name__ == "__main__":
    unittest.main()
