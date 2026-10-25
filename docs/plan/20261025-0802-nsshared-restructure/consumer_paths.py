#!/usr/bin/env python3
"""Collect the nsshared item paths used by consumer sources and write a check crate.

    consumer_paths.py OUT_DIR SHARED_PATH CONSUMER_DIR...

The crate in OUT_DIR depends on nsshared-proto and nsshared-service-control at
SHARED_PATH and imports every collected path anonymously, one per line, so a
failing path is reported individually by `cargo check`.
"""

import pathlib
import re
import sys

CRATES = ("nsshared_proto", "nsshared_service_control")
USE = re.compile(r"\buse\s+((?:::)?(?:%s)\b[^;]*);" % "|".join(CRATES), re.S)
INLINE = re.compile(r"\b(?:%s)(?:::[A-Za-z_][A-Za-z0-9_]*)+" % "|".join(CRATES))


def flatten(tree):
    """Expands a use tree into full paths."""
    tree = re.sub(r"\s+as\s+[A-Za-z_][A-Za-z0-9_]*", "", tree)
    tree = re.sub(r"\s+", "", tree).lstrip(":")
    depth = 0
    for index, char in enumerate(tree):
        if char == "{" and depth == 0:
            prefix, body = tree[:index].rstrip(":"), tree[index + 1 : -1]
            parts, current, level = [], "", 0
            for c in body:
                if c == "," and level == 0:
                    parts.append(current)
                    current = ""
                    continue
                level += c == "{"
                level -= c == "}"
                current += c
            parts.append(current)
            out = []
            for part in filter(None, parts):
                for path in flatten(part):
                    out.append(prefix if path == "self" else f"{prefix}::{path}")
            return out
        depth += char == "{"
        depth -= char == "}"
    return [tree]


def inline(path):
    segments = path.split("::")
    for index, segment in enumerate(segments[1:], 1):
        if segment[0].isupper() and not segment.isupper():
            return "::".join(segments[: index + 1])
    return path


def main():
    out, shared, consumers = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3:]
    paths = set()
    for root in consumers:
        for source in pathlib.Path(root).rglob("*.rs"):
            if "target" in source.parts:
                continue
            text = source.read_text(errors="replace")
            text = re.sub(r"//[^\n]*", "", text)
            for match in USE.finditer(text):
                paths.update(p for p in flatten(match.group(1)) if p != "*" and not p.endswith("::*"))
            for match in INLINE.finditer(USE.sub("", text)):
                paths.add(inline(match.group(0)))
    paths = sorted(p for p in paths if p.count("::") >= 1 and not p.endswith("::self"))
    (out / "src").mkdir(parents=True, exist_ok=True)
    (out / "Cargo.toml").write_text(f"""[package]
name = "consumer-paths"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
nsshared-proto = {{ path = "{shared}/crates/nsshared-proto" }}
nsshared-service-control = {{ path = "{shared}/crates/nsshared-service-control" }}

[workspace]
""")
    lines = ["#![allow(unused_imports)]"] + [f"use {p} as _;" for p in paths]
    (out / "src" / "lib.rs").write_text("\n".join(lines) + "\n")
    (out / "paths.txt").write_text("\n".join(paths) + "\n")
    print(f"{len(paths)} paths")


if __name__ == "__main__":
    main()
