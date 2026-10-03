#!/usr/bin/env python3
"""Writes or checks the NS v2 test vector fixtures.

    python3 tools/vectors/generate.py          # self-test, then write every fixture
    python3 tools/vectors/generate.py --check  # self-test, then compare with the committed files

The generator implements the specification text with the Python standard library only and
never builds, calls or reads the output of the Rust crates.
"""

import argparse
import difflib
import pathlib
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from nsvec import fixture, selftest  # noqa: E402
from nsvec.producers import PRODUCERS  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]


def fixture_dir(crate):
    return ROOT / "crates" / crate / "tests" / "fixtures" / "vectors"


def render_all():
    """Maps every generator-owned fixture path to its expected text."""
    files = {}
    for producer in PRODUCERS:
        path = fixture_dir(producer.CRATE) / f"{producer.GROUP}.vec"
        if path in files:
            raise SystemExit(f"error: two producers write {path}")
        files[path] = fixture.render(producer.TITLE, producer.SECTIONS, producer.vectors())
    return files


def check(files):
    problems = []
    owned = {path.parent for path in files}
    for directory in sorted(owned):
        for path in sorted(directory.glob("*.vec")):
            if path not in files:
                problems.append(f"extra fixture not produced by the generator: {path.relative_to(ROOT)}")
    for path, expected in sorted(files.items()):
        rel = path.relative_to(ROOT)
        if not path.exists():
            problems.append(f"missing fixture: {rel}")
            continue
        actual = path.read_bytes().decode("utf-8", errors="replace")
        if actual != expected:
            diff = list(
                difflib.unified_diff(
                    actual.splitlines(), expected.splitlines(), f"{rel} (committed)", f"{rel} (generated)", lineterm="", n=0
                )
            )
            shown = "\n".join(diff[:12])
            more = f"\n  ... {len(diff) - 12} more diff lines" if len(diff) > 12 else ""
            problems.append(f"stale fixture: {rel}\n{shown}{more}")
    if problems:
        print("vectors-check failed; run `just vectors` and review the diff:", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        return 1
    print(f"vectors-check: {len(files)} fixture files up to date")
    return 0


def write(files):
    for path, text in sorted(files.items()):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))
        print(f"wrote {path.relative_to(ROOT)}")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="compare with the committed fixtures instead of writing")
    args = parser.parse_args()
    try:
        selftest.run()
    except selftest.SelfTestError as err:
        print(f"self-test failed: {err}", file=sys.stderr)
        return 1
    files = render_all()
    return check(files) if args.check else write(files)


if __name__ == "__main__":
    sys.exit(main())
