#!/usr/bin/env python3
"""Compare test vector cases of a base revision with the working tree.

    vector_cases.py BASE MAP.json

MAP.json: {"moves": {old_path: new_path | [new_path, ...]}, "added": {new_path: [case, ...]}}
Unlisted old paths map to themselves. Every case of every old fixture (`*.vec`
blocks keyed by `name`, JSON objects keyed by member) must exist at a mapped
path with identical lines; every other case at a new path must be listed in
"added". Header comment lines are reported, not compared.
"""

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())


def is_fixture(path):
    if path.endswith(".vec"):
        return True
    return path.endswith("service-control-v1.json") or ("/tests/vectors/" in path and path.endswith(".json")
                                                       and not path.endswith("/predecessor.json"))


def cases(path, text):
    if path.endswith(".json"):
        return {key: json.dumps(value, sort_keys=True) for key, value in json.loads(text).items()}, []
    out, header, block = {}, [], []
    for line in text.split("\n"):
        if line.startswith("#"):
            header.append(line)
            continue
        if line == "":
            if block:
                name = block[0].split(" = ", 1)[1]
                if name in out:
                    raise SystemExit(f"{path}: duplicate case {name}")
                out[name] = "\n".join(block)
                block = []
            continue
        block.append(line)
    if block:
        out[block[0].split(" = ", 1)[1]] = "\n".join(block)
    return out, header


def main():
    base, mapping_path = sys.argv[1], sys.argv[2]
    mapping = json.loads(pathlib.Path(mapping_path).read_text())
    moves, added = mapping.get("moves", {}), mapping.get("added", {})
    old_paths = [p for p in subprocess.check_output(["git", "ls-tree", "-r", "--name-only", base], text=True, cwd=ROOT).split("\n") if is_fixture(p)]
    new_paths = sorted(str(p.relative_to(ROOT)) for p in ROOT.rglob("*") if p.is_file() and "target" not in p.parts and "tmp" not in p.parts and is_fixture(str(p)))
    new_cases = {p: cases(p, (ROOT / p).read_text()) for p in new_paths}
    problems, used, compared = [], {p: set() for p in new_paths}, 0
    for old in old_paths:
        old_cases, _ = cases(old, subprocess.check_output(["git", "show", f"{base}:{old}"], text=True, cwd=ROOT))
        targets = moves.get(old, old)
        targets = [targets] if isinstance(targets, str) else targets
        for name, body in old_cases.items():
            hits = [t for t in targets if t in new_cases and new_cases[t][0].get(name) == body]
            if len(hits) != 1:
                problems.append(f"{old}: case {name} found {len(hits)} times unchanged in {targets}")
                continue
            used[hits[0]].add(name)
            compared += 1
    for path, (found, _) in new_cases.items():
        extra = sorted(set(found) - used[path])
        listed = set(added.get(path, []))
        for name in extra:
            if name not in listed:
                problems.append(f"{path}: case {name} is not from the base and not listed as added")
        for name in sorted(listed - set(extra)):
            problems.append(f"{path}: listed addition {name} not found")
    for problem in problems:
        print("-", problem)
    additions = sum(len(v) for v in added.values())
    print(f"{len(old_paths)} base fixtures, {compared} base cases unchanged, {additions} listed additions, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
