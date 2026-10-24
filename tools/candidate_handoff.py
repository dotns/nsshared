#!/usr/bin/env python3
"""Compare an immutable shared candidate with explicitly selected gateway inputs.

This read-only comparison complements, and never runs or replaces, just qa.
"""
import argparse
from pathlib import Path
import re
import subprocess
import tomllib

PACKAGES = ("nsshared-proto", "nsshared-service-control", "nsshared-telemetry")
INPUTS = {
    "": set(PACKAGES),
    "e2e/r2/direct-peer/": {"nsshared-proto"},
    "e2e/r3/authority/": {"nsshared-proto"},
    "e2e/r3/control-authority/": {"nsshared-proto", "nsshared-service-control"},
}


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args])


def immutable(revision):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("revision must be a complete immutable commit id")


def check_candidate(root, candidate):
    immutable(candidate)
    paths = ["Cargo.toml", "Cargo.lock", "tools/vectors"] + [f"crates/{n}" for n in PACKAGES]
    names = git(root, "ls-tree", "-r", "--name-only", candidate, "--", *paths).decode().splitlines()
    if not names or "Cargo.lock" not in names:
        raise ValueError("candidate inputs missing")
    for name in names:
        if (root / name).read_bytes() != git(root, "show", f"{candidate}:{name}"):
            raise ValueError(f"candidate input differs: {name}")
    actual = {p.relative_to(root).as_posix() for path in paths
              for p in ([root / path] if (root / path).is_file() else (root / path).rglob("*"))
              if p.is_file() and "__pycache__" not in p.parts}
    if actual != set(names):
        raise ValueError("candidate input set differs: " + ", ".join(sorted(actual ^ set(names))))
    return len(names)


def check_consumer(manifest, lock, candidate, versions, required):
    data = tomllib.loads(manifest)
    dependencies = {}
    for section in (data, data.get("workspace", {})):
        for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
            dependencies.update(section.get(kind, {}))
    for name in required:
        dependency = dependencies.get(name)
        if not isinstance(dependency, dict) or dependency.get("rev") != candidate:
            raise ValueError(f"manifest pin differs: {name}")
        if not dependency.get("git") or any(k in dependency for k in ("path", "branch", "tag")):
            raise ValueError(f"manifest is not an immutable git input: {name}")
    packages = [p for p in tomllib.loads(lock).get("package", []) if p["name"] in PACKAGES]
    if not required <= {p["name"] for p in packages}:
        raise ValueError("lockfile missing required shared packages")
    urls = {dependencies[n]["git"] for n in required}
    if len(urls) != 1:
        raise ValueError("manifest shared repositories differ")
    expected = f"git+{next(iter(urls))}?rev={candidate}#{candidate}"
    for package in packages:
        if package.get("source") != expected or package["version"] != versions[package["name"]]:
            raise ValueError(f"lockfile resolution differs: {package['name']}")
    return len(packages)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--consumer", required=True, type=Path)
    parser.add_argument("--consumer-revision", required=True)
    args = parser.parse_args()
    immutable(args.consumer_revision)
    root = Path(__file__).resolve().parents[1]
    count = check_candidate(root, args.candidate)
    version = tomllib.loads(git(root, "show", f"{args.candidate}:Cargo.toml").decode())["workspace"]["package"]["version"]
    versions = {}
    for name in PACKAGES:
        package = tomllib.loads(git(root, "show", f"{args.candidate}:crates/{name}/Cargo.toml").decode())["package"]
        versions[name] = version if isinstance(package["version"], dict) else package["version"]
    print(f"candidate {args.candidate}: {count} package/lock/API/vector inputs identical")
    for prefix, required in INPUTS.items():
        manifest, lock = (git(args.consumer, "show", f"{args.consumer_revision}:{prefix}{name}").decode()
                          for name in ("Cargo.toml", "Cargo.lock"))
        resolved = check_consumer(manifest, lock, args.candidate, versions, required)
        print(f"consumer {args.consumer_revision}:{prefix or './'}: {resolved} shared lock resolutions agree")
    print("handoff comparison passed; independent QA and external review remain separate")


if __name__ == "__main__":
    main()
