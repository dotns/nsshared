#!/usr/bin/env python3
"""Select conservative workspace checks from Git paths and Cargo metadata."""

import json
from pathlib import Path
import shlex
import subprocess
import sys
from typing import TypedDict


class Selection(TypedDict):
    full: bool
    reason: str
    changed: list[str]
    affected: list[str]


STATIC_CHECKS = ["fmt-check", "lint", "deny", "shear", "typos", "vectors-check", "semver"]
CONFIG_NAMES = {
    "Cargo.toml", "Cargo.lock", "justfile", "rust-toolchain", "rust-toolchain.toml",
    "deny.toml", "typos.toml", ".typos.toml", "clippy.toml", ".clippy.toml",
    "rustfmt.toml", ".rustfmt.toml", "config.toml",
}


def output(root: Path, *args: str) -> bytes:
    return subprocess.check_output(args, cwd=root)


def changed_paths(root: Path, base: str) -> list[str]:
    ancestor = output(root, "git", "merge-base", "--", base, "HEAD").decode().strip()
    # Separate diffs retain both sides of staged/unstaged reversions. Disable
    # rename detection so moving global inputs into a crate remains global.
    paths = set()
    for args in [
        ("git", "diff", "--name-only", "--no-renames", "-z", ancestor, "HEAD", "--"),
        ("git", "diff", "--name-only", "--no-renames", "-z", "--cached", "--"),
        ("git", "diff", "--name-only", "--no-renames", "-z", "--"),
        ("git", "ls-files", "--others", "--exclude-standard", "-z"),
    ]:
        paths.update(path.decode(errors="surrogateescape") for path in output(root, *args).split(b"\0") if path)
    return sorted(paths)


def workspace_metadata(root: Path) -> dict:
    return json.loads(output(root, "cargo", "metadata", "--format-version", "1", "--locked", "--all-features"))


def select(root: Path, paths: list[str], metadata: dict) -> Selection:
    root = Path(root).resolve()
    members = set(metadata["workspace_members"])
    packages = {package["id"]: package for package in metadata["packages"] if package["id"] in members}
    directories = {}
    for package in packages.values():
        directory = Path(package["manifest_path"]).parent.relative_to(root).as_posix()
        if directory.startswith("crates/") and len(directory.split("/")) == 2:
            directories[directory] = package["id"]

    changed = set()
    reasons = []
    for path in paths:
        parts = path.split("/")
        directory = "/".join(parts[:2])
        package_id = directories.get(directory) if len(parts) > 2 else None
        if package_id:
            changed.add(package_id)
        if "vectors" in parts or path.startswith("tools/vectors/"):
            reasons.append(f"vector or generator changed: {path}")
        elif parts[-1] in CONFIG_NAMES or any(part.startswith(".") for part in parts):
            reasons.append(f"manifest or tool configuration changed: {path}")
        elif not package_id:
            reasons.append(f"path outside a known crate: {path}")

    if not paths:
        reasons.append("empty diff")
    elif not changed:
        reasons.append("empty package set")

    affected = set(changed)
    # Include workspace consumers outside crates/, and all dependency kinds.
    # Metadata includes all features so optional dependencies are conservative.
    nodes = metadata["resolve"]["nodes"]
    while True:
        added = {node["id"] for node in nodes if any(dependency["pkg"] in affected for dependency in node["deps"])} - affected
        if not added:
            break
        affected.update(added)

    return {
        "full": bool(reasons),
        "reason": "; ".join(reasons) if reasons else "all changed paths map to workspace crates",
        "changed": sorted(packages[package_id]["name"] for package_id in changed),
        "affected": sorted(packages[package_id]["name"] for package_id in affected & members),
    }


def commands(selection: Selection) -> list[list[str]]:
    if selection["full"]:
        return [["just", "qa"]]
    package_args = [arg for package in selection["affected"] for arg in ("--package", package)]
    filterset = " | ".join(f"rdeps({package})" for package in selection["changed"])
    return [
        ["just", *STATIC_CHECKS],
        ["just", "self-check-tests"],
        ["cargo", "nextest", "run", "--workspace", "--locked", "-E", filterset],
        ["cargo", "test", "--doc", "--locked", *package_args],
        ["env", "RUSTDOCFLAGS=-D warnings", "cargo", "doc", "--no-deps", "--locked", *package_args],
    ]


def run_commands(selected_commands: list[list[str]], root: Path) -> None:
    for command in selected_commands:
        print("+ " + shlex.join(command), flush=True)
        subprocess.run(command, cwd=root, check=True)


def main() -> None:
    base = sys.argv[1] if len(sys.argv) > 1 else "main"
    root = Path(output(Path.cwd(), "git", "rev-parse", "--show-toplevel").decode().strip())
    paths = changed_paths(root, base)
    selection = select(root, paths, workspace_metadata(root))
    print(f"self-check: {'full QA' if selection['full'] else 'scoped'}; {selection['reason']}", flush=True)
    print("self-check: changed packages: " + (", ".join(selection["changed"]) or "(none)"), flush=True)
    print("self-check: affected packages: " + (", ".join(selection["affected"]) or "(none)"), flush=True)
    run_commands(commands(selection), root)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode if error.returncode >= 0 else 128 - error.returncode)
