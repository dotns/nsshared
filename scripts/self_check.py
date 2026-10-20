#!/usr/bin/env python3
"""Select conservative workspace checks from Git paths and Cargo metadata."""

import ast
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
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
    "rustfmt.toml", ".rustfmt.toml", "config.toml", "nextest.toml",
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


SOURCE_SUFFIXES = {".rs", ".py", ".sh", ".bash", ".js", ".ts", ".mjs", ".c", ".h"}
DOUBLE_STRINGS = re.compile(r'"(?:\\.|[^"\\])*"')
STRINGS = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
READERS = re.compile(
    r"\b(include(?:_str|_bytes)?\s*!|read_to_string|read_to_end|read|read_text|"
    r"read_bytes|read_dir|open|glob|rglob|walk|walkdir|scandir|listdir|WalkDir::new)\s*([([{])"
)
DIRECTORY_READERS = {"read_dir", "glob", "rglob", "walk", "walkdir", "scandir", "listdir", "WalkDir::new"}


def configuration(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return parts[-1] in CONFIG_NAMES or any(part.startswith(".") for part in parts)


def executable_source(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return (configuration(path) or path.endswith(".rs") or
            (parts[0] in {"crates", "examples", "e2e", "scripts", "tools"} and
             PurePosixPath(path).suffix in SOURCE_SUFFIXES))


def tracked_sources(root: Path) -> list[tuple[str, str]]:
    """Keep checked-head dependencies even when a local edit removes a reader."""
    head = output(root, "git", "ls-tree", "-r", "--name-only", "-z", "HEAD").split(b"\0")
    indexed = output(root, "git", "ls-files", "-z").split(b"\0")
    sources = []
    for raw in sorted(set(head + indexed) - {b""}):
        path = raw.decode(errors="surrogateescape")
        if not executable_source(path):
            continue
        versions = set()
        if raw in head:
            versions.add(output(root, "git", "show", f"HEAD:{path}").decode(errors="replace"))
        target = root / path
        if target.is_file():
            versions.add(target.read_text(errors="replace"))
        for text in sorted(versions):
            sources.append((path, text))
    return sources


def path_candidates(value: str, source: str) -> set[str]:
    parent = posixpath.dirname(source)
    # Runtime readers may use the repository or the package as their cwd;
    # inclusion macros use the referencing source file's directory.
    parts = PurePosixPath(source).parts
    package = "/".join(parts[:2]) if len(parts) > 2 and parts[0] in {"crates", "examples"} else ""
    return {posixpath.normpath(posixpath.join(base, value)) for base in ("", parent, package)}


def reader_expression(text: str, start: int) -> str | None:
    closing = {"(": ")", "[": "]", "{": "}"}
    stack = [closing[text[start - 1]]]
    cursor = start
    while cursor < len(text):
        literal = STRINGS.match(text, cursor)
        if literal:
            cursor = literal.end()
            continue
        char = text[cursor]
        if char in closing:
            stack.append(closing[char])
        elif char in closing.values():
            if char != stack.pop():
                return None
            if not stack:
                return text[start:cursor]
        cursor += 1
    return None


def literal_path(expression: str, source: str) -> str | None:
    expression = expression.strip().rstrip(",").strip()
    if STRINGS.fullmatch(expression):
        try:
            return ast.literal_eval(expression)
        except (SyntaxError, ValueError):
            return None
    if re.fullmatch(r'env!\s*\(\s*"CARGO_MANIFEST_DIR"\s*\)', expression):
        parts = PurePosixPath(source).parts
        return "/".join(parts[:2]) if parts[0] in {"crates", "examples"} else "."
    concat = re.match(r"concat!\s*\(", expression)
    if not concat or not expression.endswith(")"):
        return None
    body = expression[concat.end():-1]
    values = []
    start = cursor = depth = 0
    while cursor <= len(body):
        literal = STRINGS.match(body, cursor)
        if literal:
            cursor = literal.end()
            continue
        if cursor == len(body) or body[cursor] == "," and depth == 0:
            part = body[start:cursor].strip()
            if part:
                value = literal_path(part, source)
                if value is None:
                    return None
                values.append(value)
            start = cursor + 1
        elif body[cursor] == "(":
            depth += 1
        elif body[cursor] == ")":
            depth -= 1
        cursor += 1
    return "".join(values)


SHELL_FILE_READERS = {
    "cat", "head", "tail", "sed", "awk", "gawk", "grep", "egrep", "fgrep", "rg",
    "sort", "uniq", "cut", "paste", "join", "wc", "cmp", "diff", "comm", "od",
    "xxd", "strings", "sha256sum", "sha512sum", "md5sum", "cksum", "source", ".",
}
SHELL_DIRECTORY_READERS = {"find", "ls", "tree", "du"}


def shell_references(path: str, source: str, text: str) -> list[str]:
    for line in text.replace("\\\n", " ").splitlines():
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|()<>")
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError:
            return [f"uncertain shell expression in {source}"]
        for index, token in enumerate(tokens):
            command = posixpath.basename(token) if token != "." else token
            redirect = token in {"<", "<>"}
            if not redirect and command not in SHELL_FILE_READERS | SHELL_DIRECTORY_READERS:
                continue
            args = []
            for argument in tokens[index + 1:]:
                if argument and all(char in ";&|()<>" for char in argument):
                    break
                args.append(argument)
                if redirect:
                    break
            for argument in args:
                if any(char in argument for char in "$`*?{}[]"):
                    return [f"uncertain shell input read by {source}: {token}"]
                if argument.startswith("-"):
                    continue
                candidates = path_candidates(argument, source)
                if path in candidates:
                    return [f"shell input read by {source}: {token}"]
                if command in SHELL_DIRECTORY_READERS and any(
                    directory in {".", ".."} or directory.startswith("../") or
                    path.startswith(directory.rstrip("/") + "/") for directory in candidates
                ):
                    return [f"shell directory read by {source}: {token}"]
    return []


def input_references(path: str, sources: list[tuple[str, str]]) -> list[str]:
    references = []
    for source, text in sources:
        if PurePosixPath(source).suffix in {".sh", ".bash"} or PurePosixPath(source).name == "justfile":
            references.extend(shell_references(path, source, text))
        strings = DOUBLE_STRINGS if source.endswith(".rs") else STRINGS
        values = [match.group()[1:-1] for match in strings.finditer(text)]
        candidates = set().union(*(path_candidates(value, source) for value in values))
        if path in candidates or re.search(r"(?<![\w./-])" + re.escape(path) + r"(?![\w./-])", text):
            references.append(f"referenced by {source}")
            continue
        # Do not mistake examples inside string literals for executable reads.
        masked = strings.sub(lambda match: " " * len(match.group()), text)
        for reader in READERS.finditer(masked):
            if re.search(r"\b(?:fn|def)\s+$", masked[:reader.start()]):
                continue
            expression = reader_expression(text, reader.end())
            # Rust file reads take a buffer or a path; lock reads take neither.
            if (source.endswith(".rs") and reader.group(1) == "read" and expression == "" and
                    masked[:reader.start()].rstrip().endswith(".")):
                continue
            value = literal_path(expression, source) if expression is not None else None
            if value is None or value.startswith("/") or any(char in value for char in "*?{}$[]"):
                references.append(f"uncertain computed path or glob in {source}")
                break
            candidates = path_candidates(value, source)
            if path in candidates:
                references.append(f"joined path referenced by {source}")
                break
            if reader.group(1) in DIRECTORY_READERS and any(
                directory in {".", ".."} or directory.startswith("../") or
                path.startswith(directory.rstrip("/") + "/") for directory in candidates
            ):
                references.append(f"directory read by {source}")
                break
    return sorted(set(references))


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
    diagnostics = []
    sources = tracked_sources(root) if any(not path.endswith(".rs") for path in paths) else []
    for path in paths:
        parts = path.split("/")
        directory = "/".join(parts[:2])
        package_id = directories.get(directory) if len(parts) > 2 else None
        rust = path.endswith(".rs")
        if package_id and rust:
            changed.add(package_id)
        cause = ""
        if "vectors" in parts or path.startswith("tools/vectors/"):
            cause = f"vector or generator changed: {path}"
        elif configuration(path):
            cause = f"manifest or tool configuration changed: {path}"
        elif rust and not package_id:
            cause = f"path outside a known crate: {path}"
        elif not rust:
            if executable_source(path):
                cause = f"build or test source: {path}"
            else:
                cause = "; ".join(input_references(path, sources))
        if cause:
            reasons.append(cause)
            if package_id:
                changed.add(package_id)
        if not rust:
            diagnostics.append(f"input: {path} ({cause})" if cause else f"non-input: {path} (no tracked build or test reference)")
        elif cause:
            diagnostics.append(cause)

    if not paths:
        reasons.append("empty diff")
        diagnostics.append("empty diff")

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
        "reason": "; ".join(diagnostics) or "all changed paths map to workspace crates",
        "changed": sorted(packages[package_id]["name"] for package_id in changed),
        "affected": sorted(packages[package_id]["name"] for package_id in affected & members),
    }


def commands(selection: Selection) -> list[list[str]]:
    if selection["full"]:
        return [["just", "qa"]]
    if not selection["affected"]:
        return [["just", *STATIC_CHECKS]]
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
