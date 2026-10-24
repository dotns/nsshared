"""Exercise handoff comparison against real temporary Git inputs."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


class HandoffTest(unittest.TestCase):
    def test_manifest_lock_and_candidate_drift_are_refused(self):
        spec = importlib.util.spec_from_file_location(
            "candidate_handoff", Path(__file__).with_name("candidate_handoff.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            def write(path, content):
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content)
            write("Cargo.toml", '[workspace.package]\nversion="0.6.0"\n')
            write("Cargo.lock", 'version=4\n')
            for name in module.PACKAGES:
                write(f"crates/{name}/Cargo.toml", f'[package]\nname="{name}"\nversion.workspace=true\n')
                write(f"crates/{name}/src/lib.rs", 'pub const VERSION: u8 = 1;\n')
            write("crates/nsshared-proto/tests/fixtures/vectors/example.vec", "bytes = 01\n")
            write("tools/vectors/generate.py", '# independent producer\n')
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(["git", "-C", str(root), "-c", "user.name=Test", "-c",
                            "user.email=test@example.invalid", "commit", "-qm", "test: create inputs"], check=True)
            candidate = module.git(root, "rev-parse", "HEAD").decode().strip()
            url = "ssh://example.invalid/shared.git"
            manifest = '[dependencies]\n' + '\n'.join(
                f'{name}={{git="{url}",rev="{candidate}"}}' for name in module.PACKAGES)
            lock = 'version=4\n' + '\n'.join(
                f'[[package]]\nname="{name}"\nversion="0.6.0"\nsource="git+{url}?rev={candidate}#{candidate}"\n'
                for name in module.PACKAGES)
            module.check_consumer(manifest, lock, candidate, {n: "0.6.0" for n in module.PACKAGES}, set(module.PACKAGES))
            for bad_manifest, bad_lock in [
                (manifest.replace(candidate, "0" * 40), lock),
                (manifest, lock.replace("#" + candidate, "#" + "0" * 40)),
                (manifest, lock.replace('version="0.6.0"', 'version="0.5.0"')),
                (manifest, 'version=4\n'),
                (manifest.replace('rev=', 'branch='), lock),
            ]:
                with self.assertRaises(ValueError):
                    module.check_consumer(bad_manifest, bad_lock, candidate, {n: "0.6.0" for n in module.PACKAGES}, set(module.PACKAGES))
            module.check_candidate(root, candidate)
            for path in ["Cargo.lock", "crates/nsshared-proto/src/lib.rs", "tools/vectors/generate.py", "crates/nsshared-proto/tests/fixtures/vectors/example.vec"]:
                original = (root / path).read_text()
                write(path, original + '\n')
                with self.assertRaises(ValueError):
                    module.check_candidate(root, candidate)
                write(path, original)
            write("crates/nsshared-proto/src/extra.rs", "pub const EXTRA: u8 = 1;\n")
            with self.assertRaises(ValueError):
                module.check_candidate(root, candidate)


if __name__ == "__main__":
    unittest.main()
