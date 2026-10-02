"""The phase 2 dependency contract requires ciborium or minicbor for CBOR."""

from pathlib import Path
import tomllib


manifest = Path(__file__).resolve().parents[1] / "Cargo.toml"
with manifest.open("rb") as source:
    dependencies = tomllib.load(source)["dependencies"]

packages = {
    entry.get("package", name) if isinstance(entry, dict) else name
    for name, entry in dependencies.items()
}
assert packages & {"ciborium", "minicbor"}, (
    "required CBOR dependency absent; production dependencies are "
    f"{sorted(packages)}"
)
