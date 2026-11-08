#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p dist
VER="$(tr -d '\r\n' < VERSION)"
cargo metadata --format-version 1 > dist/sbom-cargo-metadata.json
python3 - <<PY
import json
from pathlib import Path
meta=json.loads(Path("dist/sbom-cargo-metadata.json").read_text())
ver=Path("VERSION").read_text().strip()
comps=[{"name":p["name"],"version":p["version"],"id":p["id"],"license":p.get("license"),"source":p.get("source")} for p in meta["packages"]]
doc={"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"metadata":{"component":{"type":"application","name":"swifwire","version":ver}},"components":comps}
Path("dist/sbom-cargo.json").write_text(json.dumps(doc,indent=2))
print(f"SBOM OK dist/sbom-cargo.json ({len(comps)} components)")
PY
