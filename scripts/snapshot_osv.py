"""Cut the OSV npm dump down to the advisories that concern a package in our lockfiles (D-033).

The full dump is ~220 MB; the snapshot is a few MB and is committed, so a fresh deploy can build
the graph without downloading anything. Re-run after scripts/fetch_osv.sh to refresh it:

    uv run python scripts/snapshot_osv.py
"""
import gzip
import json
import zipfile
from pathlib import Path

from blast_radius.ingest import lockfile

DATA = Path(__file__).resolve().parent.parent / "data"
SRC, DST = DATA / "raw/npm-osv.zip", DATA / "osv/npm-snapshot.zip"

names: set[str] = set()
for lock_path in [*DATA.glob("lockfiles/*.json.gz"), *DATA.glob("scenarios/*.json.gz")]:
    tree = lockfile.parse(json.loads(gzip.decompress(lock_path.read_bytes())))
    names |= {p.name for p in tree.installs.values()}

kept = 0
DST.parent.mkdir(exist_ok=True)
with zipfile.ZipFile(SRC) as src, zipfile.ZipFile(DST, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as dst:
    for entry in sorted(src.namelist()):
        doc = json.loads(src.read(entry))
        affected = {(a.get("package") or {}).get("name") for a in doc.get("affected", [])}
        if affected & names:
            dst.writestr(entry, json.dumps(doc, separators=(",", ":")))
            kept += 1
print(f"{kept} advisories for {len(names)} package names -> {DST} ({DST.stat().st_size / 1e6:.1f} MB)")
