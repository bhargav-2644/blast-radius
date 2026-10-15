"""Scan candidate public repos: lockfile at a pinned date, package count, vulnerable versions.

Used once to pick the demo company's services (see docs/decisions.md).
Usage: python scripts/scan_candidates.py data/raw/npm-osv.zip owner/repo@ref[:path/to/package-lock.json] ...

Lockfiles are fetched from raw.githubusercontent.com at a pinned tag, so the demo is reproducible.
"""
import json
import sys
from pathlib import Path

import httpx

from blast_radius.ingest import lockfile, osv

RAW = "https://raw.githubusercontent.com"


def split_spec(spec: str) -> tuple[str, str, str]:
    """owner/repo@ref[:path] -> (repo, ref, path)"""
    repo, _, rest = spec.partition("@")
    ref, _, path = rest.partition(":")
    return repo, ref, path or "package-lock.json"


def lock_at(client: httpx.Client, spec: str):
    repo, ref, path = split_spec(spec)
    raw = client.get(f"{RAW}/{repo}/{ref}/{path}")
    if raw.status_code != 200:
        return ref, None
    return ref, raw.json()


def main():
    zip_path, repos = Path(sys.argv[1]), sys.argv[2:]
    trees = {}
    with httpx.Client(timeout=60, follow_redirects=True) as client:
        for repo in repos:
            sha, lock = lock_at(client, repo)
            if lock is None:
                print(f"{repo}: no lockfile"); continue
            try:
                trees[repo] = (sha, lockfile.parse(lock))
            except ValueError as e:
                print(f"{repo}: {e} (v{lock.get('lockfileVersion')})")
    names = {p.name for _, t in trees.values() for p in t.packages}
    index = osv.load_index(zip_path, names)
    out = {}
    for repo, (sha, tree) in trees.items():
        hits = {}
        for p in tree.packages:
            for adv in index.get(p.name, []):
                if adv.affects(p.name, p.version):
                    hits.setdefault(adv.id, set()).add(p.name)
        out[repo] = {"sha": sha, "packages": len(tree.packages), "vulns": sorted(hits)}
        print(f"{repo}: {len(tree.packages)} pkgs, {len(hits)} advisories")
    Path("data/candidates.json").write_text(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
