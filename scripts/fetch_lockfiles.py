"""Download each service's package-lock.json at its pinned ref into data/lockfiles/ (gzipped).

Lockfiles are committed so the graph can be rebuilt offline and identically (D-021).
"""
import gzip
import json
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]


def main():
    company = json.loads((ROOT / "data/company.json").read_text())
    out = ROOT / "data/lockfiles"
    out.mkdir(parents=True, exist_ok=True)
    with httpx.Client(timeout=60, follow_redirects=True) as client:
        for svc in company["services"]:
            path = svc.get("path", "package-lock.json")
            url = f"https://raw.githubusercontent.com/{svc['repo']}/{svc['ref']}/{path}"
            r = client.get(url)
            r.raise_for_status()
            (out / f"{svc['name']}.json.gz").write_bytes(gzip.compress(r.content))
            print(f"{svc['name']}: {len(r.content) // 1024} KB from {url}")


if __name__ == "__main__":
    main()
