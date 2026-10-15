"""Read OSV npm advisories and match them against exact package versions.

Version matching happens here, at ingest time, so the graph only stores
AFFECTS / FIXED_IN edges and every runtime question is a pure traversal (D-005).
"""
import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import semver


@dataclass
class Advisory:
    id: str
    aliases: list[str]
    summary: str
    severity: str | None
    published: str
    # per affected package: list of (introduced, fixed, last_affected) intervals
    ranges: dict[str, list[tuple[str | None, str | None, str | None]]] = field(default_factory=dict)
    versions: dict[str, set[str]] = field(default_factory=dict)

    def affects(self, package: str, version: str) -> bool:
        if version in self.versions.get(package, ()):
            return True
        v = _parse(version)
        if v is None:
            return False
        for introduced, fixed, last_affected in self.ranges.get(package, ()):
            lo = _parse(introduced) if introduced not in (None, "0") else None
            if lo is not None and v < lo:
                continue
            if fixed is not None:
                hi = _parse(fixed)
                if hi is not None and v >= hi:
                    continue
            if last_affected is not None:
                la = _parse(last_affected)
                if la is not None and v > la:
                    continue
            return True
        return False

    def describe_ranges(self, package: str) -> list[str]:
        out = []
        for introduced, fixed, last in self.ranges.get(package, ()):
            lo = f">={introduced}" if introduced not in (None, "0") else ""
            hi = f"<{fixed}" if fixed else (f"<={last}" if last else "")
            out.append(" ".join(x for x in (lo, hi) if x) or "all versions")
        out += sorted(self.versions.get(package, ()))
        return out

    def fixed_versions(self, package: str) -> list[str]:
        return [f for _, f, _ in self.ranges.get(package, ()) if f]


def _parse(v: str | None):
    if not v:
        return None
    try:
        return semver.Version.parse(v.lstrip("v"))
    except ValueError:
        return None


def _severity(doc: dict) -> str | None:
    sev = (doc.get("database_specific") or {}).get("severity")
    if sev:
        return sev.upper()
    for aff in doc.get("affected", []):
        sev = (aff.get("database_specific") or {}).get("severity")
        if sev:
            return sev.upper()
    return None


def _advisory(doc: dict) -> Advisory | None:
    adv = Advisory(
        id=doc["id"],
        aliases=doc.get("aliases", []),
        summary=doc.get("summary") or (doc.get("details") or "")[:200],
        severity=_severity(doc),
        published=doc.get("published", ""),
    )
    for aff in doc.get("affected", []):
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != "npm":
            continue
        name = pkg["name"]
        if aff.get("versions"):
            adv.versions.setdefault(name, set()).update(aff["versions"])
        for r in aff.get("ranges", []):
            if r.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            introduced = None
            for event in r.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                elif "fixed" in event:
                    adv.ranges.setdefault(name, []).append((introduced, event["fixed"], None))
                    introduced = None
                elif "last_affected" in event:
                    adv.ranges.setdefault(name, []).append((introduced, None, event["last_affected"]))
                    introduced = None
            if introduced is not None:
                adv.ranges.setdefault(name, []).append((introduced, None, None))
    if not adv.ranges and not adv.versions:
        return None
    return adv


def load_index(zip_path: Path, packages: set[str] | None = None) -> dict[str, list[Advisory]]:
    """Map package name -> advisories, optionally only for the given packages.

    Withdrawn advisories are skipped.
    """
    index: dict[str, list[Advisory]] = {}
    with zipfile.ZipFile(zip_path) as z:
        for name in z.namelist():
            doc = json.loads(z.read(name))
            if doc.get("withdrawn"):
                continue
            names = {
                (a.get("package") or {}).get("name")
                for a in doc.get("affected", [])
                if (a.get("package") or {}).get("ecosystem") == "npm"
            }
            if packages is not None and not (names & packages):
                continue
            adv = _advisory(doc)
            if adv is None:
                continue
            for pkg in adv.ranges.keys() | adv.versions.keys():
                index.setdefault(pkg, []).append(adv)
    return index
