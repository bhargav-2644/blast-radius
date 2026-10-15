"""Parse npm package-lock.json (lockfileVersion 2 or 3) into a resolved dependency tree.

Edges follow Node's module resolution: a dependency of the package installed at
`a/node_modules/b` resolves to the nearest `node_modules/<dep>` walking up the path.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Pkg:
    name: str
    version: str

    @property
    def purl(self) -> str:
        return f"pkg:npm/{self.name}@{self.version}"


@dataclass
class Tree:
    root_deps: list[tuple[Pkg, str, bool]]          # (package, declared range, dev)
    edges: set[tuple[Pkg, Pkg, str]]                # (parent, child, declared range)
    packages: set[Pkg]
    # install-level view: one entry per node_modules path, exact for this repo
    installs: dict[str, Pkg]                        # path -> package
    install_dev: dict[str, bool]                    # path -> only needed for development
    root_installs: list[tuple[str, str, bool]]      # (path, declared range, dev)
    install_edges: set[tuple[str, str, str]]        # (parent path, child path, declared range)


def _name_from_path(path: str) -> str:
    return path.rsplit("node_modules/", 1)[-1]


def _resolve(packages: dict, from_path: str, dep: str) -> str | None:
    base = from_path
    while True:
        candidate = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
        if candidate in packages:
            return candidate
        if not base:
            return None
        idx = base.rfind("/node_modules/")
        base = base[:idx] if idx != -1 else ""


def parse(lock: dict) -> Tree:
    if lock.get("lockfileVersion", 1) < 2 or "packages" not in lock:
        raise ValueError("only lockfileVersion 2/3 is supported")
    packages = lock["packages"]
    nodes: dict[str, Pkg] = {}
    for path, meta in packages.items():
        if not path or meta.get("link") or "version" not in meta:
            continue
        nodes[path] = Pkg(meta.get("name") or _name_from_path(path), meta["version"])

    def deps_of(meta: dict) -> list[tuple[str, str, bool]]:
        out = [(d, r, False) for d, r in (meta.get("dependencies") or {}).items()]
        out += [(d, r, False) for d, r in (meta.get("optionalDependencies") or {}).items()]
        out += [(d, r, False) for d, r in (meta.get("peerDependencies") or {}).items()]
        return out

    root_meta = packages.get("", {})
    root_installs = []
    for dep, rng, _ in deps_of(root_meta):
        path = _resolve(packages, "", dep)
        if path in nodes:
            root_installs.append((path, rng, False))
    for dep, rng in (root_meta.get("devDependencies") or {}).items():
        path = _resolve(packages, "", dep)
        if path in nodes:
            root_installs.append((path, rng, True))

    install_edges = set()
    for path in nodes:
        for dep, rng, _ in deps_of(packages[path]):
            child_path = _resolve(packages, path, dep)
            if child_path in nodes:
                install_edges.add((path, child_path, rng))
    return Tree(
        root_deps=[(nodes[p], r, d) for p, r, d in root_installs],
        edges={(nodes[a], nodes[b], r) for a, b, r in install_edges},
        packages=set(nodes.values()),
        installs=nodes,
        install_dev={p: bool(packages[p].get("dev")) for p in nodes},
        root_installs=root_installs,
        install_edges=install_edges,
    )
