from blast_radius.ingest import lockfile
from blast_radius.ingest.osv import Advisory

LOCK = {
    "lockfileVersion": 3,
    "packages": {
        "": {"dependencies": {"a": "^1.0.0"}, "devDependencies": {"c": "^1.0.0"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^2.0.0"}},
        "node_modules/a/node_modules/b": {"version": "2.0.0"},
        "node_modules/b": {"version": "3.0.0"},
        "node_modules/c": {"version": "1.0.0", "dev": True, "dependencies": {"b": "^3.0.0"}},
    },
}


def test_nested_install_resolves_to_nearest_node_modules():
    tree = lockfile.parse(LOCK)
    assert ("node_modules/a", "node_modules/a/node_modules/b", "^2.0.0") in tree.install_edges
    assert ("node_modules/c", "node_modules/b", "^3.0.0") in tree.install_edges
    assert {(p, d) for p, _, d in tree.root_installs} == {("node_modules/a", False), ("node_modules/c", True)}
    assert tree.install_dev["node_modules/c"] is True


def test_advisory_ranges():
    adv = Advisory(id="X", aliases=[], summary="", severity=None, published="",
                   ranges={"b": [("2.0.0", "2.1.0", None), ("0", None, "1.5.0")]})
    assert adv.affects("b", "2.0.5")
    assert not adv.affects("b", "2.1.0")
    assert adv.affects("b", "1.5.0")
    assert not adv.affects("b", "1.6.0")
    assert adv.fixed_versions("b") == ["2.1.0"]
