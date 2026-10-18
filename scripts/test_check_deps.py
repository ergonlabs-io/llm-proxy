"""Tests for the layering check in check-deps.py.

Each test builds a small fixture tree of manifests in a temp dir, so a rule
that stops firing fails here rather than letting a bad edge through CI.

Run: make deps-check
"""
import importlib.util
import os
import tempfile
import textwrap
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "check_deps", os.path.join(_HERE, "check-deps.py"))
check_deps = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_deps)


class LayeringTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        # A minimal tree that satisfies every rule.
        self.crate("proxy-api")
        self.crate("proxy-config", deps={"proxy-api": "{ workspace = true }"})
        self.crate("proxy-http", deps={"proxy-config": "{ workspace = true }"})
        self.crate("proxy-core", deps={"proxy-http": "{ workspace = true }"})

    def tearDown(self):
        self._tmp.cleanup()

    def crate(self, name, deps=None, dev=None, extra="", kind="crates"):
        d = os.path.join(self.root, kind, name)
        os.makedirs(d, exist_ok=True)
        body = f'[package]\nname = "{name}"\n'
        for section, table in (("dependencies", deps), ("dev-dependencies", dev)):
            if table:
                body += f"\n[{section}]\n"
                body += "".join(f"{k} = {v}\n" for k, v in table.items())
        body += textwrap.dedent(extra)
        with open(os.path.join(d, "Cargo.toml"), "w") as fh:
            fh.write(body)

    def findings(self):
        return check_deps.layering_findings(self.root)

    def assert_one(self, needle):
        found = self.findings()
        self.assertEqual(len(found), 1, found)
        self.assertIn(needle, found[0])

    def test_clean_tree_passes(self):
        self.assertEqual(self.findings(), [])

    def test_upward_edge_fails(self):
        self.crate("proxy-http", deps={"proxy-core": "{ workspace = true }"})
        self.assert_one("proxy-http (L4) [dependencies] proxy-core (L6)")

    def test_same_layer_edge_fails(self):
        self.crate("proxy-xds")
        self.crate("proxy-cluster", deps={"proxy-xds": "{ workspace = true }"})
        self.assert_one("proxy-cluster (L3) [dependencies] proxy-xds (L3)")

    def test_build_dependency_is_checked(self):
        self.crate("proxy-config", extra="""
            [build-dependencies]
            proxy-http = { workspace = true }
        """)
        self.assert_one("proxy-config (L2) [build-dependencies] proxy-http")

    def test_target_specific_dependency_is_checked(self):
        self.crate("proxy-config", extra="""
            [target.'cfg(unix)'.dependencies]
            proxy-core = { workspace = true }
        """)
        self.assert_one("proxy-config (L2) [dependencies] proxy-core (L6)")

    def test_renamed_dependency_is_checked(self):
        self.crate("proxy-http",
                   deps={"core": '{ package = "proxy-core", path = "../proxy-core" }'})
        self.assert_one("proxy-http (L4) [dependencies] core (L6)")

    def test_upward_dev_dependency_passes(self):
        self.crate("proxy-config", dev={"proxy-core": "{ workspace = true }"})
        self.assertEqual(self.findings(), [])

    def test_unknown_crate_fails(self):
        self.crate("proxy-new")
        self.assert_one("proxy-new: no row in LAYERS")

    def test_proto_crate_outside_allowlist_fails(self):
        self.crate("proxy-cluster", deps={"proxy-api": "{ workspace = true }"})
        self.assert_one("generated protos stay in proxy-config and proxy-xds")

    def test_proto_allowlist_passes(self):
        self.crate("proxy-observability", deps={"proxy-api": "{ workspace = true }"})
        self.assertEqual(self.findings(), [])

    def test_forbidden_external_fails(self):
        self.crate("proxy-http", deps={"proxy-config": "{ workspace = true }",
                                       "redb": "{ workspace = true }"})
        self.assert_one("proxy-http [dependencies] redb: forbidden")

    def test_forbidden_external_is_per_crate(self):
        self.crate("proxy-capture-spool", deps={"redb": "{ workspace = true }"})
        self.assertEqual(self.findings(), [])

    def test_harness_crate_in_normal_deps_fails(self):
        self.crate("mockupstream", kind="testing",
                   deps={"proxy-core": "{ workspace = true }"})
        self.crate("proxy-core", deps={"proxy-http": "{ workspace = true }",
                                       "mockupstream": '{ path = "../../testing/mockupstream" }'})
        self.assert_one("proxy-core [dependencies] mockupstream: test harness crate")

    def test_harness_crate_may_depend_on_anything(self):
        self.crate("diffrig", kind="testing",
                   deps={"proxy-core": "{ workspace = true }",
                         "proxy-api": "{ workspace = true }"})
        self.crate("proxy-core", dev={"diffrig": '{ path = "../../testing/diffrig" }'},
                   deps={"proxy-http": "{ workspace = true }"})
        self.assertEqual(self.findings(), [])


if __name__ == "__main__":
    unittest.main()
