#!/usr/bin/env python3
"""Fail if a crate declares a dependency nothing references, or depends
against the layering table.

Why this exists rather than `cargo-udeps`: udeps needs a nightly toolchain and
a full build, and `cargo-machete` is not installed here either. This is a
heuristic scanner, so it is deliberately paired with an ALLOWLIST carrying a
written reason for every entry -- an unexplained suppression is how a checker
stops meaning anything.

The check is source-text based: a dependency is "used" if its crate identifier
appears as a word anywhere in the sources that section covers. That over-counts
(a mention in a comment counts) and under-counts (code generated into OUT_DIR
is invisible). Over-counting is the safe direction for a CI gate: it never
fails a build over a dependency that is genuinely needed. Under-counting is
what the allowlist is for.

The layering check reads the manifests with the stdlib `tomllib`, so it
needs no cargo tool and no download. It enforces internal-docs/architecture.md
section 2 and AGENTS.md invariant 2; see LAYERS below.

Run: python3 scripts/check-deps.py [--list]
"""
import os, re, subprocess, sys, tomllib

# (crate, section, dep) -> why the scanner cannot see the use.
ALLOWLIST = {
    ("proxy-api", "dependencies", "prost"):
        "Used by the generated proto code, which build.rs writes to OUT_DIR and "
        "src/lib.rs splices in with include!(concat!(env!(\"OUT_DIR\"), ...)). "
        "Nothing under src/ names prost directly and nothing should. "
        "NOTE: this entry currently does not trigger, because the word 'prost' "
        "also appears in a doc comment in build.rs and this scanner counts a "
        "comment mention as a use. Kept deliberately: the real justification is "
        "the OUT_DIR code, and if that comment is ever reworded the check would "
        "otherwise flag prost with no recorded reason.",
    ("proxy-api", "dependencies", "prost-types"):
        "Same as prost: referenced only from the OUT_DIR-generated code, for the "
        "well-known types (Any, Duration, Struct) the vendored Envoy protos use.",
}

CRATE_DIRS = ["crates", "testing"]

def sections(path):
    cur, out = None, {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            m = re.match(r"\s*\[([^\]]+)\]\s*$", line)
            if m:
                cur = m.group(1)
                out.setdefault(cur, [])
                continue
            if cur:
                out[cur].append(line)
    return out

def crate_manifests():
    for root in CRATE_DIRS:
        if not os.path.isdir(root):
            continue
        for name in sorted(os.listdir(root)):
            p = os.path.join(root, name, "Cargo.toml")
            if os.path.exists(p):
                yield name, p

def used(ident, paths):
    # Paths may be directories (src/, tests/) or single files (build.rs).
    # An earlier version guarded with os.path.isdir alone, which silently
    # skipped every build.rs and made build-dependencies unverifiable -- a
    # checker with a blind spot reports success it has not earned.
    for path in paths:
        if not os.path.exists(path):
            continue
        if subprocess.run(["grep", "-rqE", rf"\b{re.escape(ident)}\b", path],
                          capture_output=True).returncode == 0:
            return True
    return False

# Layering (internal-docs/architecture.md section 2). A [dependencies] or
# [build-dependencies] edge between workspace crates must point to a strictly
# lower layer. [dev-dependencies] are exempt: tests may reach upward (for
# example proxy-config's tests parse filter configs) and cargo cannot build a
# cycle from them. Every crate under crates/ needs a row, so a new crate cannot
# skip the check. Crates under testing/ are harnesses and may depend on
# anything, but nothing may list one in [dependencies].
LAYERS = {
    "proxy-api": 0,
    "proxy-capture-protocol": 0,
    "proxy-capture-spool": 0,
    "proxy-observability": 1,
    "proxy-config": 2,
    "proxy-credentials": 2,
    "proxy-simple-config": 3,
    "proxy-xds": 3,
    "proxy-cluster": 3,
    "proxy-capture-agent": 3,
    "proxy-http": 4,
    "proxy-control": 5,
    "proxy-filters": 6,
    "proxy-core": 7,
    "proxy-admin": 8,
    "proxy": 9,
}

# AGENTS.md invariant 2: generated protos stay inside proxy-config and
# proxy-xds, so only they may list proxy-api in [dependencies].
PROTO_CRATE = "proxy-api"
PROTO_CONSUMERS = {"proxy-config", "proxy-xds"}
# (crate) -> why it may depend on proxy-api directly anyway.
PROTO_ALLOWLIST = {
    "proxy-observability":
        "The OTLP exporters encode opentelemetry.proto request types, which "
        "proxy-api generates. They are export wire types, not config, so there "
        "is nothing to lower to IR.",
    "proxy":
        "main.rs builds the ADS gRPC client (AggregatedDiscoveryServiceClient) "
        "and reads DiscoveryResponse/DeltaDiscoveryResponse, which proxy-api "
        "generates. The resources inside still lower through proxy-xds and "
        "proxy-config.",
}

# (crate) -> external crates it must not list in [dependencies]. Storage
# backends belong to the control plane, not the HTTP data plane.
FORBIDDEN_EXTERNAL = {
    "proxy-http": {"redb", "redis"},
    "proxy-filters": {"redb", "redis"},
}

LAYER_SECTIONS = ("dependencies", "build-dependencies")


def manifest_deps(doc, section):
    """Yield (declared name, package name) for one section, including the
    same section under every [target.*] table."""
    tables = [doc.get(section, {})]
    for target in doc.get("target", {}).values():
        tables.append(target.get(section, {}))
    for table in tables:
        for name, spec in table.items():
            pkg = spec.get("package", name) if isinstance(spec, dict) else name
            yield name, pkg


def layering_findings(root):
    """Return a list of human-readable layering violations under root."""
    crates = {}  # package name -> (dir kind, manifest doc)
    for kind in CRATE_DIRS:
        base = os.path.join(root, kind)
        if not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base)):
            p = os.path.join(base, name, "Cargo.toml")
            if not os.path.exists(p):
                continue
            with open(p, "rb") as fh:
                doc = tomllib.load(fh)
            pkg = doc.get("package", {}).get("name", name)
            crates[pkg] = (kind, doc)

    out = []
    for pkg, (kind, doc) in sorted(crates.items()):
        if kind == "crates" and pkg not in LAYERS:
            out.append(f"{pkg}: no row in LAYERS; give the new crate a layer")
            continue
        for section in LAYER_SECTIONS:
            for name, dep in manifest_deps(doc, section):
                if kind == "crates" and dep in FORBIDDEN_EXTERNAL.get(pkg, ()):
                    out.append(f"{pkg} [{section}] {name}: forbidden in this crate")
                if dep not in crates:
                    continue
                dep_kind = crates[dep][0]
                if dep_kind == "testing":
                    out.append(f"{pkg} [{section}] {name}: test harness crate "
                               "in a non-dev section")
                    continue
                if kind == "testing":
                    continue
                if dep not in LAYERS:
                    continue  # reported on its own row above
                if LAYERS[dep] >= LAYERS[pkg]:
                    out.append(f"{pkg} (L{LAYERS[pkg]}) [{section}] {name} "
                               f"(L{LAYERS[dep]}): must point to a lower layer")
                if (dep == PROTO_CRATE and pkg not in PROTO_CONSUMERS
                        and pkg not in PROTO_ALLOWLIST):
                    out.append(f"{pkg} [{section}] {name}: generated protos stay "
                               "in proxy-config and proxy-xds (AGENTS.md "
                               "invariant 2)")
    return out


def unused_main(listing):
    findings, allowed = [], 0
    for crate, manifest in crate_manifests():
        base = os.path.dirname(manifest)
        secs = sections(manifest)
        scopes = {
            "dependencies": [f"{base}/src", f"{base}/build.rs"],
            "dev-dependencies": [f"{base}/tests", f"{base}/src",
                                 f"{base}/benches", f"{base}/examples"],
            "build-dependencies": [f"{base}/build.rs"],
        }
        for section, dirs in scopes.items():
            for line in secs.get(section, []):
                m = re.match(r"([A-Za-z0-9_-]+)\s*=", line.strip())
                if not m:
                    continue
                dep = m.group(1)
                if used(dep.replace("-", "_"), dirs) or used(dep, dirs):
                    continue
                key = (crate, section, dep)
                if key in ALLOWLIST:
                    allowed += 1
                    if listing:
                        print(f"  allowed  {crate} [{section}] {dep}\n"
                              f"           {ALLOWLIST[key]}")
                    continue
                findings.append(key)

    if listing:
        print(f"\n{allowed} allowlisted suppression(s).")
    if findings:
        print("Unused dependencies (declared, never referenced):\n")
        for crate, section, dep in findings:
            print(f"  {crate} [{section}] {dep}")
        print("\nRemove it, or add it to ALLOWLIST in this script WITH A REASON "
              "if the use is invisible to a text scan (generated code, macros).")
        return 1
    print(f"deps ok: no unused dependencies ({allowed} allowlisted)")
    return 0

def layering_main(listing):
    if listing:
        for crate, why in sorted(PROTO_ALLOWLIST.items()):
            print(f"  allowed  {crate} [dependencies] {PROTO_CRATE}\n"
                  f"           {why}")
    findings = layering_findings(".")
    if findings:
        print("Layering violations (see LAYERS in scripts/check-deps.py):\n")
        for f in findings:
            print(f"  {f}")
        return 1
    print(f"layering ok: {len(LAYERS)} crates in the table "
          f"({len(PROTO_ALLOWLIST)} proto exceptions allowlisted)")
    return 0


def main():
    listing = "--list" in sys.argv
    # Run both so one failure does not hide the other.
    return unused_main(listing) | layering_main(listing)


if __name__ == "__main__":
    sys.exit(main())
