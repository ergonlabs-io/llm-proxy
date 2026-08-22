#!/usr/bin/env python3
"""WP-40: fail if a crate declares a dependency nothing references.

Why this exists rather than `cargo-udeps`: udeps needs a nightly toolchain and
a full build, and `cargo-machete` is not installed here either. This is the
"or equivalent" the WP's acceptance criteria allow. It is a heuristic scanner,
so it is deliberately paired with an ALLOWLIST carrying a written reason for
every entry -- an unexplained suppression is how a checker stops meaning
anything.

The check is source-text based: a dependency is "used" if its crate identifier
appears as a word anywhere in the sources that section covers. That over-counts
(a mention in a comment counts) and under-counts (code generated into OUT_DIR
is invisible). Over-counting is the safe direction for a CI gate: it never
fails a build over a dependency that is genuinely needed. Under-counting is
what the allowlist is for.

Run: python3 scripts/check-deps.py [--list]
"""
import os, re, subprocess, sys

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

def main():
    listing = "--list" in sys.argv
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

if __name__ == "__main__":
    sys.exit(main())
