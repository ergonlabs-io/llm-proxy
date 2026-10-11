#!/usr/bin/env python3
"""Fail if code or user-facing files cite planning provenance.

AGENTS.md "Comments": comments explain why in place and cite only durable
references (ADRs, envoy-semantics.md S-sections, envoy-divergences.md,
AGENTS.md sections, architecture.md sections, upstream Envoy docs). Work
package IDs, increments, lanes, and planning-document parts go stale as soon
as the plan moves on; git history already records provenance.

Planning and history documents (internal-docs/, CHANGELOG.md, the board
templates) are allowed to name work packages, so they are not scanned.
"""

import re
import subprocess
import sys

PATTERN = re.compile(
    r"WP-\d+"
    r"|\b[Ii]ncrement \d"
    r"|\bLane[- ][A-Z]\b"
    r"|IMPLEMENTATION_PLAN"
    r"|\bPLAN\.md"
    r"|[Gg]round rule"
    r"|Appendix S\b"
)

SCANNED = [
    "crates",
    "testing",
    "scripts",
    "examples",
    "schema",
    "docs",
    "Makefile",
    "Cargo.toml",
    "AGENTS.md",
    "README.md",
    ".github",
]

EXCLUDED = (
    "scripts/board-templates/",  # board data: WP IDs are the content
    "scripts/check-citations.py",  # this file names the patterns
)


def main() -> int:
    files = subprocess.run(
        ["git", "ls-files", "--", *SCANNED],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()
    hits = []
    for path in files:
        if path.startswith(EXCLUDED):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                for lineno, line in enumerate(f, 1):
                    if PATTERN.search(line):
                        hits.append(f"{path}:{lineno}: {line.strip()}")
        except (UnicodeDecodeError, FileNotFoundError):
            continue
    if hits:
        print("Planning citations found (AGENTS.md \"Comments\"):", file=sys.stderr)
        for hit in hits:
            print(f"  {hit}", file=sys.stderr)
        print(f"{len(hits)} hit(s). State the reason in place or cite a durable reference.",
              file=sys.stderr)
        return 1
    print(f"citations ok: {len(files)} files scanned")
    return 0


if __name__ == "__main__":
    sys.exit(main())
