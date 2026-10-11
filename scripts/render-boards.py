#!/usr/bin/env python3
"""Render the two tracking artifacts from structured backlog data.

Why this exists
---------------
The build board and release tracker used to be maintained by editing ~50KB of
HTML directly. Changing a handful of facts meant fetching the whole page,
holding it, rewriting it, and republishing -- one refresh cost roughly 200k
tokens, and the edits landed in presentation code where a stray CSS change
once made the entire board render as a single blank header.

So the data moved out. `internal-docs/boards/*.yaml` is now the source of truth for
board STATE; the templates own presentation and nobody edits them to record a
status change. A status flip is a two-line diff.

Deliberately NOT a full templating engine
-----------------------------------------
The templates are the real published pages with their data array replaced by a
`/*__DATA__*/` marker. Rendering is a single splice of JSON into that spot.
That keeps the design byte-identical to what is already live -- these are
working instruments the owner reads at a glance, and a re-render that quietly
restyles them is a regression even when it looks nicer.

`internal-docs/boards/backlog.yaml` is the single home for planned work: state (id,
status, priority, milestone, lane, bullets) plus each WP's spec fields (goal, build,
depends, acceptance, caveats, findings; see `internal-docs/boards/README.md`). The board
renders the state fields.

Usage:  make boards          (or: python3 scripts/render-boards.py)
        make boards-check    (verify committed HTML matches the YAML)
"""

import argparse
import json
import pathlib
import sys

try:
    import yaml
except ImportError:
    sys.exit("pyyaml is required: pip3 install pyyaml")

REPO = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = REPO / "scripts/board-templates"
DATA = REPO / "internal-docs/boards"
OUT = REPO / "internal-docs/boards"

MARKER = "/*__DATA__*/"

# (data file, top-level key, template, rendered output)
BOARDS = [
    ("backlog.yaml", "work_packages", "build-board.html.tmpl", "build-board.html"),
    ("releases.yaml", "releases", "release-tracker.html.tmpl", "release-tracker.html"),
]

# Every work package must carry these. A card missing `status` renders as a
# silently mis-filed blank rather than an error, which is exactly the failure
# this check exists to convert into a loud one.
REQUIRED_WP_FIELDS = ("id", "title", "status", "prio", "ms", "lane")
VALID_STATUS = {"done", "started", "ready", "blocked"}


def validate(rows, key):
    """Fail loudly on malformed data rather than rendering a broken board."""
    errors = []
    if key == "work_packages":
        seen = {}
        for row in rows:
            wp = row.get("id", "<no id>")
            for field in REQUIRED_WP_FIELDS:
                if field not in row:
                    errors.append(f"WP-{wp}: missing required field `{field}`")
            status = row.get("status")
            if status is not None and status not in VALID_STATUS:
                errors.append(
                    f"WP-{wp}: status `{status}` is not one of {sorted(VALID_STATUS)}"
                )
            if wp in seen:
                errors.append(f"WP-{wp}: duplicate id")
            seen[wp] = True
    if errors:
        sys.exit("backlog data is invalid:\n  " + "\n  ".join(errors))


def render(data_file, key, template, output):
    rows = yaml.safe_load((DATA / data_file).read_text())[key]
    validate(rows, key)

    tmpl = (TEMPLATES / template).read_text()
    if MARKER not in tmpl:
        sys.exit(f"{template} has no {MARKER} marker -- cannot render")

    # `indent=1` keeps the rendered diff readable when the HTML is committed:
    # one line per field beats a single 40KB line where every change looks the
    # same size.
    payload = json.dumps(rows, indent=1, ensure_ascii=False)
    return tmpl.replace(MARKER, payload), len(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--check",
        action="store_true",
        help="verify the committed HTML matches the YAML; exit 1 if it drifted",
    )
    args = ap.parse_args()

    drifted = []
    for data_file, key, template, output in BOARDS:
        html, count = render(data_file, key, template, output)
        dest = OUT / output
        if args.check:
            current = dest.read_text() if dest.exists() else ""
            if current != html:
                drifted.append(output)
                print(f"DRIFTED  {output} ({count} entries in {data_file})")
            else:
                print(f"ok       {output} ({count} entries)")
        else:
            dest.write_text(html)
            print(f"wrote    {dest.relative_to(REPO)} ({count} entries from {data_file})")

    if args.check and drifted:
        sys.exit(
            f"\n{len(drifted)} board(s) out of date with their YAML. "
            f"Run `make boards` and commit the result."
        )


if __name__ == "__main__":
    main()
