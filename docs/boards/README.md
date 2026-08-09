# Tracking boards

Two published artifacts, generated — never hand-edited.

| File | What it answers |
|---|---|
| `backlog.yaml` → `build-board.html` 🧱 | what state is each work package in |
| `releases.yaml` → `release-tracker.html` 🚦 | are we going to ship, and what stands in the way |

```sh
make boards         # re-render both from YAML
make boards-check   # fail if the HTML drifted from the YAML
```

## Editing

Edit the **YAML**. `make boards` overwrites the HTML, so a hand edit there is
lost at the next render — `make boards-check` is what catches that before you
lose it.

To change how a board *looks*, edit `scripts/board-templates/*.html.tmpl`.
Those are the real published pages with their data array replaced by a
`/*__DATA__*/` marker; rendering splices JSON into that spot and changes
nothing else.

### The templates carry prose, and NOTHING validates it

`make boards-check` compares the rendered **data array** against the YAML. The
narrative around the cards — the eyebrow line, the "Now" block, the ship-gate
summary — lives in the template and is checked by no tool and no schema. It
therefore rots silently while every automated check stays green.

This is not hypothetical. On 2026-08-06 the build-board template still read
*"v0.0.1 gate is unchanged: still red"* eleven lines below its own
*"v0.0.1 shipped 2026-08-01"*, and still said provider failover *"has no code
yet"* after two of its increments had landed. Both survived a board refresh
that same day, because the refresh audited the YAML and the YAML was right.

**So: every board refresh must re-read the template prose against the data it
sits next to.** The eyebrow's WP count, test count and date are part of that —
and a test count must come from an actual run, never from the previous value.

## Why this is generated

These pages were maintained by editing ~50KB of HTML in place. One refresh cost
roughly 200k tokens, and the edits landed in presentation code: a sticky header
with no height cap once grew until it pushed the entire board off-screen, and
the page reported as "one big block with no items."

Splitting state from presentation makes a status flip a two-line diff, and puts
CSS changes somewhere they get reviewed on their own.

## What lives here, and what doesn't

Only **state**: id, status, priority, milestone, lane, and the card's bullet
lines. Normative prose — the *why*, the build scope, acceptance criteria —
stays in `IMPLEMENTATION_PLAN.md`, joined on the WP id.

Duplicating the prose into YAML would create two things to drift, and the plan
is the one that wins. If a card's bullets and the plan disagree, the plan is
right and the card is stale.

## Publishing

Rendering does not publish. To update the live artifacts, publish the rendered
HTML to the **existing** URLs — a fresh publish mints a new URL and orphans the
one the owner has bookmarked. The URLs and favicons (🧱 / 🚦) are recorded in
the product-manager agent definition (`.claude/agents/product-manager.md`).
