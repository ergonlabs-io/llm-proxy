# WP-53 — versioned model pricing: design brief

**Status:** design, 2026-08-08, from owner direction: *"support for updating versioned
pricing information so that eventual rate limiting can be done on dollar values as well."*

## What is and is not already owned

- **WP-42 (spend controls)** already owns "a cost model over the four token buckets priced
  per model", budget scopes, and the enforcement point. **Dollar-based limiting is WP-42's**,
  and this brief does not take it.
- **WP-49 (backend taxonomy)** owns the model catalogue, but is explicitly *"naming and data
  model only"*.
- **Nothing owns the prices themselves** — where they come from, how an operator updates
  them, what "versioned" means, or what happens to already-recorded spend when a price
  changes. That gap is this WP, and it is a **prerequisite for WP-42**: a spend ceiling
  cannot be built on a price list nobody can update.

## The decision that everything else follows from

**Record the computed cost at request time. Never store tokens and price them later.**

The tempting design is to keep raw token counts and multiply by the current price whenever
someone asks. It is wrong for a reason that only shows up after the first price change:

- A tenant's spend for *last Tuesday* would change when a price list lands this Friday.
- A budget that was not exceeded becomes exceeded retroactively, or the reverse.
- "Why was I charged this?" becomes unanswerable, because the inputs no longer exist.

So a completed request produces a **cost record**: the four token counts (kept, for
observability), the **computed list-price cost** (`list_cost_nanodollars` — see "the naming
consequence" below for why it is not called `cost`), and **the price-list version that
computed it**. The cost is authoritative for budgets; the tokens are evidence. A later price
change moves nothing already recorded.

This also makes the enforcement path deterministic, which matters because dollar limiting
has the same retrospective shape as WP-34's token limiting — cost is unknown until the
response completes, so it is check-before / record-after, and the *next* request is the one
that gets denied.

## Money is integer arithmetic, and the unit is not dollars

Never `f64`. Provider prices are quantities like `$0.000003` per token, budgets are
quantities like `$25.00`, and floating-point accumulation over millions of requests produces
a number nobody can reconcile against an invoice.

Store **nanodollars per token** as `u64`:

- `$3.00 per 1M tokens` → `3000` nanodollars/token.
- `cost_nanodollars = tokens × price_nanodollars_per_token`, integer throughout.
- 1M tokens at that price = `3 × 10⁹` nanodollars = `$3.00`, comfortably inside `u64`.

All arithmetic **saturating**, per WP-48 — these multiply a wire-derived token count by a
config-derived price, which is exactly the class WP-48 swept.

Rendering to dollars for display happens at the edge, once, and never feeds back into
accounting.

## Prices are per token bucket, and collapsing them is structurally wrong

`LlmTokenUsage` has four non-overlapping buckets — input, cache-read, cache-write, output —
and its doc already says why: *they are priced differently*. Cache reads bill at a steep
discount and cache writes at a premium.

So a price entry carries four rates, not one, and not two. A cost model that prices
`input + output` cannot be made correct for a cache-heavy workload later; it can only be
replaced. This is the same reason the four buckets exist at all, and it is worth restating
because "price × total tokens" is the obvious first implementation.

## Versioning: effective-dated lists, and the version travels with the spend

A **price list** is a versioned, effective-dated set of entries:

```
price_list:
  version: "2026-08-08.1"     # operator-chosen, opaque, must be unique
  effective_from: "2026-08-08T00:00:00Z"
  entries:
    - provider_type: openai
      model: gpt-5
      input_nanodollars_per_token: 1250
      cached_input_nanodollars_per_token: 125
      cache_write_nanodollars_per_token: 1560
      output_nanodollars_per_token: 10000
```

Two properties matter:

1. **A request is priced with the list in effect when it completed** — not "the newest list".
   Those differ during a rollout, and a fleet mid-rollout must not price the same request two
   ways depending on which replica served it.
2. **The version is recorded on the cost record.** Without it, an operator disputing a figure
   has no way to reconstruct it, and we would be asking them to trust arithmetic they cannot
   check. This is the pricing equivalent of the audit requirement that made `KeyId` separate
   from `TenantId`.

## Tiered rates: the rate is not a scalar (owner, 2026-08-08)

> *"claude opus 4.8 can be priced at x dollars but will get a price cut after opus 5 is
> released. Similarly some might charge x dollar when tokens is below x tokens and y dollar
> when token is above x tokens."*

Those are two different mechanisms and only the first was designed for.

**The price cut is effective-dating, and it already works.** Opus 4.8 at one rate today and a
lower rate once Opus 5 ships is exactly a new price list with a later `effective_from`.
Nothing changes — and note this is also the case that makes "never re-price history"
load-bearing rather than pedantic: after the cut, last month's requests must still cost what
they cost.

**Volume thresholds are new, and they make a rate a function of quantity.** A price entry
therefore carries a **list of tiers**, not four scalars:

```yaml
- provider_type: google
  model: gemini-2.5-pro
  tier_basis: input_tokens        # which quantity the thresholds are measured against
  tier_mode: whole_request        # or `graduated` -- see below, no default
  tiers:
    - up_to: 200000               # omitted on the last tier = "and above"
      input_nanodollars_per_token: 1250
      cached_input_nanodollars_per_token: 125
      cache_write_nanodollars_per_token: 1560
      output_nanodollars_per_token: 10000
    - input_nanodollars_per_token: 2500
      cached_input_nanodollars_per_token: 250
      cache_write_nanodollars_per_token: 3120
      output_nanodollars_per_token: 15000
```

Three things here are decisions, not formatting.

**1. A tier supplies all four rates, and the threshold is measured against its own quantity.**
Real long-context pricing raises the *output* rate based on the *input* size — the request is
more expensive to serve, not just bigger. So `tier_basis` names the measured quantity
(normally input tokens) and each tier carries the full set of four rates. Per-bucket
independent tiers would not express the common case and would express nonsense ones.

**2. `tier_mode` has no default, because guessing it silently produces wrong money.**

- `whole_request` — cross the threshold and the **entire** request prices at the higher tier.
- `graduated` — the first 200k tokens price at tier 1 and only the remainder at tier 2, the
  way income tax brackets work.

These give **different numbers for the same request**, both are real in the market, and
neither is more "natural" than the other. A default would be a coin flip applied to every
invoice, so the field is required and a config omitting it is a load error with its dotted
path. This is ground rule #1 applied to arithmetic rather than to a field name.

**3. Tiers must be validated at load, not trusted.** Ascending `up_to`, no duplicates,
exactly one open-ended final tier, at least one tier. A malformed ladder is a config error —
never a silent fallback to the first tier, which would look like it worked and under-bill
every large request.

### Cumulative volume discounts are NOT this, and they break the design

"First 1M tokens this month at X, thereafter at Y" looks like the same feature and is not. It
makes cost depend on **accumulated usage across requests**, which breaks three properties
this brief is built on:

- **Cost stops being a function of the request.** It becomes a function of the request *and*
  every request before it, so two concurrent requests can both observe "under the threshold"
  and both price low. The total then depends on scheduling.
- **It couples pricing to the spend counter** — the read-modify-write half this brief
  explicitly left to WP-42 — and puts that dependency on the pricing path.
- **Retroactive tiers re-price history outright.** Some real volume pricing is retroactive
  ("exceed 1M and *all* of this month's tokens bill at the lower rate"). That directly
  contradicts the central guarantee: a cost record could no longer be final when written.

So cumulative discounts are **explicitly out of scope**. Owner decision, 2026-08-08: *"no
point supporting that, we can have a separate system for it. This can maintain the raw
prices."*

### What that makes this system, and the naming consequence

**WP-53 is the rate card.** It answers "what did this request cost at list price, under the
prices in effect when it completed?" — a pure function of the request. Anything that adjusts
that figure afterwards (volume discounts, negotiated rebates, credits, committed-spend
agreements) belongs to a separate downstream system, and **the cost records are the interface
to it.** That is a good boundary: it is exactly the line between a stateless per-request
calculation and a stateful periodic reconciliation, and the two have different correctness
requirements.

It has one consequence that is easy to get wrong and expensive to unpick: **do not call the
figure `cost`.** Call it what it is — a *list-price* cost. A field named `cost` on a record
that a discount system will later adjust invites a dashboard, an alert, or an invoice to
treat it as the final amount owed. Naming it `list_cost_nanodollars` (and the access-log
operator `%LLM_LIST_COST%`) makes the downstream system's existence visible at every call
site, and makes a double-count read as obviously wrong rather than plausible.

The same reasoning that keeps `KeyId` separate from `TenantId`, and `input_tokens`
separate from `cached_tokens`: when two numbers can be confused and one of them is money, the type or the
name has to keep them apart.

## An unpriced model must be `None`, never `$0`

This is the same trap WP-48 found in `token_count`, and it is worse here.

If a model has no price entry, its cost is **`None`** — unknown. It must never be recorded as
zero, because **zero is a number a budget subtracts from**: an unpriced model would become a
free, unlimited hole through any dollar cap, and the way you would find out is a bill.

What to *do* about `None` depends on whether anything is relying on the number, and that rule
should be explicit rather than a default someone discovers:

| Situation | Behaviour |
|---|---|
| No dollar budget configured anywhere | Serve. Record cost as absent. It is an observability gap, not an error. |
| A dollar budget applies to this route/tenant, model unpriced | **Reject**, with a distinguishable status and response flag. Serving it makes the budget a lie. |
| Price list fails to load / is malformed | **Config error at load time**, with the dotted path — never fall back to "no prices". |

Note the shape mirrors WP-50's: *authentication fails closed, authorization defaults open*.
Here, **pricing is only as strict as the thing depending on it**. That is a defensible rule
precisely because it is stated, not inferred.

Where the route can be enumerated (an explicit `model:` list), an unpriced model with a
dollar budget configured should be caught at **config load**, not at request time — a
wildcard route (`model: "*"`) cannot be, which is why the runtime rule above still exists.

## Where prices come from

**Increment 1: operator config**, exactly as virtual keys do today. It is honest, needs no
network, and works offline.

### Owner decision, 2026-08-08: config or file, and that is the whole update path

> *"I will keep providing you costs as part of config or file."*

**A runtime publishing API is therefore out of scope for this WP and is not deferred to
WP-50 increment 3 either — it is simply not wanted.** That is a real simplification, and it
has one consequence worth stating plainly: **WP-53 no longer blocks on anything.** It does
not need the control-plane store, the admin endpoints, or admin-surface authentication. It
can be built as soon as the current milestone's gate allows.

A `price_list_file:` pointing at a JSON/YAML document is the expected shape, mirroring
`hmac_secret_file` — a price table is large and machine-generated, and nobody wants it inline
in `llmproxy.yaml`. Like `api_key_file`, it is **read once at startup**, so updating prices
means a config reload; say so in the field's documentation rather than letting an operator
discover that edits are inert.

### Two things this decision does NOT remove

**1. Cost is still recorded at request time, stamped with a version.** This has nothing to do
with how prices arrive. Edit the file, reload, and every already-recorded cost must stay
exactly what it was. Re-pricing on read is wrong whether the new prices came from an API or
from `vim`.

**2. Effective-dating still earns its place, because of fleets.** It looks like ceremony when
one process reads one file. It is not, as soon as there is more than one replica: a config
rollout takes minutes, and during it some replicas have the new file and some have the old.
Without an effective date, the *same request* prices differently depending on which replica
served it, and the difference is invisible. With one, every replica agrees on when the new
prices start regardless of when each got the file.

### The trap this decision creates: a version that lies

A file-supplied list carries an operator-written `version` string. The failure is obvious
once named and easy to miss until it bites: **someone edits the prices and forgets to bump
the version.** Now two different price tables have both claimed to be `2026-08-08.1`, cost
records stamped with that version are no longer reconstructable, and the audit guarantee this
brief is built on is quietly gone — with nothing anywhere reporting a problem.

So the version must be **derived, not trusted**: compute a content hash of the normalised
price entries at load, and make the recorded version `<operator-label>+<short-hash>` (or the
hash alone if no label is given). An operator-meaningful label stays useful for humans, and
the hash makes "same version, different content" unrepresentable. This is cheap — it happens
once at config load — and it is the only mechanism here that survives an operator's mistake
rather than assuming they will not make one.

**Later, if ever: a fetched catalogue.** Provider prices change and nobody wants to hand-maintain
them. But note before anyone builds it: a proxy that auto-fetches pricing and enforces
budgets on the result has made a third party able to change what its customers are charged
and what traffic is refused. That wants pinning, signature or checksum verification, and an
explicit operator promotion step — it is not a background refresh. Deliberately out of scope
here, named so it is not slipped in as a convenience. Note it is the *same* promotion step
the admin path above provides, which is the argument for building that one first.

The seam is the same one ADR-0005 describes for read-mostly data: a `PriceCatalogue` trait,
a snapshot published through `ArcSwap`, the hot path doing a lock-free load and **never**
I/O. Pricing is read-mostly and tolerates seconds of staleness within one effective period —
it is closer to the key set than to a spend counter. **Spend counters are the hard,
read-modify-write half, and they belong to WP-42, not here.**

## Increments

- **1 — the price model + config surface.** Types, nanodollar arithmetic, per-bucket rates,
  effective-dated lists, strict validation with dotted paths, `None` for unpriced. Pure
  library plus dialect surface. No enforcement, no store.
- **2 — cost records.** Compute cost at response end from `LlmTokenUsage`, stamp the price
  list version, expose on `StreamInfo` and in access logs. Makes spend *visible* before it is
  *enforceable*, which is the right order — an operator should be able to see what a budget
  would have done before one rejects traffic.
- **3 — hand off to WP-42.** Dollar budgets, scopes, periods, enforcement. WP-42 owns it and
  should be re-scoped to depend on this WP rather than describing its own cost model.

*(A runtime price-publishing API was briefly increment 3 and was removed by the owner
decision above — prices arrive as config or a file. Recorded rather than deleted so the
absence reads as a decision instead of an oversight.)*

## What this brief does not decide

Multi-currency (everything is USD; a `currency` field with one legal value is a lie about
capability). Per-tenant negotiated rates. Cost-aware *routing* — picking the cheapest
capable backend is WP-44, and it needs this data but is a different feature.
