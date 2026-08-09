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
observability), the **computed cost**, and **the price-list version that computed it**. The
cost is authoritative for budgets; the tokens are evidence. A later price change moves
nothing already recorded.

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

**Later: a fetched catalogue.** Provider prices change and nobody wants to hand-maintain
them. But note before anyone builds it: a proxy that auto-fetches pricing and enforces
budgets on the result has made a third party able to change what its customers are charged
and what traffic is refused. That wants pinning, signature or checksum verification, and an
explicit operator promotion step — it is not a background refresh. Deliberately out of scope
here, named so it is not slipped in as a convenience.

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

## What this brief does not decide

Multi-currency (everything is USD; a `currency` field with one legal value is a lie about
capability). Per-tenant negotiated rates. Cost-aware *routing* — picking the cheapest
capable backend is WP-44, and it needs this data but is a different feature.
