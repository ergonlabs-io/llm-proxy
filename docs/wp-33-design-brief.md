# WP-33 design brief — make token metering live, per route

**For:** the repo owner (you build, I review)
**Date:** 2026-07-30
**Priority:** P0 · **Milestone:** v0.1.0 · **Depends on:** ADR-0004 step 4 increment 2 (landed, `18ab73f`)

---

## Start here: much of WP-33 is already built

Before writing anything, know what exists, or you'll rebuild it:

| Piece | State | Where |
|---|---|---|
| Token extractor (3 dialects, streaming + not, 4 cost buckets) | **done** | `crates/proxy-filters/src/usage.rs` |
| The encode filter that feeds it live response bytes | **done**, 23 tests | `crates/proxy-filters/src/usage_filter.rs` |
| Writes `StreamInfo::llm` (usage, TTFB, max inter-chunk, chunk count) | **done** | `usage_filter.rs::finalize` |
| Registered in the filter registry | **done** | `crates/proxy-core/src/listener.rs:72` |
| `%LLM_INPUT_TOKENS%` … `%LLM_TTFT%` access-log operators | **done** | `crates/proxy-observability/src/access_log.rs:56-66, 289+` |

## The actual gap

**`crates/proxy-simple-config/src/lower.rs:455` emits exactly one HTTP filter — the router.**

```rust
"http_filters": [ {
    "name": "envoy.filters.http.router",
    "typed_config": { "@type": ROUTER_TYPE_URL }
} ]
```

So on any proxy configured with the `llmproxy` dialect — which is the config people actually use — the usage filter is never in the chain, and none of the machinery above runs. The extractor is fully tested and completely unreachable. That is the ⚑ "built-but-unwired" flag on the board, and closing it is most of WP-33.

**The second gap is why this needed step 4 first.** `UsageFilterInstanceFactory` holds a single `dialect` fixed at listener build time (`usage_filter.rs:119`). But one listener serves both providers — `routes: [{model: gpt-*, provider: openai}, {model: claude-*, provider: anthropic}]`. A per-listener dialect is wrong for every route that doesn't match it, and it would silently produce **wrong token counts**, not missing ones, because the Anthropic scanner fed OpenAI SSE just finds nothing and reports `None`… but the reverse (OpenAI parser on Anthropic JSON) can partially match. The dialect has to come from the **route**.

That's what `typed_per_filter_config` now makes possible.

---

## Design

### 1. Emit the filter from the dialect (`proxy-simple-config/src/lower.rs`)

In the `http_filters` array at `lower.rs:455`, put the usage filter **before** the router:

```rust
"http_filters": [
    {
        "name": "llmproxy.usage",
        "typed_config": {
            "@type": "type.llmproxy.dev/envoy.config.core.v3.DataSource",
            "inline_string": <default dialect>
        }
    },
    { "name": "envoy.filters.http.router", "typed_config": { "@type": ROUTER_TYPE_URL } }
]
```

The name `llmproxy.usage` is the key that per-route overrides match against — it must be identical in both places or the build fails (correctly: increment 2 errors on an override naming a filter absent from the chain).

The type URL is `usage_filter::TYPE_URL`. Import it rather than retyping the string. Note the `DataSource`-reuse hack is deliberate and documented in `usage_filter.rs`'s module doc — don't "fix" it here; it becomes a real vendored proto when the filter grows a second config field.

**Default dialect:** the listener-level value is only used when a route carries no override. Since you'll attach an override to *every* route (below), it's effectively unreachable — requests matching no route get the dialect's `direct_response` 404 and never produce an upstream body. Use the first route's provider dialect and leave a comment saying exactly that. Do **not** invent an `Unknown`/`None` dialect variant to express "no default"; that widens `Dialect` for no gain.

### 2. Attach a per-route override in `lower_route` (`lower.rs:330`)

`lower_route` already resolves `rule.provider.provider` → `&Provider` and calls `provider.effective_type(name)` (see `auth_header`, `lower.rs:300`). Map that to the dialect string and attach:

```rust
r["typed_per_filter_config"] = json!({
    "llmproxy.usage": {
        "@type": "type.llmproxy.dev/envoy.config.core.v3.DataSource",
        "inline_string": dialect_for(provider.effective_type(provider_name)),
    }
});
```

`ProviderType::Anthropic` → `"anthropic"`; everything else → `"openai"` (openai-compatible upstreams — vLLM, Ollama, TGI — speak the OpenAI response shape, which is exactly why `auth_header` uses the same `_ =>` fallback).

**Do not** wrap it in `envoy.config.route.v3.FilterConfig` unless you need `is_optional`. A bare `Any` is the simpler form and both are supported (increment 1 unwraps the wrapper when present).

### 3. Teach the filter to read its per-route dialect (`usage_filter.rs`)

Three changes:

**a. A `PerRouteConfig` type.** Note the trait now requires `as_any` (added in increment 2 — a trait object can't be downcast without it):

```rust
struct UsagePerRoute { dialect: Dialect }

impl PerRouteConfig for UsagePerRoute {
    fn as_any(&self) -> &dyn std::any::Any { self }
}
```

**b. `UsageFilterFactory::parse_per_route`.** Reuse `parse_config` — the per-route message is the same `DataSource` shape:

```rust
fn parse_per_route(&self, config: &DynamicMessage)
    -> Result<Arc<dyn PerRouteConfig>, ConfigError>
{
    Ok(Arc::new(UsagePerRoute { dialect: parse_config(config)? }))
}
```

An invalid dialect here must stay an `Err`. Increment 2 propagates every non-`Unimplemented` error even when `is_optional` is set, precisely so a typo'd override can't be silently dropped — don't undo that by swallowing it.

**c. Resolve in `encode_headers`, before `classify_body`.** This is the only correct place: `classify_body` constructs `SseUsageScanner::new(dialect)`, so the dialect must be final before it runs.

```rust
fn encode_headers(&mut self, cb: &mut dyn EncoderCallbacks, headers: &mut ResponseHeaders, end_stream: bool) -> FilterHeadersStatus {
    self.headers_at = Some(Instant::now());

    // Per-route override wins over the listener-level default: one listener
    // serves several providers, and the response shape follows the ROUTE's
    // provider, not the listener's.
    if let Some(cfg) = cb.per_route_config() {
        if let Some(per_route) = cfg.as_any().downcast_ref::<UsagePerRoute>() {
            self.dialect = per_route.dialect;
        }
    }

    self.mode = classify_body(&headers.headers, self.dialect);
    ...
}
```

---

## Traps — please read these

**1. `EncoderCallbacks::per_route_config` has a default body returning `None`.** I flagged this as a wart when reviewing increment 2 and it will bite you here specifically: `usage_filter.rs`'s `TestCallbacks` double (line 366) does **not** implement it, so every existing test will silently take the `None` path and your per-route logic will look like it works while never executing. **Override it in `TestCallbacks`** to return a configurable value, and write at least one test that fails if the override is ignored.

If you'd rather remove the default from the trait and fix the three or four implementors, that's the better fix and I'd support it — it converts a silent wrong answer into a compile error. Your call; say which you picked.

**2. Never buffer.** `usage_filter.rs`'s module doc and the `// Rust note:` at `encode_data`'s `FilterDataStatus::Continue` explain why. Your change touches `encode_headers` only — if you find yourself returning anything but `Continue` from `encode_data`, or calling `add_encoded_data`, stop. The `TestCallbacks` double `unimplemented!()`s those methods on purpose, so a buffering regression panics rather than passes.

**3. `per_route_config()` resolves the route (S2.8).** It goes through the same cache as `route()`, so it is subject to `clear_route_cache()`. Not an issue for an encode filter today — routing is settled long before the response — but don't cache the resolved dialect anywhere longer-lived than the stream.

**4. `None` must stay `None`.** `finalize` deliberately writes `None` rather than `Some(0,0)` when a response reported no usage (`usage_filter.rs:251`). This number feeds billing; a wrong zero is worse than an honest unknown. Preserve that.

**5. The dialect currently rejects `limits:` and `fallbacks:`.** Leave both rejections alone — they're WP-34 and WP-35. This change must not make either look supported.

---

## Acceptance criteria

**Unit (`usage_filter.rs`):**
1. A route-level override changes the dialect the filter uses — Anthropic-shaped response body on a route configured `anthropic`, with the instance default set to `openai`, still extracts correct usage.
2. With no per-route override, the listener-level default is used (existing behavior preserved).
3. An invalid per-route dialect is a build error, and `is_optional: true` does **not** swallow it.

**Dialect (`proxy-simple-config/tests/dialect.rs`):**
4. A two-provider config lowers to an HCM whose `http_filters` contains `llmproxy.usage` before the router.
5. The `gpt-*` route carries `typed_per_filter_config["llmproxy.usage"].inline_string == "openai"`; the `claude-*` route, `"anthropic"`.
6. An `openai-compatible` provider (e.g. a `base_url`-only `local-vllm`) gets `"openai"`.

**End-to-end — this is the one that proves it:**
7. Against the mock upstreams, a request routed to the OpenAI provider and one routed to the Anthropic provider each produce an access-log line with correct `%LLM_INPUT_TOKENS%` / `%LLM_OUTPUT_TOKENS%` / `%LLM_TTFT%`, **from the same running proxy with one config**. That is the whole point — per-listener dialect cannot pass this test, so it's the test that proves the per-route path is real.

A shared e2e harness for exactly this is being built now in `testing/diffrig/src/harness.rs` + `tests/mock_e2e.rs`. Build criterion 7 on top of it rather than hand-rolling a proxy spawn.

> **Update (2026-07-31) — criterion 7's prerequisites have changed.**
>
> When this brief was written, criterion 7 was blocked by two gaps, only one
> of which was WP-33. The black-box Go QA suite found the other on its first
> run: **the `llmproxy` dialect never wired `observability.access_logs` into
> the config it generated at all**, so there was no log destination for a
> wired-up usage filter to write to. `proxy-simple-config/src/lower.rs` emitted
> only a stale "not emitted yet (WP-24)" warning. That is now **fixed** (commit
> *"Emit access logs from the llmproxy dialect"*), along with a second
> access-log defect the same run exposed: `%REQ(:METHOD)%` and
> `%REQ(:AUTHORITY)%` always rendered `-`, in Envoy mode too.
>
> **WP-33 is now the sole remaining blocker on criterion 7.** `QA-1`
> (`testing/qa/scenarios/qa1_per_route_tokens_test.go`) already asserts
> everything criterion 7 needs *except* the token values, and skips loudly
> naming WP-33 for those. So there is a ready-made check on the work: when the
> usage filter reaches the dialect's generated `http_filters`, QA-1 stops
> skipping and starts asserting `111/222` and `444/555` per route — from one
> proxy, one config, exactly as criterion 7 demands.
>
> Practical consequence: build criterion 7 against QA-1 rather than writing a
> new e2e test. If QA-1 goes green, criterion 7 is met. The dialect's JSON log
> format has no `model` field yet, so QA-1 currently correlates lines by
> request path; if your change adds a model field, tighten QA-1 to correlate
> on it (that is a case-maintenance edit, allowed under SCENARIOS.md rule 5).

**Definition of done:** `make ci` green; report before/after test counts and reconcile any change. Format with `rustfmt --edition 2021 <explicit paths>` — never `cargo fmt --all` or `cargo fmt -p`.

---

## What this does not include

Token *rate limiting* (WP-34's remainder) and model routing / fallback (WP-35). This brief is only "the numbers are correct, live, and per-route." Once criterion 7 passes, the extractor stops being dead code and WP-34 has something real to meter against.
