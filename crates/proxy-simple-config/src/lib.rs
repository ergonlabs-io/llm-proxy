//! The simple LLM-native config dialect (WP-38).
//!
//! **Normative schema: `schema/llmproxy-v0.schema.json`** — the single source of
//! truth for the dialect. User docs, editor autocomplete, and the validator are
//! all generated from that file; this crate implements it, never extends it.
//!
//! Architecture: this is a FRONT-END, not a parallel config system. The dialect
//! lowers to standard Envoy resources (providers -> clusters + TLS contexts,
//! routes -> a route table on one listener/HCM, limits -> Lane H filters), which
//! then flow through the identical `proxy-config` validation -> IR pipeline as
//! Envoy bootstrap mode. `llm-proxy config translate` prints the lowered Envoy
//! bootstrap. Dialect rule: a capability must exist in the Envoy-mode surface
//! before the dialect may expose it.
//!
//! LLM-tuned defaults live here (idle-based timeouts, streaming flush-through,
//! never-retry-after-first-byte); Envoy bootstrap mode keeps Envoy's defaults
//! for parity.
