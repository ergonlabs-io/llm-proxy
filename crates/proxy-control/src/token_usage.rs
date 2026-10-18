//! [`TokenUsage`], the per-bucket token counts of one exchange. It is kept
//! apart from the response scanner in `usage` because the token limiter and the
//! control plane need the type but not the parser.

use proxy_http::LlmTokenUsage;

/// Tokens consumed by one request/response exchange, split into the buckets
/// that are **priced differently** so downstream cost accounting can apply a
/// per-bucket rate.
///
/// Buckets do not overlap, so totals and per-bucket pricing avoid
/// double-counting. `input_tokens` excludes cached tokens: OpenAI cached
/// tokens are subtracted from `prompt_tokens`, while Anthropic input already
/// excludes them.
///
/// Rust note: `Copy` is derived because this is four `u64`s — small enough that
/// copying is cheaper than referencing, so callers needn't think about borrows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TokenUsage {
    /// Standard (non-cached) input tokens, priced at the base input rate.
    /// OpenAI `prompt_tokens` minus its cached portion; Anthropic `input_tokens`.
    pub input_tokens: u64,
    /// Cache-**read** input tokens, served from a prompt cache at a steep
    /// discount. OpenAI `prompt_tokens_details.cached_tokens` (a subset of
    /// `prompt_tokens`); Anthropic `cache_read_input_tokens`.
    pub cached_tokens: u64,
    /// Cache-**write** input tokens, priced at a premium over base input.
    /// Anthropic `cache_creation_input_tokens`; OpenAI has no such billed
    /// bucket, so this stays 0 there.
    pub cache_creation_tokens: u64,
    /// Output/completion tokens (OpenAI `completion_tokens`, Anthropic
    /// `output_tokens`).
    pub output_tokens: u64,
}

impl TokenUsage {
    /// Total token count across all buckets. Sound to sum because the buckets
    /// don't overlap.
    pub fn total(&self) -> u64 {
        // Saturating, not `+`: every one of these four numbers comes straight
        // from a provider's JSON via `as_u64()` with no clamping, so the sum is
        // attacker-/bug-reachable input, not a value we computed. A plain `+`
        // panics on overflow in debug (killing the worker) and wraps in release
        // (logging a billing number nobody computed). `parse_usage_object` in
        // proxy-filters' `usage` module uses `saturating_sub` against these
        // same numbers for the same reason.
        self.input_tokens
            .saturating_add(self.cached_tokens)
            .saturating_add(self.cache_creation_tokens)
            .saturating_add(self.output_tokens)
    }
}

/// Convert a [`TokenUsage`] into the [`LlmTokenUsage`] that `StreamInfo`
/// carries. All four cost buckets cross the boundary intact — dropping the
/// cache buckets would leave anything downstream (billing, the token
/// limiter) unable to compute a correct cost, since the buckets are priced
/// differently.
///
/// Rust note: `From` is the idiomatic "one type converts unambiguously into
/// another" trait; implementing it here (rather than a free function) lets
/// callers write `usage.into()` and is what `stream_info.rs`'s doc comment on
/// `LlmTokenUsage` means by "the usage filter converts at its boundary". It
/// lives beside `TokenUsage` because Rust's orphan rule allows the impl only
/// in the crate that defines one of the two types.
impl From<TokenUsage> for LlmTokenUsage {
    fn from(usage: TokenUsage) -> Self {
        LlmTokenUsage {
            input_tokens: usage.input_tokens,
            cached_tokens: usage.cached_tokens,
            cache_creation_tokens: usage.cache_creation_tokens,
            output_tokens: usage.output_tokens,
        }
    }
}
