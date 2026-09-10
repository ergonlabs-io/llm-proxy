//! Versioned, four-bucket list pricing for LLM requests (WP-53).
//!
//! This is deliberately a rate-card library: it computes an immutable
//! request-time list price but does not enforce a budget.  Money stays in
//! integer nanodollars and an unpriced model is `None`, never a free zero.

use std::time::SystemTime;

use ring::digest::{digest, SHA256};

use crate::usage::TokenUsage;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierBasis {
    InputTokens,
    CachedTokens,
    CacheCreationTokens,
    OutputTokens,
}

impl Default for TierBasis {
    fn default() -> Self {
        Self::InputTokens
    }
}

/// Intentionally has no Default: choosing either option changes money.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierMode {
    WholeRequest,
    Graduated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tier {
    /// Inclusive; `None` is the final open-ended tier.
    pub up_to: Option<u64>,
    pub input_nanodollars_per_token: u64,
    pub cached_input_nanodollars_per_token: u64,
    pub cache_write_nanodollars_per_token: u64,
    pub output_nanodollars_per_token: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceEntry {
    pub provider_type: String,
    pub model: String,
    pub tier_basis: TierBasis,
    pub tier_mode: TierMode,
    pub tiers: Vec<Tier>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceListVersion(String);

impl PriceListVersion {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PriceListVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A list's version combines its optional human label and a content hash, so
/// editing rates while forgetting to bump a label cannot corrupt auditability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceList {
    version: PriceListVersion,
    effective_from: SystemTime,
    entries: Vec<PriceEntry>,
}

impl PriceList {
    pub fn new(label: Option<&str>, effective_from: SystemTime, entries: Vec<PriceEntry>) -> Self {
        let mut canonical: Vec<&PriceEntry> = entries.iter().collect();
        canonical.sort_by(|a, b| {
            (a.provider_type.as_str(), a.model.as_str())
                .cmp(&(b.provider_type.as_str(), b.model.as_str()))
        });
        let mut bytes = Vec::new();
        for e in canonical {
            bytes.extend_from_slice(e.provider_type.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(e.model.as_bytes());
            bytes.push(0);
            bytes.push(e.tier_basis as u8);
            bytes.push(e.tier_mode as u8);
            for t in &e.tiers {
                bytes.extend_from_slice(&t.up_to.unwrap_or(u64::MAX).to_le_bytes());
                bytes.extend_from_slice(&t.input_nanodollars_per_token.to_le_bytes());
                bytes.extend_from_slice(&t.cached_input_nanodollars_per_token.to_le_bytes());
                bytes.extend_from_slice(&t.cache_write_nanodollars_per_token.to_le_bytes());
                bytes.extend_from_slice(&t.output_nanodollars_per_token.to_le_bytes());
            }
            bytes.push(0xff);
        }
        let hash = digest(&SHA256, &bytes).as_ref()[..6]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let version = match label.filter(|label| !label.is_empty()) {
            Some(label) => format!("{label}+{hash}"),
            None => hash,
        };
        Self {
            version: PriceListVersion(version),
            effective_from,
            entries,
        }
    }

    pub fn version(&self) -> &PriceListVersion {
        &self.version
    }
    pub fn effective_from(&self) -> SystemTime {
        self.effective_from
    }
    pub fn lookup(&self, provider_type: &str, model: &str) -> Option<&PriceEntry> {
        self.entries
            .iter()
            .find(|entry| entry.provider_type == provider_type && entry.model == model)
    }

    /// `None` means unknown/unpriced, never a fabricated zero amount.
    pub fn list_cost_nanodollars(
        &self,
        provider_type: &str,
        model: &str,
        usage: &TokenUsage,
    ) -> Option<u64> {
        self.lookup(provider_type, model)
            .map(|entry| list_cost_nanodollars(entry, usage))
    }
}

/// Context length selects a provider's published long-context price band.
/// These three buckets are disjoint representations of prompt/context tokens,
/// so their saturating sum is the only safe selector; output is generated
/// after context selection and must not move a request into a higher band.
fn context_tokens(usage: &TokenUsage) -> u64 {
    usage
        .input_tokens
        .saturating_add(usage.cached_tokens)
        .saturating_add(usage.cache_creation_tokens)
}

fn rate_for_basis(basis: TierBasis, tier: &Tier) -> u64 {
    match basis {
        TierBasis::InputTokens => tier.input_nanodollars_per_token,
        TierBasis::CachedTokens => tier.cached_input_nanodollars_per_token,
        TierBasis::CacheCreationTokens => tier.cache_write_nanodollars_per_token,
        TierBasis::OutputTokens => tier.output_nanodollars_per_token,
    }
}

fn tier_for(tiers: &[Tier], quantity: u64) -> Option<&Tier> {
    tiers
        .iter()
        .find(|tier| tier.up_to.is_none_or(|up_to| quantity <= up_to))
}

fn all_buckets(usage: &TokenUsage, tier: &Tier) -> u64 {
    usage
        .input_tokens
        .saturating_mul(tier.input_nanodollars_per_token)
        .saturating_add(
            usage
                .cached_tokens
                .saturating_mul(tier.cached_input_nanodollars_per_token),
        )
        .saturating_add(
            usage
                .cache_creation_tokens
                .saturating_mul(tier.cache_write_nanodollars_per_token),
        )
        .saturating_add(
            usage
                .output_tokens
                .saturating_mul(tier.output_nanodollars_per_token),
        )
}

/// Compute the four-bucket list price. Tier selection uses total input
/// context (`input + cache-read + cache-write`), not output tokens. `up_to`
/// is inclusive, so exactly 500_000 context tokens remain in a `up_to:
/// 500000` tier. All multiplication and addition saturates because token
/// counts are provider-derived wire values.
pub fn list_cost_nanodollars(entry: &PriceEntry, usage: &TokenUsage) -> u64 {
    let quantity = context_tokens(usage);
    let Some(selected) = tier_for(&entry.tiers, quantity) else {
        return 0;
    };
    if entry.tier_mode == TierMode::WholeRequest {
        return all_buckets(usage, selected);
    }

    let mut lower = 0u64;
    let mut remaining = quantity;
    let mut basis_cost = 0u64;
    for tier in &entry.tiers {
        if remaining == 0 {
            break;
        }
        let upper = tier.up_to.unwrap_or(u64::MAX);
        let in_band = remaining.min(upper.saturating_sub(lower));
        basis_cost = basis_cost
            .saturating_add(in_band.saturating_mul(rate_for_basis(entry.tier_basis, tier)));
        remaining = remaining.saturating_sub(in_band);
        lower = upper;
    }
    let non_basis = match entry.tier_basis {
        TierBasis::InputTokens => all_buckets(
            &TokenUsage {
                input_tokens: 0,
                ..*usage
            },
            selected,
        ),
        TierBasis::CachedTokens => all_buckets(
            &TokenUsage {
                cached_tokens: 0,
                ..*usage
            },
            selected,
        ),
        TierBasis::CacheCreationTokens => all_buckets(
            &TokenUsage {
                cache_creation_tokens: 0,
                ..*usage
            },
            selected,
        ),
        TierBasis::OutputTokens => all_buckets(
            &TokenUsage {
                output_tokens: 0,
                ..*usage
            },
            selected,
        ),
    };
    basis_cost.saturating_add(non_basis)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tier(up_to: Option<u64>, input: u64, cached: u64, write: u64, output: u64) -> Tier {
        Tier {
            up_to,
            input_nanodollars_per_token: input,
            cached_input_nanodollars_per_token: cached,
            cache_write_nanodollars_per_token: write,
            output_nanodollars_per_token: output,
        }
    }
    fn entry(mode: TierMode, tiers: Vec<Tier>) -> PriceEntry {
        PriceEntry {
            provider_type: "openai".into(),
            model: "gpt-5".into(),
            tier_basis: TierBasis::InputTokens,
            tier_mode: mode,
            tiers,
        }
    }
    fn usage(input: u64, cached: u64, write: u64, output: u64) -> TokenUsage {
        TokenUsage {
            input_tokens: input,
            cached_tokens: cached,
            cache_creation_tokens: write,
            output_tokens: output,
        }
    }

    #[test]
    fn prices_all_four_disjoint_buckets() {
        let price = list_cost_nanodollars(
            &entry(
                TierMode::WholeRequest,
                vec![tier(None, 1000, 100, 5000, 8000)],
            ),
            &usage(100, 900, 50, 200),
        );
        assert_eq!(price, 100 * 1000 + 900 * 100 + 50 * 5000 + 200 * 8000);
    }
    #[test]
    fn arithmetic_saturates() {
        let price = list_cost_nanodollars(
            &entry(
                TierMode::WholeRequest,
                vec![tier(None, u64::MAX, u64::MAX, u64::MAX, u64::MAX)],
            ),
            &usage(u64::MAX, u64::MAX, u64::MAX, u64::MAX),
        );
        assert_eq!(price, u64::MAX);
    }
    #[test]
    fn tier_modes_differ_on_threshold() {
        let tiers = vec![
            tier(Some(1000), 1000, 100, 1200, 5000),
            tier(None, 2000, 200, 2400, 10000),
        ];
        assert_eq!(
            list_cost_nanodollars(
                &entry(TierMode::WholeRequest, tiers.clone()),
                &usage(1500, 0, 0, 0)
            ),
            3_000_000
        );
        assert_eq!(
            list_cost_nanodollars(&entry(TierMode::Graduated, tiers), &usage(1500, 0, 0, 0)),
            2_000_000
        );
    }
    #[test]
    fn context_length_selects_the_band_inclusively_across_cache_buckets() {
        let entry = entry(
            TierMode::WholeRequest,
            vec![tier(Some(500_000), 1, 1, 1, 1), tier(None, 2, 2, 2, 2)],
        );
        // Context includes cached input: output must not influence selection.
        assert_eq!(
            list_cost_nanodollars(&entry, &usage(100_000, 400_000, 0, 10)),
            500_010
        );
        assert_eq!(
            list_cost_nanodollars(&entry, &usage(100_000, 400_001, 0, 10)),
            1_000_022
        );
    }
    #[test]
    fn unpriced_is_none_and_version_is_content_addressed() {
        let first = PriceList::new(
            Some("v1"),
            SystemTime::UNIX_EPOCH,
            vec![entry(TierMode::WholeRequest, vec![tier(None, 1, 2, 3, 4)])],
        );
        assert_eq!(
            first.list_cost_nanodollars("openai", "missing", &usage(1, 2, 3, 4)),
            None
        );
        let changed = PriceList::new(
            Some("v1"),
            SystemTime::UNIX_EPOCH,
            vec![entry(TierMode::WholeRequest, vec![tier(None, 2, 2, 3, 4)])],
        );
        assert_ne!(first.version(), changed.version());
    }
}
