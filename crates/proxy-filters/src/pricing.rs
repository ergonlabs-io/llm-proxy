//! Versioned, four-bucket list pricing for LLM requests.
//!
//! This is deliberately a rate-card library: it computes an immutable
//! request-time list price but does not enforce a budget.  Money stays in
//! integer nanodollars and an unpriced model is `None`, never a free zero.

use std::collections::BTreeMap;
use std::time::SystemTime;

use ring::digest::{digest, SHA256};

use crate::usage::TokenUsage;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TierBasis {
    #[default]
    InputTokens,
    CachedTokens,
    CacheCreationTokens,
    OutputTokens,
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
    /// Unknown cache rates only prevent pricing when that bucket is used.
    pub cached_input_unpriced: bool,
    pub cache_write_unpriced: bool,
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
///
/// The hash covers everything that decides what a request costs: the price
/// entries AND the map from a dialled cluster to its provider type, because
/// that map picks which entry applies. Two replicas with the same prices and
/// different maps would otherwise report one version and charge differently.
/// `effective_from` is left out on purpose: it never selects a price (a card
/// applies from the moment it is installed, and a future date is rejected), so
/// re-dating an identical list is not a change in what anything costs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceList {
    label: Option<String>,
    version: PriceListVersion,
    effective_from: SystemTime,
    entries: Vec<PriceEntry>,
    /// Dialled cluster name -> configured provider type. A route can point at
    /// an aggregate or fallback, so this is never inferred from the dialect.
    cluster_providers: BTreeMap<String, String>,
}

impl PriceList {
    pub fn new(
        label: Option<&str>,
        effective_from: SystemTime,
        entries: Vec<PriceEntry>,
        cluster_providers: BTreeMap<String, String>,
    ) -> Self {
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
            bytes.push(u8::from(e.cached_input_unpriced));
            bytes.push(u8::from(e.cache_write_unpriced));
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
        // The provider map, after the entries. 0xfd and 0xfe are never part of
        // valid UTF-8, so no cluster or provider name can imitate a separator.
        // A BTreeMap iterates in key order, so the bytes do not depend on the
        // order the operator wrote the map in.
        bytes.push(0xfe);
        for (cluster, provider) in &cluster_providers {
            bytes.extend_from_slice(cluster.as_bytes());
            bytes.push(0xfd);
            bytes.extend_from_slice(provider.as_bytes());
            bytes.push(0xfd);
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
            label: label.map(str::to_owned),
            version: PriceListVersion(version),
            effective_from,
            entries,
            cluster_providers,
        }
    }

    pub fn cluster_providers(&self) -> &BTreeMap<String, String> {
        &self.cluster_providers
    }

    /// The provider type the rate card prices `cluster` as, if it names one.
    pub fn provider_for(&self, cluster: &str) -> Option<&str> {
        self.cluster_providers.get(cluster).map(String::as_str)
    }

    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    pub fn version(&self) -> &PriceListVersion {
        &self.version
    }
    pub fn effective_from(&self) -> SystemTime {
        self.effective_from
    }
    pub fn entries(&self) -> &[PriceEntry] {
        &self.entries
    }
    pub fn lookup(&self, provider_type: &str, model: &str) -> Option<&PriceEntry> {
        self.entries
            .iter()
            .find(|entry| entry.provider_type == provider_type && entry.model == model)
    }

    /// The model to price a request at, and whether that is the served model.
    ///
    /// `base` is the model the proxy sent (selected, else requested). The
    /// provider's reported `served` model replaces it only when it differs and
    /// this card prices it for the dialled provider type with `usage`; a served
    /// model with no card (a dated snapshot) keeps `base`, so the request is
    /// never made unpriced by a model name the card lacks. The usage filter and
    /// the spend filter both call this so a charge and the logged cost agree.
    pub fn model_to_price<'a>(
        &self,
        cluster: &str,
        base: &'a str,
        served: Option<&'a str>,
        usage: &TokenUsage,
    ) -> (&'a str, bool) {
        if let (Some(served), Some(provider)) = (served, self.provider_for(cluster)) {
            if served != base
                && self
                    .list_cost_nanodollars(provider, served, usage)
                    .is_some()
            {
                return (served, true);
            }
        }
        (base, false)
    }

    /// As [`Self::list_cost_nanodollars`], for the cluster a request actually
    /// dialled. `None` also covers a cluster the card's map does not name.
    pub fn list_cost_for_cluster(
        &self,
        cluster: &str,
        model: &str,
        usage: &TokenUsage,
    ) -> Option<u64> {
        self.list_cost_nanodollars(self.provider_for(cluster)?, model, usage)
    }

    /// `None` means unknown/unpriced, never a fabricated zero amount.
    pub fn list_cost_nanodollars(
        &self,
        provider_type: &str,
        model: &str,
        usage: &TokenUsage,
    ) -> Option<u64> {
        self.lookup(provider_type, model)
            .filter(|entry| {
                !(entry.cached_input_unpriced && usage.cached_tokens > 0
                    || entry.cache_write_unpriced && usage.cache_creation_tokens > 0)
            })
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
fn list_cost_nanodollars(entry: &PriceEntry, usage: &TokenUsage) -> u64 {
    let quantity = context_tokens(usage);
    let Some(selected) = tier_for(&entry.tiers, quantity) else {
        return 0;
    };
    if entry.tier_mode == TierMode::WholeRequest {
        return all_buckets(usage, selected);
    }

    // Graduated: the context is laid out in prompt order and cut into bands
    // like tax brackets. Providers cache prefixes, so cache-read tokens come
    // first, then cache-write tokens, then the uncached input. Each token costs
    // its own bucket's rate in the band its position falls in, so every token
    // is priced exactly once. Output is not part of the context; it is priced
    // at the band the whole context selected.
    type Rate = fn(&Tier) -> u64;
    let buckets: [(u64, Rate); 3] = [
        (usage.cached_tokens, |t| {
            t.cached_input_nanodollars_per_token
        }),
        (usage.cache_creation_tokens, |t| {
            t.cache_write_nanodollars_per_token
        }),
        (usage.input_tokens, |t| t.input_nanodollars_per_token),
    ];
    let mut cost = usage
        .output_tokens
        .saturating_mul(selected.output_nanodollars_per_token);
    let mut position = 0u64;
    for (tokens, rate) in buckets {
        let end = position.saturating_add(tokens);
        let mut band_start = 0u64;
        for tier in &entry.tiers {
            let band_end = tier.up_to.unwrap_or(u64::MAX);
            let overlap = end.min(band_end).saturating_sub(position.max(band_start));
            cost = cost.saturating_add(overlap.saturating_mul(rate(tier)));
            band_start = band_end;
        }
        position = end;
    }
    cost
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
            cached_input_unpriced: false,
            cache_write_unpriced: false,
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
    fn two_bands() -> Vec<Tier> {
        vec![
            tier(Some(1000), 1000, 100, 1200, 5000),
            tier(None, 2000, 200, 2400, 10000),
        ]
    }

    /// Cache-read fills the first 800 context tokens, input the next 500 (200
    /// in band one, 300 in band two), and output follows the band the 1300
    /// context tokens selected. Priced once: the old code charged the cache
    /// tokens again at the cache rate on top of slicing them at the input rate.
    #[test]
    fn graduated_prices_every_token_once_in_prompt_order() {
        let entry = entry(TierMode::Graduated, two_bands());
        assert_eq!(
            list_cost_nanodollars(&entry, &usage(500, 800, 0, 10)),
            800 * 100 + 200 * 1000 + 300 * 2000 + 10 * 10000
        );
        assert_eq!(
            list_cost_nanodollars(&entry, &usage(500, 800, 0, 10)),
            980_000
        );
    }

    #[test]
    fn graduated_crosses_a_band_inside_each_bucket() {
        let entry = entry(TierMode::Graduated, two_bands());
        // cache-read 1500: 1000 at band one, 500 at band two.
        assert_eq!(
            list_cost_nanodollars(&entry, &usage(0, 1500, 0, 0)),
            1000 * 100 + 500 * 200
        );
        // cache-write starts at 600: 400 in band one, 300 in band two.
        assert_eq!(
            list_cost_nanodollars(&entry, &usage(0, 600, 700, 0)),
            600 * 100 + 400 * 1200 + 300 * 2400
        );
        // input starts at 900 + 50: 50 in band one, 250 in band two; output
        // at the selected band two.
        assert_eq!(
            list_cost_nanodollars(&entry, &usage(300, 900, 50, 4)),
            900 * 100 + 50 * 1200 + 50 * 1000 + 250 * 2000 + 4 * 10000
        );
    }

    #[test]
    fn graduated_with_one_band_matches_whole_request() {
        let tiers = vec![tier(None, 7, 3, 9, 11)];
        let u = usage(40, 30, 20, 10);
        assert_eq!(
            list_cost_nanodollars(&entry(TierMode::Graduated, tiers.clone()), &u),
            list_cost_nanodollars(&entry(TierMode::WholeRequest, tiers), &u)
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
    fn unknown_cache_rates_never_become_free_cache_usage() {
        let mut model = entry(TierMode::WholeRequest, vec![tier(None, 150, 0, 0, 600)]);
        model.cached_input_unpriced = true;
        model.cache_write_unpriced = true;
        let list = PriceList::new(
            Some("test"),
            SystemTime::UNIX_EPOCH,
            vec![model.clone()],
            BTreeMap::new(),
        );
        assert_eq!(
            list.list_cost_nanodollars("openai", "gpt-5", &usage(2, 0, 0, 3)),
            Some(2100)
        );
        assert_eq!(
            list.list_cost_nanodollars("openai", "gpt-5", &usage(2, 1, 0, 3)),
            None
        );
        assert_eq!(
            list.list_cost_nanodollars("openai", "gpt-5", &usage(2, 0, 1, 3)),
            None
        );
        model.cached_input_unpriced = false;
        model.cache_write_unpriced = false;
        let free_cache = PriceList::new(
            Some("test"),
            SystemTime::UNIX_EPOCH,
            vec![model],
            BTreeMap::new(),
        );
        assert_ne!(list.version(), free_cache.version());
        assert_eq!(
            free_cache.list_cost_nanodollars("openai", "gpt-5", &usage(2, 1, 0, 3)),
            Some(2100)
        );
    }

    #[test]
    fn unpriced_is_none_and_version_is_content_addressed() {
        let first = PriceList::new(
            Some("v1"),
            SystemTime::UNIX_EPOCH,
            vec![entry(TierMode::WholeRequest, vec![tier(None, 1, 2, 3, 4)])],
            BTreeMap::new(),
        );
        assert_eq!(
            first.list_cost_nanodollars("openai", "missing", &usage(1, 2, 3, 4)),
            None
        );
        let changed = PriceList::new(
            Some("v1"),
            SystemTime::UNIX_EPOCH,
            vec![entry(TierMode::WholeRequest, vec![tier(None, 2, 2, 3, 4)])],
            BTreeMap::new(),
        );
        assert_ne!(first.version(), changed.version());
    }

    fn providers(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(cluster, provider)| (cluster.to_string(), provider.to_string()))
            .collect()
    }

    fn list_with(pairs: &[(&str, &str)]) -> PriceList {
        PriceList::new(
            Some("v1"),
            SystemTime::UNIX_EPOCH,
            vec![entry(TierMode::WholeRequest, vec![tier(None, 1, 2, 3, 4)])],
            providers(pairs),
        )
    }

    /// Same prices, different cluster-to-provider map: the map decides which
    /// entry prices a request, so the version must name it.
    #[test]
    fn the_version_changes_when_only_the_provider_map_changes() {
        let base = list_with(&[("provider:a", "openai")]);
        assert_ne!(
            base.version(),
            list_with(&[("provider:a", "anthropic")]).version(),
            "a different provider type for the same cluster"
        );
        assert_ne!(
            base.version(),
            list_with(&[("provider:a", "openai"), ("provider:b", "openai")]).version(),
            "an extra cluster"
        );
        assert_ne!(
            base.version(),
            list_with(&[("provider:b", "openai")]).version(),
            "a renamed cluster"
        );
        assert_eq!(
            list_with(&[("a", "x"), ("b", "y")]).version(),
            list_with(&[("b", "y"), ("a", "x")]).version(),
            "the order the map was written in is not content"
        );
        assert_ne!(
            list_with(&[("ab", "c")]).version(),
            list_with(&[("a", "bc")]).version(),
            "a name boundary moved"
        );
    }

    #[test]
    fn a_cluster_the_map_does_not_name_is_unpriced() {
        let list = list_with(&[("provider:a", "openai")]);
        let u = usage(1, 0, 0, 1);
        assert_eq!(
            list.list_cost_for_cluster("provider:a", "gpt-5", &u),
            Some(5)
        );
        assert_eq!(list.list_cost_for_cluster("provider:z", "gpt-5", &u), None);
    }
}
