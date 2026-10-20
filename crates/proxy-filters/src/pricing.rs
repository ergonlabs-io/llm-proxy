//! Computes immutable request prices without enforcing budgets. Money uses
//! integer nanodollars; an unpriced request is `None`, not zero.
//!
//! An entry declares its basis (ADR-0010 decision 3): `tokens` prices the
//! token buckets, `images` the images meter, `characters` the input
//! characters, and `audio_seconds` the audio duration. An entry prices only
//! the meters of its basis, so one request is never charged twice for the
//! same work.

use std::collections::BTreeMap;
use std::time::SystemTime;

use proxy_http::{LlmTokenUsage, LlmUsage, PriceBasis};
use ring::digest::{digest, SHA256};

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
    /// Modality rates. When one is set, the tokens of that modality are split
    /// out of their text bucket and charged at it; when it is not, they stay
    /// at the text rate, which is the charge before modality rates existed.
    pub image_input_nanodollars_per_token: Option<u64>,
    pub image_output_nanodollars_per_token: Option<u64>,
    pub audio_input_nanodollars_per_token: Option<u64>,
    pub audio_output_nanodollars_per_token: Option<u64>,
}

impl Tier {
    fn has_modality_rate(&self) -> bool {
        self.image_input_nanodollars_per_token.is_some()
            || self.image_output_nanodollars_per_token.is_some()
            || self.audio_input_nanodollars_per_token.is_some()
            || self.audio_output_nanodollars_per_token.is_some()
    }
}

/// One per-image price row. A row names the attributes it requires; a
/// request matches it when every named attribute equals the observed one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImagePrice {
    pub size: Option<String>,
    pub quality: Option<String>,
    pub nanodollars_per_image: u64,
}

impl ImagePrice {
    fn specificity(&self) -> u8 {
        u8::from(self.size.is_some()) + u8::from(self.quality.is_some())
    }

    fn matches(&self, size: Option<&str>, quality: Option<&str>) -> bool {
        self.size.as_deref().is_none_or(|want| size == Some(want))
            && self
                .quality
                .as_deref()
                .is_none_or(|want| quality == Some(want))
    }
}

/// A priced request: the amount, the basis that priced it, and whether
/// modality tokens fell back to their text rate (ADR-0010 decision 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Priced {
    pub nanodollars: u64,
    pub basis: PriceBasis,
    /// Image or audio tokens were reported and the entry has no rate for that
    /// modality, so they were charged at the text rate. Never less than the
    /// charge before modality rates, but under the provider's price.
    pub underpriced_modality: bool,
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
    /// Empty unless `basis` is `tokens`.
    pub tiers: Vec<Tier>,
    pub basis: PriceBasis,
    /// Empty unless `basis` is `images`.
    pub image_prices: Vec<ImagePrice>,
    /// Set exactly when `basis` is `characters`.
    pub nanodollars_per_character: Option<u64>,
    /// Set exactly when `basis` is `audio_seconds`. Applied to milliseconds,
    /// rounded up to a whole nanodollar.
    pub nanodollars_per_second: Option<u64>,
}

impl PriceEntry {
    /// Whether any field added by ADR-0010 holds a value other than its
    /// default. An entry that uses none hashes and stores exactly as before.
    pub fn uses_media_fields(&self) -> bool {
        self.basis != PriceBasis::Tokens
            || !self.image_prices.is_empty()
            || self.nanodollars_per_character.is_some()
            || self.nanodollars_per_second.is_some()
            || self.tiers.iter().any(Tier::has_modality_rate)
    }
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
            // ADR-0010 fields, only when one differs from its default, so a
            // card that uses none keeps its version across the upgrade. 0xfc
            // follows the 0xff/0xfe/0xfd scheme; strings are length-prefixed.
            if e.uses_media_fields() {
                bytes.push(0xfc);
                bytes.push(e.basis as u8);
                for t in &e.tiers {
                    for rate in [
                        t.image_input_nanodollars_per_token,
                        t.image_output_nanodollars_per_token,
                        t.audio_input_nanodollars_per_token,
                        t.audio_output_nanodollars_per_token,
                    ] {
                        push_option_u64(&mut bytes, rate);
                    }
                }
                for row in &e.image_prices {
                    push_option_str(&mut bytes, row.size.as_deref());
                    push_option_str(&mut bytes, row.quality.as_deref());
                    bytes.extend_from_slice(&row.nanodollars_per_image.to_le_bytes());
                }
                // Only the bases that have them, so an image card keeps the
                // version it had before these rates existed.
                if e.nanodollars_per_character.is_some() || e.nanodollars_per_second.is_some() {
                    push_option_u64(&mut bytes, e.nanodollars_per_character);
                    push_option_u64(&mut bytes, e.nanodollars_per_second);
                }
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

    /// Whether any entry uses a field added by ADR-0010. A stored card that
    /// does is written at rate-card schema version 2, so an older replica
    /// skips it instead of misreading it.
    pub fn uses_media_fields(&self) -> bool {
        self.entries.iter().any(PriceEntry::uses_media_fields)
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
        usage: &LlmUsage,
    ) -> (&'a str, bool) {
        if let (Some(served), Some(provider)) = (served, self.provider_for(cluster)) {
            if served != base && self.price(provider, served, usage).is_some() {
                return (served, true);
            }
        }
        (base, false)
    }

    /// As [`Self::price`], for the cluster a request actually dialled. `None`
    /// also covers a cluster the card's map does not name.
    pub fn price_for_cluster(
        &self,
        cluster: &str,
        model: &str,
        usage: &LlmUsage,
    ) -> Option<Priced> {
        self.price(self.provider_for(cluster)?, model, usage)
    }

    /// As [`Self::list_cost_nanodollars`], for the cluster a request actually
    /// dialled.
    pub fn list_cost_for_cluster(
        &self,
        cluster: &str,
        model: &str,
        usage: &LlmUsage,
    ) -> Option<u64> {
        self.price_for_cluster(cluster, model, usage)
            .map(|priced| priced.nanodollars)
    }

    /// `None` means unknown/unpriced, never a fabricated zero amount.
    pub fn list_cost_nanodollars(
        &self,
        provider_type: &str,
        model: &str,
        usage: &LlmUsage,
    ) -> Option<u64> {
        self.price(provider_type, model, usage)
            .map(|priced| priced.nanodollars)
    }

    /// Price `usage` against the one entry for `(provider_type, model)`.
    ///
    /// `None` when there is no entry, or the request observed none of the
    /// entry's basis meters (no token usage for a `tokens` entry, no images
    /// for an `images` entry or no image row matching its attributes, no
    /// input characters for `characters`, no audio duration for
    /// `audio_seconds`). Such
    /// a request is unpriced, exactly like an unpriced model (ADR-0010
    /// decision 3).
    pub fn price(&self, provider_type: &str, model: &str, usage: &LlmUsage) -> Option<Priced> {
        let entry = self.lookup(provider_type, model)?;
        match entry.basis {
            PriceBasis::Tokens => {
                let tokens = usage.tokens?;
                if entry.cached_input_unpriced && tokens.cached_tokens > 0
                    || entry.cache_write_unpriced && tokens.cache_creation_tokens > 0
                {
                    return None;
                }
                Some(Priced {
                    nanodollars: list_cost_nanodollars(entry, &tokens),
                    basis: PriceBasis::Tokens,
                    underpriced_modality: underpriced_modality(entry, &tokens),
                })
            }
            PriceBasis::Images => {
                let images = usage.meters.images?;
                let row = image_price(
                    &entry.image_prices,
                    usage.meters.image_size.as_deref(),
                    usage.meters.image_quality.as_deref(),
                )?;
                Some(Priced {
                    nanodollars: images.saturating_mul(row.nanodollars_per_image),
                    basis: PriceBasis::Images,
                    underpriced_modality: false,
                })
            }
            PriceBasis::Characters => {
                let characters = usage.meters.input_characters?;
                Some(Priced {
                    nanodollars: characters.saturating_mul(entry.nanodollars_per_character?),
                    basis: PriceBasis::Characters,
                    underpriced_modality: false,
                })
            }
            PriceBasis::AudioSeconds => {
                let milliseconds = usage.meters.audio_milliseconds?;
                Some(Priced {
                    nanodollars: milliseconds
                        .saturating_mul(entry.nanodollars_per_second?)
                        .div_ceil(1000),
                    basis: PriceBasis::AudioSeconds,
                    underpriced_modality: false,
                })
            }
        }
    }
}

fn push_option_u64(bytes: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        None => bytes.push(0),
    }
}

fn push_option_str(bytes: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
        None => bytes.push(0),
    }
}

/// The most specific row matching the observed attributes: both attributes,
/// then one, then neither. The card parser refuses a card where two rows of
/// the same specificity could both match, so the first found is the only one.
fn image_price<'a>(
    rows: &'a [ImagePrice],
    size: Option<&str>,
    quality: Option<&str>,
) -> Option<&'a ImagePrice> {
    rows.iter()
        .filter(|row| row.matches(size, quality))
        .max_by_key(|row| row.specificity())
}

/// Why `rows` cannot be priced unambiguously, if it cannot: two rows of the
/// same specificity that some request matches both. A size-only row and a
/// quality-only row always can, for a request with that size and quality.
pub fn image_prices_conflict(rows: &[ImagePrice]) -> Option<(usize, usize)> {
    for (i, a) in rows.iter().enumerate() {
        for (j, b) in rows.iter().enumerate().skip(i + 1) {
            let overlap = a.specificity() == b.specificity()
                && a.size
                    .as_deref()
                    .zip(b.size.as_deref())
                    .is_none_or(|(x, y)| x == y)
                && a.quality
                    .as_deref()
                    .zip(b.quality.as_deref())
                    .is_none_or(|(x, y)| x == y);
            if overlap {
                return Some((i, j));
            }
        }
    }
    None
}

/// Context length selects a provider's published long-context price band.
/// These three buckets are disjoint representations of prompt/context tokens,
/// so their saturating sum is the only safe selector; output is generated
/// after context selection and must not move a request into a higher band.
fn context_tokens(usage: &LlmTokenUsage) -> u64 {
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

/// The reported modality tokens, clamped so they never exceed the text
/// bucket they were reported inside: `(text, image, audio)` for input, then
/// for output. Provider-derived values, so subtraction saturates.
struct Split {
    input: [u64; 3],
    output: [u64; 3],
}

fn split(usage: &LlmTokenUsage) -> Split {
    let parts = |total: u64, image: u64, audio: u64| {
        let image = image.min(total);
        let audio = audio.min(total - image);
        [total - image - audio, image, audio]
    };
    Split {
        input: parts(
            usage.input_tokens,
            usage.input_image_tokens,
            usage.input_audio_tokens,
        ),
        output: parts(
            usage.output_tokens,
            usage.output_image_tokens,
            usage.output_audio_tokens,
        ),
    }
}

type Rate = fn(&Tier) -> u64;

const INPUT_RATES: [Rate; 3] = [
    |t| t.input_nanodollars_per_token,
    |t| {
        t.image_input_nanodollars_per_token
            .unwrap_or(t.input_nanodollars_per_token)
    },
    |t| {
        t.audio_input_nanodollars_per_token
            .unwrap_or(t.input_nanodollars_per_token)
    },
];

const OUTPUT_RATES: [Rate; 3] = [
    |t| t.output_nanodollars_per_token,
    |t| {
        t.image_output_nanodollars_per_token
            .unwrap_or(t.output_nanodollars_per_token)
    },
    |t| {
        t.audio_output_nanodollars_per_token
            .unwrap_or(t.output_nanodollars_per_token)
    },
];

fn output_cost(split: &Split, tier: &Tier) -> u64 {
    split
        .output
        .iter()
        .zip(OUTPUT_RATES)
        .fold(0u64, |cost, (tokens, rate)| {
            cost.saturating_add(tokens.saturating_mul(rate(tier)))
        })
}

fn all_buckets(usage: &LlmTokenUsage, tier: &Tier) -> u64 {
    let split = split(usage);
    let input = split
        .input
        .iter()
        .zip(INPUT_RATES)
        .fold(0u64, |cost, (tokens, rate)| {
            cost.saturating_add(tokens.saturating_mul(rate(tier)))
        });
    input
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
        .saturating_add(output_cost(&split, tier))
}

/// Modality tokens were reported and the tier that priced them has no rate
/// for that modality. The parser requires a modality rate on every tier of an
/// entry or on none, so the first tier answers for all of them.
fn underpriced_modality(entry: &PriceEntry, usage: &LlmTokenUsage) -> bool {
    let Some(tier) = entry.tiers.first() else {
        return false;
    };
    usage.input_image_tokens > 0 && tier.image_input_nanodollars_per_token.is_none()
        || usage.output_image_tokens > 0 && tier.image_output_nanodollars_per_token.is_none()
        || usage.input_audio_tokens > 0 && tier.audio_input_nanodollars_per_token.is_none()
        || usage.output_audio_tokens > 0 && tier.audio_output_nanodollars_per_token.is_none()
}

/// Compute the token list price. Tier selection uses total input context
/// (`input + cache-read + cache-write`), not output tokens; modality tokens
/// are inside `input` and so count toward `up_to`. `up_to` is inclusive, so
/// exactly 500_000 context tokens remain in a `up_to: 500000` tier. All
/// multiplication and addition saturates because token counts are
/// provider-derived wire values.
fn list_cost_nanodollars(entry: &PriceEntry, usage: &LlmTokenUsage) -> u64 {
    let quantity = context_tokens(usage);
    let Some(selected) = tier_for(&entry.tiers, quantity) else {
        return 0;
    };
    if entry.tier_mode == TierMode::WholeRequest {
        return all_buckets(usage, selected);
    }

    // Graduated: the context is laid out in prompt order and cut into bands
    // like tax brackets. Providers cache prefixes, so cache-read tokens come
    // first, then cache-write tokens, then the uncached input (text, then
    // image, then audio). Each token costs its own bucket's rate in the band
    // its position falls in, so every token is priced exactly once. Output is
    // not part of the context; it is priced at the band the whole context
    // selected.
    let split = split(usage);
    let buckets: [(u64, Rate); 5] = [
        (usage.cached_tokens, |t| {
            t.cached_input_nanodollars_per_token
        }),
        (usage.cache_creation_tokens, |t| {
            t.cache_write_nanodollars_per_token
        }),
        (split.input[0], INPUT_RATES[0]),
        (split.input[1], INPUT_RATES[1]),
        (split.input[2], INPUT_RATES[2]),
    ];
    let mut cost = output_cost(&split, selected);
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
            image_input_nanodollars_per_token: None,
            image_output_nanodollars_per_token: None,
            audio_input_nanodollars_per_token: None,
            audio_output_nanodollars_per_token: None,
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
            basis: PriceBasis::Tokens,
            image_prices: Vec::new(),
            nanodollars_per_character: None,
            nanodollars_per_second: None,
        }
    }
    fn usage(input: u64, cached: u64, write: u64, output: u64) -> LlmTokenUsage {
        LlmTokenUsage {
            input_tokens: input,
            cached_tokens: cached,
            cache_creation_tokens: write,
            output_tokens: output,
            ..LlmTokenUsage::default()
        }
    }
    /// The same buckets as the whole-request [`LlmUsage`] a `PriceList` prices.
    fn priced(input: u64, cached: u64, write: u64, output: u64) -> LlmUsage {
        LlmUsage::from_tokens(usage(input, cached, write, output))
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

    /// Modality tokens sit inside the input bucket, so they count toward the
    /// band, and in graduated mode they follow the text input in prompt
    /// order. Without modality rates the charge is exactly the old one.
    #[test]
    fn graduated_modality_tokens_take_their_band_positions_after_text_input() {
        let mut bands = two_bands();
        for band in &mut bands {
            band.image_input_nanodollars_per_token = Some(band.input_nanodollars_per_token * 3);
            band.image_output_nanodollars_per_token = Some(7);
        }
        let mut u = usage(1200, 0, 0, 10);
        u.input_image_tokens = 600;
        u.output_image_tokens = 4;
        // Text 600 fills band one; image 400 more in band one at 3000, then
        // 200 in band two at 6000; output at band two (6 text, 4 image).
        assert_eq!(
            list_cost_nanodollars(&entry(TierMode::Graduated, bands), &u),
            600 * 1000 + 400 * 3000 + 200 * 6000 + 6 * 10000 + 4 * 7
        );
        assert!(!underpriced_modality(
            &entry(TierMode::Graduated, two_bands()),
            &usage(1, 0, 0, 1)
        ));
        assert!(underpriced_modality(
            &entry(TierMode::Graduated, two_bands()),
            &u
        ));
        assert_eq!(
            list_cost_nanodollars(&entry(TierMode::Graduated, two_bands()), &u),
            list_cost_nanodollars(
                &entry(TierMode::Graduated, two_bands()),
                &usage(1200, 0, 0, 10)
            ),
            "no modality rate: the same charge as before"
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
            list.list_cost_nanodollars("openai", "gpt-5", &priced(2, 0, 0, 3)),
            Some(2100)
        );
        assert_eq!(
            list.list_cost_nanodollars("openai", "gpt-5", &priced(2, 1, 0, 3)),
            None
        );
        assert_eq!(
            list.list_cost_nanodollars("openai", "gpt-5", &priced(2, 0, 1, 3)),
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
            free_cache.list_cost_nanodollars("openai", "gpt-5", &priced(2, 1, 0, 3)),
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
            first.list_cost_nanodollars("openai", "missing", &priced(1, 2, 3, 4)),
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
        let u = priced(1, 0, 0, 1);
        assert_eq!(
            list.list_cost_for_cluster("provider:a", "gpt-5", &u),
            Some(5)
        );
        assert_eq!(list.list_cost_for_cluster("provider:z", "gpt-5", &u), None);
    }
}
