//! Named response profiles: per-profile distributions for TTFT, inter-token
//! delay, and streamed length, selected by the request's `model` string.
//!
//! A scale test needs a mix of fast/short and slow/long streams coexisting,
//! not every stream advancing
//! on the same clock. A [`Profile`] is three independent [`Dist`]s; sampling
//! one draws a `Duration`/count with `rand`, never blocks, and never
//! allocates beyond the small `Vec` of per-token delays the caller builds
//! from it (see `frames.rs`).
//!
//! # Distribution shape
//!
//! Deliberately just uniform-on-`[min, max]` (inclusive) for all three axes
//! -- the scale-test plan explicitly allows this ("do not over-engineer").
//! `min == max` degrades to "always this value", which is how the CLI's
//! legacy `--ttft-ms`/`--inter-token-ms`/`--tokens` flags become the
//! `default` profile's distributions unchanged (see [`ProfileSet::from_cli`]).

use std::collections::HashMap;
use std::time::Duration;

use rand::Rng;
use serde::Deserialize;

/// The name of the profile every unmatched `model` falls back to. Never
/// errors -- this is load infrastructure, not a validator (see
/// [`ProfileSet::resolve`]).
pub const DEFAULT_PROFILE: &str = "default";

/// A uniform distribution on `[min, max]`, inclusive. `min == max` always
/// draws that one value -- how a fixed CLI flag becomes a (degenerate)
/// distribution.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct Dist {
    pub min: u64,
    pub max: u64,
}

impl Dist {
    pub fn fixed(value: u64) -> Self {
        Self {
            min: value,
            max: value,
        }
    }

    /// Draw one value. `gen_range` on an inclusive range with `min == max`
    /// always returns that value, so callers never need to special-case a
    /// fixed distribution.
    fn sample(&self, rng: &mut impl Rng) -> u64 {
        rng.gen_range(self.min..=self.max)
    }

    fn sample_duration_ms(&self, rng: &mut impl Rng) -> Duration {
        Duration::from_millis(self.sample(rng))
    }
}

/// One named response shape: how long TTFT is, how long each inter-token
/// gap is, and how many content chunks the stream carries.
#[derive(Debug, Clone, Deserialize)]
pub struct Profile {
    #[serde(default)]
    pub name: String,
    pub ttft_ms: Dist,
    pub inter_token_ms: Dist,
    /// Output length in content chunks. Also reported verbatim as
    /// `output_tokens`/`completion_tokens` -- see the crate doc's
    /// "one content chunk == one token" simplification.
    pub length: Dist,
}

impl Profile {
    pub fn sample_ttft(&self, rng: &mut impl Rng) -> Duration {
        self.ttft_ms.sample_duration_ms(rng)
    }

    pub fn sample_inter_token(&self, rng: &mut impl Rng) -> Duration {
        self.inter_token_ms.sample_duration_ms(rng)
    }

    /// Number of content chunks to stream this request, drawn fresh. Capped
    /// at `u32::MAX` implicitly by `Dist`'s `u64` sample being narrowed --
    /// no profile here configures anything near that, so `as u32` never
    /// truncates in practice.
    pub fn sample_length(&self, rng: &mut impl Rng) -> u32 {
        self.length.sample(rng) as u32
    }
}

/// The full set of profiles this process serves, keyed by name, plus which
/// one an unmatched `model` falls back to.
pub struct ProfileSet {
    profiles: HashMap<String, Profile>,
}

/// The on-disk shape for `--profiles <file>`: a map of profile name to its
/// three distributions. Loaded once at startup and merged over the built-in
/// defaults (a file entry with the same name replaces the built-in; new
/// names are added) -- see [`ProfileSet::merge_file`].
#[derive(Debug, Deserialize)]
pub struct ProfileFile {
    #[serde(default)]
    pub profiles: HashMap<String, Profile>,
}

impl ProfileSet {
    /// Built-in profiles matching the workload mix (~60% short / 30% medium /
    /// 10% long; TTFT
    /// 200-600ms; inter-token 10-40ms across the mix), plus the CLI-derived
    /// `default` fallback for any `model` that names none of them.
    pub fn with_builtins(default_profile: Profile) -> Self {
        let mut profiles = HashMap::new();
        profiles.insert(
            "mock-fast-short".to_string(),
            Profile {
                name: "mock-fast-short".to_string(),
                ttft_ms: Dist { min: 50, max: 150 },
                inter_token_ms: Dist { min: 5, max: 15 },
                length: Dist { min: 50, max: 150 },
            },
        );
        profiles.insert(
            "mock-medium".to_string(),
            Profile {
                name: "mock-medium".to_string(),
                ttft_ms: Dist { min: 200, max: 400 },
                inter_token_ms: Dist { min: 15, max: 30 },
                length: Dist { min: 300, max: 600 },
            },
        );
        profiles.insert(
            "mock-slow-long".to_string(),
            Profile {
                name: "mock-slow-long".to_string(),
                ttft_ms: Dist { min: 400, max: 800 },
                inter_token_ms: Dist { min: 30, max: 60 },
                length: Dist {
                    min: 1000,
                    max: 2000,
                },
            },
        );
        profiles.insert(DEFAULT_PROFILE.to_string(), default_profile);
        Self { profiles }
    }

    /// Overlay `file` onto the current set: a name already present is
    /// replaced (including `"default"`, if the file chooses to redefine
    /// it); a new name is added.
    pub fn merge_file(&mut self, file: ProfileFile) {
        for (name, mut profile) in file.profiles {
            profile.name = name.clone();
            self.profiles.insert(name, profile);
        }
    }

    /// Look up the profile a request's `model` selects. An unmatched model
    /// is load-testing input, not a validation failure -- it falls back to
    /// [`DEFAULT_PROFILE`], which always exists (installed by
    /// [`Self::with_builtins`] and never removable, only replaceable).
    pub fn resolve(&self, model: &str) -> &Profile {
        self.profiles
            .get(model)
            .unwrap_or_else(|| &self.profiles[DEFAULT_PROFILE])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::SmallRng;
    use rand::SeedableRng;

    #[test]
    fn fixed_dist_always_returns_its_value() {
        let dist = Dist::fixed(42);
        let mut rng = SmallRng::seed_from_u64(1);
        for _ in 0..20 {
            assert_eq!(dist.sample(&mut rng), 42);
        }
    }

    #[test]
    fn resolve_falls_back_to_default_for_unknown_model() {
        let set = ProfileSet::with_builtins(Profile {
            name: DEFAULT_PROFILE.to_string(),
            ttft_ms: Dist::fixed(0),
            inter_token_ms: Dist::fixed(0),
            length: Dist::fixed(16),
        });
        let p = set.resolve("some-model-nobody-configured");
        assert_eq!(p.name, DEFAULT_PROFILE);
    }

    #[test]
    fn resolve_finds_builtin_by_name() {
        let set = ProfileSet::with_builtins(Profile {
            name: DEFAULT_PROFILE.to_string(),
            ttft_ms: Dist::fixed(0),
            inter_token_ms: Dist::fixed(0),
            length: Dist::fixed(16),
        });
        assert_eq!(set.resolve("mock-fast-short").name, "mock-fast-short");
        assert_eq!(set.resolve("mock-medium").name, "mock-medium");
        assert_eq!(set.resolve("mock-slow-long").name, "mock-slow-long");
    }

    #[test]
    fn merge_file_overrides_and_adds() {
        let mut set = ProfileSet::with_builtins(Profile {
            name: DEFAULT_PROFILE.to_string(),
            ttft_ms: Dist::fixed(0),
            inter_token_ms: Dist::fixed(0),
            length: Dist::fixed(16),
        });
        let file: ProfileFile = serde_json::from_str(
            r#"{"profiles": {
                "mock-fast-short": {"ttft_ms": {"min": 1, "max": 1}, "inter_token_ms": {"min": 1, "max": 1}, "length": {"min": 5, "max": 5}},
                "mock-custom": {"ttft_ms": {"min": 2, "max": 2}, "inter_token_ms": {"min": 2, "max": 2}, "length": {"min": 7, "max": 7}}
            }}"#,
        )
        .unwrap();
        set.merge_file(file);
        let mut rng = SmallRng::seed_from_u64(1);
        assert_eq!(set.resolve("mock-fast-short").sample_length(&mut rng), 5);
        assert_eq!(set.resolve("mock-custom").sample_length(&mut rng), 7);
    }

    /// The whole point of a distribution: two draws against a wide-enough
    /// range are not forced to agree. Seeded so the test itself is
    /// deterministic (rule 12's mutation-testing spirit: this must be able
    /// to fail if `sample_length` were hardcoded to `min`).
    #[test]
    fn sampling_varies_across_draws() {
        let profile = Profile {
            name: "t".to_string(),
            ttft_ms: Dist { min: 0, max: 1000 },
            inter_token_ms: Dist { min: 0, max: 1000 },
            length: Dist {
                min: 1,
                max: 10_000,
            },
        };
        let mut rng = SmallRng::seed_from_u64(7);
        let lengths: Vec<u32> = (0..10).map(|_| profile.sample_length(&mut rng)).collect();
        assert!(
            lengths.iter().any(|&l| l != lengths[0]),
            "expected varying lengths, got {lengths:?}"
        );
    }
}
