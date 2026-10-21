//! Chargeback tags: operator allow-listed key=value pairs that attribute a
//! request's spend to a project, team or cost centre.
//!
//! Tags come from two sources. The credential sets them (key metadata the
//! admin set on a virtual key, or verified JWT claims the operator mapped to
//! tags), and the client may send them in the [`HEADER`] request header when
//! the operator enables it. Both pass the same allow-list and caps; a tag key
//! the credential sets is never taken from the header, so a client cannot
//! override what the admin or the identity provider set. Everything not accepted is dropped and
//! counted by [`DropReason`], and a malformed header never fails the request.
//!
//! Tags are request-record and ledger data only. They are never a metric
//! label: their values are open-ended even when allow-listed.

use std::collections::{BTreeMap, BTreeSet};

/// Accepted tags, ordered by key so records and ledger entries serialize the
/// same way for the same tags.
pub type ChargebackTags = BTreeMap<String, String>;

/// The request header clients may send tags in, when the operator enables it.
pub const HEADER: &str = "x-cost-tags";

/// Longest tag key.
pub const MAX_KEY_BYTES: usize = 64;
/// Ceiling for a configured `max_tags`, and the most tags a key may carry.
pub const MAX_TAGS_CEILING: usize = 32;
/// Ceiling for a configured `max_value_bytes`, and for a key-metadata value.
pub const MAX_VALUE_BYTES_CEILING: usize = 256;
/// Default `max_tags` when the operator sets none.
pub const DEFAULT_MAX_TAGS: usize = 8;
/// Default `max_value_bytes` when the operator sets none.
pub const DEFAULT_MAX_VALUE_BYTES: usize = 64;
/// A longer header is malformed. Bounds the parse work per request.
pub const MAX_HEADER_BYTES: usize = 4096;

/// Checks a tag key: 1 to [`MAX_KEY_BYTES`] bytes of lowercase ASCII letters,
/// digits, `_`, `.` and `-`, starting with a letter.
pub fn validate_key(key: &str) -> Result<(), String> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        return Err(format!(
            "tag key must be 1 to {MAX_KEY_BYTES} bytes, got {}",
            key.len()
        ));
    }
    let mut bytes = key.bytes();
    if !bytes.next().is_some_and(|b| b.is_ascii_lowercase()) {
        return Err(format!(
            "tag key `{key}` must start with a lowercase letter"
        ));
    }
    if !bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b)) {
        return Err(format!(
            "tag key `{key}` may contain only lowercase letters, digits, `_`, `.` and `-`"
        ));
    }
    Ok(())
}

/// Whether every byte of a tag value is in the value alphabet: ASCII letters,
/// digits and `_ . : / @ + -`. No separators, quotes, spaces or controls, so
/// a value cannot inject into a CSV export or a log line.
pub fn value_alphabet(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"_.:/@+-".contains(&b))
}

/// Checks a tag value against the alphabet and `max_bytes`.
pub fn validate_value(value: &str, max_bytes: usize) -> Result<(), String> {
    if value.is_empty() || value.len() > max_bytes {
        return Err(format!(
            "tag value must be 1 to {max_bytes} bytes, got {}",
            value.len()
        ));
    }
    if !value_alphabet(value) {
        return Err(format!(
            "tag value `{value}` may contain only ASCII letters, digits, `_`, `.`, `:`, `/`, `@`, `+` and `-`"
        ));
    }
    Ok(())
}

/// Checks a key-metadata tag map, as the admin API and static key config
/// accept it: at most [`MAX_TAGS_CEILING`] tags, each key and value valid,
/// values at most [`MAX_VALUE_BYTES_CEILING`] bytes. The per-route allow-list
/// and caps apply again at request time.
pub fn validate_key_tags(tags: &ChargebackTags) -> Result<(), String> {
    if tags.len() > MAX_TAGS_CEILING {
        return Err(format!(
            "at most {MAX_TAGS_CEILING} tags, got {}",
            tags.len()
        ));
    }
    for (key, value) in tags {
        validate_key(key)?;
        validate_value(value, MAX_VALUE_BYTES_CEILING).map_err(|e| format!("tag `{key}`: {e}"))?;
    }
    Ok(())
}

/// Why a tag was not attributed. A finite set: it is the only label on the
/// drop counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// The key is not allow-listed, or the value is not one of its allowed values.
    NotAllowed,
    /// The value is longer than `max_tags`' companion cap, `max_value_bytes`.
    TooLong,
    /// The request had more accepted tags than `max_tags`.
    OverCount,
    /// The header did not parse; all its tags are dropped, counted once.
    Malformed,
    /// The header set a key that key metadata also sets; the key's value wins.
    Overridden,
    /// A JWT claim mapped to a tag was absent from the verified token.
    ClaimMissing,
}

impl DropReason {
    pub const ALL: [DropReason; 6] = [
        DropReason::NotAllowed,
        DropReason::TooLong,
        DropReason::OverCount,
        DropReason::Malformed,
        DropReason::Overridden,
        DropReason::ClaimMissing,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            DropReason::NotAllowed => "not_allowed",
            DropReason::TooLong => "too_long",
            DropReason::OverCount => "over_count",
            DropReason::Malformed => "malformed",
            DropReason::Overridden => "overridden",
            DropReason::ClaimMissing => "claim_missing",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

/// Drops per reason for one request, indexed like [`DropReason::ALL`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Drops([u64; 6]);

impl Drops {
    fn add(&mut self, reason: DropReason) {
        self.0[reason.index()] += 1;
    }

    pub fn get(&self, reason: DropReason) -> u64 {
        self.0[reason.index()]
    }

    /// Non-zero `(reason, count)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (DropReason, u64)> + '_ {
        DropReason::ALL
            .into_iter()
            .map(|r| (r, self.get(r)))
            .filter(|(_, n)| *n > 0)
    }
}

/// The tags a request is attributed with, and what was dropped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resolved {
    pub tags: ChargebackTags,
    pub dropped: Drops,
}

/// The operator's tag configuration for one auth filter, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagPolicy {
    /// Allow-listed keys; `Some` restricts the key to those values.
    allowed: BTreeMap<String, Option<BTreeSet<String>>>,
    from_header: bool,
    max_tags: usize,
    max_value_bytes: usize,
}

impl TagPolicy {
    /// Validates and builds a policy. `allowed` must name at least one key;
    /// an allowed-values list, when given, must be non-empty. Errors name the
    /// offending part; callers prefix their own field path.
    pub fn new(
        allowed: Vec<(String, Option<Vec<String>>)>,
        from_header: bool,
        max_tags: Option<usize>,
        max_value_bytes: Option<usize>,
    ) -> Result<Self, String> {
        let max_tags = max_tags.unwrap_or(DEFAULT_MAX_TAGS);
        if !(1..=MAX_TAGS_CEILING).contains(&max_tags) {
            return Err(format!(
                "max_tags must be 1 to {MAX_TAGS_CEILING}, got {max_tags}"
            ));
        }
        let max_value_bytes = max_value_bytes.unwrap_or(DEFAULT_MAX_VALUE_BYTES);
        if !(1..=MAX_VALUE_BYTES_CEILING).contains(&max_value_bytes) {
            return Err(format!(
                "max_value_bytes must be 1 to {MAX_VALUE_BYTES_CEILING}, got {max_value_bytes}"
            ));
        }
        if allowed.is_empty() {
            return Err("allowed must name at least one tag key".into());
        }
        let mut map = BTreeMap::new();
        for (i, (key, values)) in allowed.into_iter().enumerate() {
            validate_key(&key).map_err(|e| format!("allowed[{i}].key: {e}"))?;
            let values = match values {
                None => None,
                Some(values) if values.is_empty() => {
                    return Err(format!(
                        "allowed[{i}].values must not be empty; omit it to allow any value"
                    ))
                }
                Some(values) => {
                    let mut set = BTreeSet::new();
                    for (j, value) in values.into_iter().enumerate() {
                        validate_value(&value, max_value_bytes)
                            .map_err(|e| format!("allowed[{i}].values[{j}]: {e}"))?;
                        set.insert(value);
                    }
                    Some(set)
                }
            };
            if map.insert(key.clone(), values).is_some() {
                return Err(format!("allowed[{i}].key: duplicate tag key `{key}`"));
            }
        }
        Ok(Self {
            allowed: map,
            from_header,
            max_tags,
            max_value_bytes,
        })
    }

    /// Whether the operator enabled the [`HEADER`]. When false the header is
    /// never read.
    pub fn from_header(&self) -> bool {
        self.from_header
    }

    /// Whether `key` is allow-listed. Config uses it to refuse a tag source
    /// that names a key the policy would always drop.
    pub fn allows_key(&self, key: &str) -> bool {
        self.allowed.contains_key(key)
    }

    /// Why `(key, value)` is refused, or `None` when it passes.
    fn check(&self, key: &str, value: &str) -> Option<DropReason> {
        let Some(values) = self.allowed.get(key) else {
            return Some(DropReason::NotAllowed);
        };
        if value.len() > self.max_value_bytes {
            return Some(DropReason::TooLong);
        }
        match values {
            Some(values) if !values.contains(value) => Some(DropReason::NotAllowed),
            _ => None,
        }
    }

    /// Resolves a request's tags. `key_tags` is the tags the credential set
    /// (key metadata, or mapped JWT claims). `header_values` holds every
    /// value of the [`HEADER`] the request carried; it is ignored unless the
    /// policy enables the header. More than one value is malformed.
    ///
    /// Key-metadata tags come first: a header tag whose key the key metadata
    /// sets is dropped as [`DropReason::Overridden`], and when the total is
    /// over `max_tags` the header's tags are dropped before the key's.
    pub fn resolve(&self, key_tags: &ChargebackTags, header_values: &[&[u8]]) -> Resolved {
        self.resolve_withheld(key_tags, &[], header_values)
    }

    /// [`Self::resolve`], plus `withheld`: tag keys the credential owns but
    /// could not fill (a mapped JWT claim that was missing or not a valid
    /// value), each with its drop reason. Each is counted, and the header
    /// cannot set the key, as if the credential had set it.
    pub fn resolve_withheld(
        &self,
        key_tags: &ChargebackTags,
        withheld: &[(String, DropReason)],
        header_values: &[&[u8]],
    ) -> Resolved {
        let mut out = Resolved::default();
        for (_, reason) in withheld {
            out.dropped.add(*reason);
        }
        let owned =
            |key: &str| key_tags.contains_key(key) || withheld.iter().any(|(k, _)| k == key);
        let mut from_key = Vec::new();
        for (key, value) in key_tags {
            match self.check(key, value) {
                Some(reason) => out.dropped.add(reason),
                None => from_key.push((key.as_str(), value.as_str())),
            }
        }
        let mut from_header = Vec::new();
        let parsed = if self.from_header && !header_values.is_empty() {
            match header_values {
                [one] => parse_header(one),
                _ => None,
            }
        } else {
            Some(Vec::new())
        };
        match parsed {
            None => out.dropped.add(DropReason::Malformed),
            Some(pairs) => {
                for (key, value) in pairs {
                    if owned(key) {
                        out.dropped.add(DropReason::Overridden);
                        continue;
                    }
                    match self.check(key, value) {
                        Some(reason) => out.dropped.add(reason),
                        None => from_header.push((key, value)),
                    }
                }
            }
        }
        from_header.sort();
        for (key, value) in from_key.into_iter().chain(from_header) {
            if out.tags.len() == self.max_tags {
                out.dropped.add(DropReason::OverCount);
            } else {
                out.tags.insert(key.to_owned(), value.to_owned());
            }
        }
        out
    }
}

/// Parses `k=v, k2=v2`. `None` when the header is malformed: over
/// [`MAX_HEADER_BYTES`], not ASCII, an empty item, an item without `=`, an
/// invalid key, a value outside the alphabet, or a repeated key. Value
/// length is not checked here; an over-long value is dropped alone, as
/// [`DropReason::TooLong`].
fn parse_header(raw: &[u8]) -> Option<Vec<(&str, &str)>> {
    if raw.len() > MAX_HEADER_BYTES || !raw.is_ascii() {
        return None;
    }
    let text = std::str::from_utf8(raw).ok()?;
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    for item in text.split(',') {
        let (key, value) = item.split_once('=')?;
        let (key, value) = (
            key.trim_matches([' ', '\t']),
            value.trim_matches([' ', '\t']),
        );
        if validate_key(key).is_err() || value.is_empty() || !value_alphabet(value) {
            return None;
        }
        if pairs.iter().any(|(k, _)| *k == key) {
            return None;
        }
        pairs.push((key, value));
    }
    Some(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(from_header: bool) -> TagPolicy {
        TagPolicy::new(
            vec![
                ("project".into(), None),
                ("team".into(), Some(vec!["infra".into(), "search".into()])),
                ("env".into(), None),
            ],
            from_header,
            Some(2),
            Some(8),
        )
        .unwrap()
    }

    fn tags(pairs: &[(&str, &str)]) -> ChargebackTags {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn allow_listed_header_tags_are_accepted() {
        let r = policy(true).resolve(&tags(&[]), &[b"project=search, team=infra"]);
        assert_eq!(r.tags, tags(&[("project", "search"), ("team", "infra")]));
        assert_eq!(r.dropped, Drops::default());
    }

    #[test]
    fn header_is_ignored_unless_enabled() {
        let r = policy(false).resolve(&tags(&[]), &[b"project=search", b"x"]);
        assert!(r.tags.is_empty());
        assert_eq!(
            r.dropped,
            Drops::default(),
            "an unread header is not a drop"
        );
    }

    #[test]
    fn each_drop_reason_is_counted() {
        let p = policy(true);
        // Not listed, value not allowed, over-long.
        let r = p.resolve(&tags(&[]), &[b"owner=a,team=ads,project=123456789"]);
        assert!(r.tags.is_empty());
        assert_eq!(r.dropped.get(DropReason::NotAllowed), 2);
        assert_eq!(r.dropped.get(DropReason::TooLong), 1);
        // Over the count cap (max_tags = 2).
        let r = p.resolve(&tags(&[]), &[b"project=a,team=infra,env=prod"]);
        assert_eq!(r.tags.len(), 2);
        assert_eq!(r.dropped.get(DropReason::OverCount), 1);
    }

    #[test]
    fn malformed_header_drops_everything_and_counts_once() {
        let p = policy(true);
        for raw in [
            &b"project"[..],
            b"project=a,,team=infra",
            b"Project=a",
            b"project=a b",
            b"project=a,project=b",
            b"project=\xc3\xa9",
            b"",
        ] {
            let r = p.resolve(&tags(&[]), &[raw]);
            assert!(r.tags.is_empty(), "{raw:?}");
            assert_eq!(r.dropped.get(DropReason::Malformed), 1, "{raw:?}");
            assert_eq!(r.dropped.iter().count(), 1, "{raw:?}");
        }
        let long = format!("project={}", "a".repeat(MAX_HEADER_BYTES));
        let r = p.resolve(&tags(&[]), &[long.as_bytes()]);
        assert_eq!(r.dropped.get(DropReason::Malformed), 1);
        // Two header instances are ambiguous: malformed.
        let r = p.resolve(&tags(&[]), &[b"project=a", b"team=infra"]);
        assert!(r.tags.is_empty());
        assert_eq!(r.dropped.get(DropReason::Malformed), 1);
    }

    #[test]
    fn key_metadata_wins_over_the_header() {
        let r = policy(true).resolve(&tags(&[("team", "infra")]), &[b"team=search,project=p"]);
        assert_eq!(r.tags, tags(&[("project", "p"), ("team", "infra")]));
        assert_eq!(r.dropped.get(DropReason::Overridden), 1);
    }

    #[test]
    fn header_cannot_fill_a_key_tag_the_policy_refused() {
        // The admin's value is not allowed; the client's is, but the key still
        // owns the tag key, so nothing is attributed for it.
        let r = policy(true).resolve(&tags(&[("team", "ads")]), &[b"team=infra"]);
        assert!(r.tags.is_empty());
        assert_eq!(r.dropped.get(DropReason::NotAllowed), 1);
        assert_eq!(r.dropped.get(DropReason::Overridden), 1);
    }

    #[test]
    fn key_tags_fill_the_count_cap_before_header_tags() {
        let r = policy(true).resolve(
            &tags(&[("project", "p"), ("team", "infra")]),
            &[b"env=prod"],
        );
        assert_eq!(r.tags, tags(&[("project", "p"), ("team", "infra")]));
        assert_eq!(r.dropped.get(DropReason::OverCount), 1);
    }

    #[test]
    fn key_tags_pass_the_same_allow_list() {
        let r = policy(false).resolve(&tags(&[("owner", "x"), ("project", "p")]), &[]);
        assert_eq!(r.tags, tags(&[("project", "p")]));
        assert_eq!(r.dropped.get(DropReason::NotAllowed), 1);
    }

    #[test]
    fn withheld_keys_are_counted_and_the_header_cannot_fill_them() {
        let withheld = [
            ("team".to_owned(), DropReason::ClaimMissing),
            ("project".to_owned(), DropReason::Malformed),
        ];
        let r = policy(true).resolve_withheld(&tags(&[]), &withheld, &[b"team=infra,project=p"]);
        assert_eq!(r.tags, tags(&[]));
        assert_eq!(r.dropped.get(DropReason::ClaimMissing), 1);
        assert_eq!(r.dropped.get(DropReason::Malformed), 1);
        assert_eq!(r.dropped.get(DropReason::Overridden), 2);
    }

    #[test]
    fn policy_validation_names_the_part() {
        let bad = |allowed: Vec<(String, Option<Vec<String>>)>, t, v| {
            TagPolicy::new(allowed, true, t, v).unwrap_err()
        };
        assert!(bad(vec![], None, None).contains("at least one"));
        assert!(bad(vec![("Team".into(), None)], None, None).contains("allowed[0].key"));
        assert!(bad(vec![("team".into(), Some(vec![]))], None, None).contains("values"));
        assert!(
            bad(vec![("a".into(), None), ("a".into(), None)], None, None).contains("duplicate")
        );
        assert!(bad(vec![("a".into(), None)], Some(0), None).contains("max_tags"));
        assert!(bad(vec![("a".into(), None)], Some(33), None).contains("max_tags"));
        assert!(bad(vec![("a".into(), None)], None, Some(257)).contains("max_value_bytes"));
        assert!(
            bad(vec![("a".into(), Some(vec!["x y".into()]))], None, None)
                .contains("allowed[0].values[0]")
        );
    }

    #[test]
    fn key_tag_validation() {
        assert!(validate_key_tags(&tags(&[("project", "a:b/c@d+e-f_g.h")])).is_ok());
        assert!(validate_key_tags(&tags(&[("project", "a,b")])).is_err());
        assert!(validate_key_tags(&tags(&[("project", "")])).is_err());
        let long = "a".repeat(MAX_VALUE_BYTES_CEILING + 1);
        assert!(validate_key_tags(&tags(&[("project", &long)])).is_err());
        let many: ChargebackTags = (0..=MAX_TAGS_CEILING)
            .map(|i| (format!("k{i}"), "v".to_string()))
            .collect();
        assert!(validate_key_tags(&many).is_err());
    }
}
