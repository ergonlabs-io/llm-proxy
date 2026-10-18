//! Tenant ownership of provider objects: the parts that do not touch a
//! stream. [`crate::object_ownership_filter`] applies them.
//!
//! A provider issues object IDs in one namespace per provider account, and
//! every tenant reaches the provider through the proxy's account. A tenant
//! that learns another tenant's ID could otherwise read, cancel or delete
//! that object, or feed it to a model, through the proxy. The proxy records
//! which tenant created each object and refuses everyone else. What is an
//! object, and how its creation is recorded, is configured by endpoint shape
//! ([`Rules`]); nothing here knows a provider (ADR-0013).
//!
//! # What names an object
//!
//! - A request path that contains a configured collection's segments,
//!   contiguous and in order, followed by one more segment: that segment is
//!   the ID, and anything after it (`/content`, `/cancel`) is the same
//!   object, unless the segment is one of the collection's endpoints
//!   (`/v1/threads/runs`). Matching runs on the path after percent-decoding
//!   and resolving `.` and `..` segments, so an encoded or dotted path
//!   cannot slip past it. It matches anywhere in the path, so a prefix that a
//!   route strips before dialling cannot hide a collection either.
//! - In a JSON request body, any member a reference pattern matches, at any
//!   depth: its string value, each string in its array value, and the string
//!   `id` of its object value. Duplicate members are all checked, since a
//!   provider's parser may keep either one. The values of opaque members
//!   (caller data such as `metadata`) are not looked into.
//!
//! # Unknown IDs
//!
//! An ID no tenant owns (created before ownership was recorded, or outside
//! the proxy, or whose owner expired) is refused exactly like another
//! tenant's: unset never means open (AGENTS.md "Fail-open controls"). An
//! operator assigns such an object to its tenant through the admin API.
//!
//! # Where owners live
//!
//! In the control-plane store ([`ControlPlaneStore::claim_object`]), so they
//! survive a restart with a durable store and reach every replica with a
//! shared one. The worker never does the I/O: [`ObjectOwners`] keeps a
//! bounded cache of known owners and hands every store call to its own
//! thread. A cache miss is a store read the filter waits for; it is never
//! answered from a guess. This is the one request that waits on a store read,
//! an exception to AGENTS.md "Policy Domains" recorded in ADR-0012, which also
//! says why owners are not preloaded.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use tokio::sync::oneshot;

use crate::auth::TenantId;
use crate::control::{ControlPlaneStore, ObjectOwner, StoreError};

/// Unix seconds now, the clock owner expiries are kept in; `0` if the
/// clock is before the epoch.
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Most owners [`ObjectOwners`] caches. Past it the cache is cleared and
/// refilled from the store, so a long-lived replica cannot grow it without
/// limit; a miss costs one store read, never a wrong answer.
const CACHE_CAP: usize = 65_536;

/// Most store calls queued for the owners thread. A full queue fails the
/// call rather than blocking the worker: a read becomes a 503, a claim is
/// logged as not recorded.
const QUEUE_CAP: usize = 4_096;

/// Shortest gap between two warnings of the same kind. Repeats in between
/// are counted and reported with the next one (AGENTS.md "Fail-open
/// controls": suppress repeats, or the log becomes the incident).
const WARN_EVERY: Duration = Duration::from_secs(60);

/// The reference and owned members when none are configured: the file rule
/// every configuration had before they were configurable.
pub const DEFAULT_FILE_MEMBERS: [&str; 4] = ["file_id", "*_file_id", "file_ids", "*_file_ids"];

/// When a create's ID is recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    Always,
    /// Only when this top-level request member is `true`.
    IfTrue(String),
    /// Unless this top-level request member is `false`.
    UnlessFalse(String),
}

/// One object collection.
#[derive(Debug, Clone)]
pub struct Collection {
    /// Lowercased path segments.
    segments: Vec<String>,
    /// Lowercased segments under the path that are endpoints, not IDs.
    endpoints: Vec<String>,
    pub record: Record,
    /// How long a created object's owner is kept; `None` until removed.
    pub owner_ttl: Option<Duration>,
}

impl Collection {
    /// Validates `path` and `endpoints`; the error says why.
    pub fn new(
        path: &str,
        endpoints: &[String],
        record: Record,
        owner_ttl: Option<Duration>,
    ) -> Result<Self, String> {
        let Some(rest) = path.strip_prefix('/') else {
            return Err(format!("{path:?} must start with '/'"));
        };
        if rest.is_empty() || rest.ends_with('/') {
            return Err(format!("{path:?} must name a path and not end with '/'"));
        }
        if path.contains(['*', '?', '%', '\\']) {
            return Err(format!("{path:?} must not contain '*', '?', '%' or '\\'"));
        }
        let segments: Vec<String> = rest.split('/').map(str::to_ascii_lowercase).collect();
        if segments
            .iter()
            .any(|s| s.is_empty() || s == "." || s == "..")
        {
            return Err(format!(
                "{path:?} must not contain an empty, '.' or '..' segment"
            ));
        }
        let mut lowered = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            if endpoint.is_empty()
                || endpoint == "."
                || endpoint == ".."
                || endpoint.contains(['/', '\\', '*', '?', '%'])
            {
                return Err(format!(
                    "endpoint {endpoint:?} must be one segment without '/', '\\', '*', '?' or '%'"
                ));
            }
            lowered.push(endpoint.to_ascii_lowercase());
        }
        Ok(Collection {
            segments,
            endpoints: lowered,
            record,
            owner_ttl,
        })
    }

    /// The path, as configured but lowercased.
    pub fn path(&self) -> String {
        format!("/{}", self.segments.join("/"))
    }
}

/// A member name, or `*` and a suffix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberPattern {
    Exact(String),
    Suffix(String),
}

impl MemberPattern {
    pub fn parse(pattern: &str) -> Result<Self, String> {
        let (suffix, name) = match pattern.strip_prefix('*') {
            Some(suffix) => (true, suffix),
            None => (false, pattern),
        };
        if name.is_empty() || name.contains(['*', '.']) {
            return Err(format!(
                "{pattern:?} must be a member name, or '*' and a suffix, without '.' or another '*'"
            ));
        }
        Ok(if suffix {
            MemberPattern::Suffix(name.to_string())
        } else {
            MemberPattern::Exact(name.to_string())
        })
    }

    fn matches(&self, key: &str) -> bool {
        match self {
            MemberPattern::Exact(name) => key == name,
            MemberPattern::Suffix(suffix) => key.len() > suffix.len() && key.ends_with(suffix),
        }
    }

    /// The literal a body must contain to spell a matching member.
    fn literal(&self) -> &str {
        match self {
            MemberPattern::Exact(name) | MemberPattern::Suffix(name) => name,
        }
    }
}

/// A response member whose objects the caller now owns: a top-level member,
/// optionally one member of its object value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedMember {
    top: MemberPattern,
    nested: Option<String>,
}

impl OwnedMember {
    pub fn parse(path: &str) -> Result<Self, String> {
        let (top, nested) = match path.split_once('.') {
            Some((top, nested)) => {
                if nested.is_empty() || nested.contains(['.', '*']) {
                    return Err(format!(
                        "{path:?} may name one nested member, by exact name"
                    ));
                }
                (top, Some(nested.to_string()))
            }
            None => (path, None),
        };
        Ok(OwnedMember {
            top: MemberPattern::parse(top)?,
            nested,
        })
    }
}

/// Everything that decides what names an object and what a response
/// records. Built once per filter chain from its config.
#[derive(Debug, Clone)]
pub struct Rules {
    collections: Vec<Collection>,
    references: Vec<MemberPattern>,
    owned: Vec<OwnedMember>,
    opaque: Vec<String>,
}

/// What a request path names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathTarget {
    /// No collection.
    None,
    /// A collection itself, by index: a POST creates, anything else lists.
    Collection(usize),
    /// An endpoint under a collection, by index: a POST creates, anything
    /// else names no object.
    Endpoint(usize),
    /// One object in a collection, by ID.
    Object(String),
}

impl Rules {
    /// The error names what is wrong; `collections` must not be empty and no
    /// path may repeat.
    pub fn new(
        collections: Vec<Collection>,
        references: Vec<MemberPattern>,
        owned: Vec<OwnedMember>,
        opaque: Vec<String>,
    ) -> Result<Self, String> {
        if collections.is_empty() {
            return Err("at least one collection is required".into());
        }
        for (i, c) in collections.iter().enumerate() {
            if collections[..i].iter().any(|d| d.segments == c.segments) {
                return Err(format!("collection {} is configured twice", c.path()));
            }
        }
        let file_rule = || {
            DEFAULT_FILE_MEMBERS
                .iter()
                .map(|m| MemberPattern::parse(m).expect("the default members parse"))
                .collect::<Vec<_>>()
        };
        let references = if references.is_empty() {
            file_rule()
        } else {
            references
        };
        let owned = if owned.is_empty() {
            file_rule()
                .into_iter()
                .map(|top| OwnedMember { top, nested: None })
                .collect()
        } else {
            owned
        };
        Ok(Rules {
            collections,
            references,
            owned,
            opaque,
        })
    }

    pub fn collection(&self, index: usize) -> &Collection {
        &self.collections[index]
    }

    /// What `raw_path` (the request target's path, without the query) names.
    /// See the module doc for the matching rule.
    pub fn classify(&self, raw_path: &str) -> PathTarget {
        let segments = normalized_segments(raw_path);
        let lowered: Vec<String> = segments.iter().map(|s| s.to_ascii_lowercase()).collect();
        // The earliest match in the path wins, so a collection named inside
        // another object's ID cannot be preferred over the real one. At the
        // same start the longer collection wins, so the outcome does not
        // depend on the order collections are configured in.
        let mut best: Option<(usize, usize, usize)> = None;
        for (index, collection) in self.collections.iter().enumerate() {
            let n = collection.segments.len();
            if let Some(start) = lowered
                .windows(n)
                .position(|w| w == collection.segments.as_slice())
            {
                if best.is_none_or(|(s, len, _)| start < s || (start == s && n > len)) {
                    best = Some((start, n, index));
                }
            }
        }
        match best {
            None => PathTarget::None,
            Some((start, n, index)) => match segments.get(start + n) {
                None => PathTarget::Collection(index),
                Some(_)
                    if self.collections[index]
                        .endpoints
                        .contains(&lowered[start + n]) =>
                {
                    PathTarget::Endpoint(index)
                }
                Some(id) => PathTarget::Object(id.clone()),
            },
        }
    }

    /// See the module doc. A body is parsed only when its bytes could spell
    /// a reference member: a pattern's literal, or a `\u` escape that could
    /// spell it without the literal. Anything else passes without a parse.
    pub fn references(&self, body: &[u8]) -> BodyReferences {
        let first = body.iter().find(|b| !b.is_ascii_whitespace());
        if !matches!(first, Some(b'{') | Some(b'[')) {
            return BodyReferences::None;
        }
        if !contains(body, "\\u") && !self.references.iter().any(|p| contains(body, p.literal())) {
            return BodyReferences::None;
        }
        let mut found = Vec::new();
        let mut de = serde_json::Deserializer::from_slice(body);
        let walked = Walk {
            rules: self,
            found: &mut found,
            mode: Mode::Plain,
        }
        .deserialize(&mut de)
        .and_then(|()| de.end());
        match walked {
            Ok(()) => BodyReferences::Ids(found),
            Err(_) => BodyReferences::Unparseable,
        }
    }

    /// What a 2xx JSON response body says the caller now owns. `None` when
    /// the body is not a JSON object.
    pub fn owned_by_response(&self, body: &[u8], created: bool) -> Option<ResponseOwned> {
        let serde_json::Value::Object(members) = serde_json::from_slice(body).ok()? else {
            return None;
        };
        let mut owned = ResponseOwned::default();
        if created {
            if let Some(serde_json::Value::String(id)) = members.get("id") {
                owned.created = Some(id.clone());
            }
        }
        for (key, value) in &members {
            for rule in self.owned.iter().filter(|rule| rule.top.matches(key)) {
                let value = match &rule.nested {
                    None => Some(value),
                    Some(nested) => value.get(nested),
                };
                match value {
                    Some(serde_json::Value::String(id)) => owned.files.push(id.clone()),
                    Some(serde_json::Value::Array(items)) => owned
                        .files
                        .extend(items.iter().filter_map(|v| v.as_str().map(str::to_string))),
                    _ => {}
                }
            }
        }
        owned.files.dedup();
        Some(owned)
    }

    fn mode_for(&self, key: &str) -> Mode {
        if self.opaque.iter().any(|name| name == key) {
            Mode::Opaque
        } else if self.references.iter().any(|p| p.matches(key)) {
            Mode::Reference
        } else {
            Mode::Plain
        }
    }
}

/// Whether `haystack` contains `needle`. Request bodies are UTF-8 JSON in
/// practice, where `str::contains` is fast; anything else is scanned bytewise.
fn contains(haystack: &[u8], needle: &str) -> bool {
    match std::str::from_utf8(haystack) {
        Ok(text) => text.contains(needle),
        Err(_) => haystack
            .windows(needle.len())
            .any(|w| w == needle.as_bytes()),
    }
}

/// `raw_path` percent-decoded and split into segments, with empty and `.`
/// segments dropped and `..` applied. A backslash counts as a separator,
/// since some servers treat it as one.
fn normalized_segments(raw_path: &str) -> Vec<String> {
    let decoded = percent_decode(raw_path);
    let mut out: Vec<String> = Vec::new();
    for segment in decoded.split(['/', '\\']) {
        match segment {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s.to_string()),
        }
    }
    out
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| (b as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The object IDs a request body references.
#[derive(Debug, PartialEq, Eq)]
pub enum BodyReferences {
    /// The body cannot reference an object: it is not JSON, or no member
    /// name could spell one.
    None,
    /// Every referenced ID, duplicates included.
    Ids(Vec<String>),
    /// The body may spell a reference but does not parse as JSON. The
    /// provider's parser may still accept it, so it is refused, not passed.
    Unparseable,
}

/// How the value being walked relates to references.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Not a reference; members inside start over by name.
    Plain,
    /// The value of a reference member.
    Reference,
    /// An element of a reference member's array, or the `id` of its object.
    Element,
    /// Caller data: not looked into.
    Opaque,
}

/// Walks a JSON document without building it, collecting reference values.
///
/// Rust note: a `DeserializeSeed` rather than `serde_json::Value`, because
/// `Value` keeps only the last of two members with the same name, and the
/// provider may keep the first.
struct Walk<'a> {
    rules: &'a Rules,
    found: &'a mut Vec<String>,
    mode: Mode,
}

impl<'de> DeserializeSeed<'de> for Walk<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<(), D::Error> {
        if self.mode == Mode::Opaque {
            <IgnoredAny as serde::Deserialize>::deserialize(de).map(|_| ())
        } else {
            de.deserialize_any(self)
        }
    }
}

impl<'de> Visitor<'de> for Walk<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_str<E>(self, v: &str) -> Result<(), E> {
        if matches!(self.mode, Mode::Reference | Mode::Element) {
            self.found.push(v.to_string());
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        // Strings directly in a reference member's array are references; an
        // element that is itself an object is walked like its parent.
        let mode = if self.mode == Mode::Reference {
            Mode::Element
        } else {
            Mode::Plain
        };
        while seq
            .next_element_seed(Walk {
                rules: self.rules,
                found: self.found,
                mode,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        // A reference member's object names its object by its `id`
        // (`"conversation": {"id": ...}`); its other members start over.
        let names_by_id = matches!(self.mode, Mode::Reference | Mode::Element);
        while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
            let mode = if names_by_id && key == "id" {
                Mode::Element
            } else {
                self.rules.mode_for(&key)
            };
            map.next_value_seed(Walk {
                rules: self.rules,
                found: self.found,
                mode,
            })?;
        }
        Ok(())
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
}

/// Whether a create with this request body is recorded under `record`.
/// When in doubt it records: a recorded object the provider did not keep
/// costs one row, while an object kept but not recorded is refused to its
/// creator. Every duplicate of the member counts, since the provider's
/// parser may keep either one.
pub fn records(record: &Record, body: Option<&[u8]>) -> bool {
    let (member, if_true) = match record {
        Record::Always => return true,
        Record::IfTrue(member) => (member, true),
        Record::UnlessFalse(member) => (member, false),
    };
    let Some(body) = body else {
        return !if_true;
    };
    if !contains(body, member) && !contains(body, "\\u") {
        return !if_true;
    }
    let mut values = Vec::new();
    let mut de = serde_json::Deserializer::from_slice(body);
    let read = TopLevel {
        member,
        values: &mut values,
    }
    .deserialize(&mut de)
    .and_then(|()| de.end());
    if read.is_err() {
        return true;
    }
    if if_true {
        values.contains(&Some(true))
    } else {
        values.is_empty() || values.iter().any(|v| *v != Some(false))
    }
}

/// Collects every top-level value of one member: `Some(bool)` for a boolean,
/// `None` for anything else.
struct TopLevel<'a> {
    member: &'a str,
    values: &'a mut Vec<Option<bool>>,
}

impl<'de> DeserializeSeed<'de> for TopLevel<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<(), D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for TopLevel<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
            if key == self.member {
                let value: serde_json::Value = map.next_value()?;
                self.values.push(value.as_bool());
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
}

/// What a 2xx JSON response body says the caller now owns.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ResponseOwned {
    /// The top-level `id`, read only from a create's response.
    pub created: Option<String>,
    /// What the owned members name: a batch's `output_file_id` appears only
    /// once the batch completes, and the provider created that file for the
    /// batch's owner.
    pub files: Vec<String>,
}

/// Most bytes of an event stream read for a create's ID. The ID is in the
/// first event, which is small.
pub const MAX_FIRST_EVENT_BYTES: usize = 64 * 1024;

/// What the start of a create's event stream says about the created ID.
#[derive(Debug, PartialEq, Eq)]
pub enum FirstEvent {
    /// No event with JSON data has ended yet.
    NeedMore,
    /// The created ID.
    Found(String),
    /// The first event with JSON data names no single ID; why.
    NotFound(&'static str),
}

/// Reads the created ID from the first event of `stream` that carries a
/// JSON object: its top-level string `id`, else the `id` of its one member
/// whose value is an object with a string `id` (`{"type": ...,
/// "response": {"id": ...}}`). Events without JSON data are skipped.
pub fn created_in_first_event(stream: &[u8]) -> FirstEvent {
    let text = String::from_utf8_lossy(stream);
    let normalized = text.replace("\r\n", "\n");
    let mut rest = normalized.as_str();
    while let Some(end) = rest.find("\n\n") {
        let event = &rest[..end];
        rest = &rest[end + 2..];
        let data: Vec<&str> = event
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(|value| value.strip_prefix(' ').unwrap_or(value))
            .collect();
        if data.is_empty() {
            continue;
        }
        let Ok(serde_json::Value::Object(members)) =
            serde_json::from_str::<serde_json::Value>(&data.join("\n"))
        else {
            continue;
        };
        if let Some(serde_json::Value::String(id)) = members.get("id") {
            return FirstEvent::Found(id.clone());
        }
        let mut nested = members
            .values()
            .filter_map(|v| v.get("id").and_then(|id| id.as_str()));
        return match (nested.next(), nested.next()) {
            (Some(id), None) => FirstEvent::Found(id.to_string()),
            (None, _) => FirstEvent::NotFound("names no `id`"),
            (Some(_), Some(_)) => FirstEvent::NotFound("names more than one nested `id`"),
        };
    }
    FirstEvent::NeedMore
}

/// The cache's verdict on a set of IDs for one tenant.
#[derive(Debug, PartialEq, Eq)]
pub enum Cached {
    /// The tenant owns every ID.
    Owned,
    /// Another tenant owns at least one ID.
    NotOwned,
    /// No other tenant owns any of them, but these are not cached.
    Unknown(Vec<String>),
}

/// The answer to a store read: one owner per ID asked for, in order.
pub type LookupAnswer = Result<Vec<Option<TenantId>>, StoreError>;

enum Job {
    Claim {
        id: String,
        tenant: TenantId,
        ttl: Option<Duration>,
    },
    Lookup {
        ids: Vec<String>,
        reply: oneshot::Sender<LookupAnswer>,
    },
}

/// Rate-limited warnings for the owners thread and the filter.
#[derive(Default)]
pub(crate) struct Warn {
    last: Mutex<Option<Instant>>,
    suppressed: AtomicU64,
}

impl Warn {
    /// Calls `emit` with the number of warnings suppressed since the last
    /// one, at most once per [`WARN_EVERY`]; otherwise counts this one.
    pub(crate) fn emit(&self, emit: impl FnOnce(u64)) {
        let now = Instant::now();
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        if last.is_some_and(|at| now.saturating_duration_since(at) < WARN_EVERY) {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            return;
        }
        *last = Some(now);
        emit(self.suppressed.swap(0, Ordering::Relaxed));
    }
}

struct Shared {
    /// Owners with their expiry, so a cached owner stops counting when its
    /// store row does (ADR-0013 §6).
    cache: Mutex<HashMap<String, ObjectOwner>>,
    claim_failed: Warn,
    claim_conflict: Warn,
}

impl Shared {
    fn remember(&self, id: String, owner: ObjectOwner) {
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if cache.len() >= CACHE_CAP && !cache.contains_key(&id) {
            cache.clear();
        }
        cache.insert(id, owner);
    }
}

/// Owners of provider objects: a bounded cache in front of the store, and a
/// thread that makes every store call. See the module doc.
pub struct ObjectOwners {
    shared: Arc<Shared>,
    jobs: mpsc::SyncSender<Job>,
    queue_full: Warn,
    /// The filter's: a store read that failed or timed out.
    pub(crate) unavailable: Warn,
    /// The filter's: a create response the owner could not be read from.
    pub(crate) unrecorded: Warn,
}

impl ObjectOwners {
    /// Starts the owners thread, which exits once this value is dropped and
    /// its queue drains.
    pub fn new(store: Arc<dyn ControlPlaneStore>) -> Self {
        let shared = Arc::new(Shared {
            cache: Mutex::new(HashMap::new()),
            claim_failed: Warn::default(),
            claim_conflict: Warn::default(),
        });
        let (jobs, inbox) = mpsc::sync_channel(QUEUE_CAP);
        let thread_shared = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("object-owners".to_string())
            .spawn(move || run(&thread_shared, store.as_ref(), &inbox))
            .expect("spawning the object owners thread");
        ObjectOwners {
            shared,
            jobs,
            queue_full: Warn::default(),
            unavailable: Warn::default(),
            unrecorded: Warn::default(),
        }
    }

    /// What the cache knows about `ids` for `tenant`. Never touches the store.
    pub fn check_cached(&self, tenant: &str, ids: &[String]) -> Cached {
        let cache = self
            .shared
            .cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let now = unix_now_secs();
        let mut unknown = Vec::new();
        for id in ids {
            match cache.get(id).filter(|owner| owner.is_live(now)) {
                Some(owner) if owner.tenant.as_str() == tenant => {}
                Some(_) => return Cached::NotOwned,
                None => {
                    if !unknown.contains(id) {
                        unknown.push(id.clone());
                    }
                }
            }
        }
        if unknown.is_empty() {
            Cached::Owned
        } else {
            Cached::Unknown(unknown)
        }
    }

    /// Reads the owners of `ids` from the store on the owners thread. Never
    /// blocks: a full queue answers at once with an error.
    pub fn lookup(&self, ids: Vec<String>) -> oneshot::Receiver<LookupAnswer> {
        let (reply, answer) = oneshot::channel();
        if let Err(mpsc::TrySendError::Full(Job::Lookup { reply, .. })) =
            self.jobs.try_send(Job::Lookup { ids, reply })
        {
            let _ = reply.send(Err(StoreError::Unavailable(
                "object owner queue is full".into(),
            )));
        }
        answer
    }

    /// Records `tenant` as the owner of `id`, for `ttl` or for good: in the
    /// cache at once, so the next request on this replica sees it, and in
    /// the store on the owners thread. A live owner already cached is kept;
    /// the store's answer then settles it.
    pub fn record(&self, id: String, tenant: TenantId, ttl: Option<Duration>) {
        {
            let now = unix_now_secs();
            let mut cache = self
                .shared
                .cache
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if cache.len() >= CACHE_CAP && !cache.contains_key(&id) {
                cache.clear();
            }
            if !cache.get(&id).is_some_and(|owner| owner.is_live(now)) {
                cache.insert(id.clone(), ObjectOwner::new(tenant.clone(), ttl, now));
            }
        }
        if self.jobs.try_send(Job::Claim { id, tenant, ttl }).is_err() {
            self.queue_full.emit(|suppressed| {
                tracing::warn!(
                    suppressed,
                    "llmproxy.object_ownership: the owner queue is full, so a created object's \
                     owner was not stored; it stays reachable on this replica until restart and \
                     is refused everywhere else"
                );
            });
        }
    }
}

fn run(shared: &Shared, store: &dyn ControlPlaneStore, inbox: &mpsc::Receiver<Job>) {
    while let Ok(job) = inbox.recv() {
        match job {
            Job::Claim { id, tenant, ttl } => match store.claim_object(&id, &tenant, ttl) {
                Ok(owner) => {
                    if owner.tenant != tenant && owner.is_live(unix_now_secs()) {
                        shared.claim_conflict.emit(|suppressed| {
                            tracing::warn!(
                                creator = tenant.as_str(),
                                owner = owner.tenant.as_str(),
                                suppressed,
                                "llmproxy.object_ownership: a provider returned an object id \
                                 another tenant already owns; the existing owner is kept and \
                                 the creating tenant is refused"
                            );
                        });
                    }
                    shared.remember(id, owner);
                }
                Err(e) => shared.claim_failed.emit(|suppressed| {
                    tracing::warn!(
                        error = %e,
                        suppressed,
                        "llmproxy.object_ownership: a created object's owner could not be \
                         stored; it stays reachable on this replica until restart and is \
                         refused everywhere else"
                    );
                }),
            },
            Job::Lookup { ids, reply } => {
                let answer: LookupAnswer = ids
                    .into_iter()
                    .map(|id| match store.object_owner(&id) {
                        Ok(Some(owner)) => {
                            let tenant = owner.tenant.clone();
                            shared.remember(id, owner);
                            Ok(Some(tenant))
                        }
                        Ok(None) => Ok(None),
                        // An id the store could never hold has no owner.
                        Err(StoreError::InvalidInput(_)) => Ok(None),
                        Err(e) => Err(e),
                    })
                    .collect();
                let _ = reply.send(answer);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::InMemoryControlPlaneStore;

    fn collection(path: &str, endpoints: &[&str]) -> Collection {
        let endpoints: Vec<String> = endpoints.iter().map(|e| e.to_string()).collect();
        Collection::new(path, &endpoints, Record::Always, None).unwrap()
    }

    fn patterns(names: &[&str]) -> Vec<MemberPattern> {
        names
            .iter()
            .map(|n| MemberPattern::parse(n).unwrap())
            .collect()
    }

    /// The rules the files and batches configuration has: default members.
    fn file_rules() -> Rules {
        Rules::new(
            vec![
                collection("/v1/files", &[]),
                collection("/v1/batches", &[]),
                collection("/v1/messages/batches", &[]),
            ],
            vec![],
            vec![],
            vec![],
        )
        .unwrap()
    }

    #[test]
    fn paths_name_collections_and_objects_however_they_are_spelled() {
        let c = file_rules();
        let object = |id: &str| PathTarget::Object(id.to_string());
        for (path, want) in [
            ("/v1/files", PathTarget::Collection(0)),
            ("/v1/files/", PathTarget::Collection(0)),
            ("/v1/files/file-1", object("file-1")),
            ("/v1/files/file-1/content", object("file-1")),
            ("/v1/batches/b1/cancel", object("b1")),
            ("/v1/messages/batches/mb1/results", object("mb1")),
            ("/v1/messages/batches", PathTarget::Collection(2)),
            // Encodings, dot segments, doubled and back slashes, and case.
            ("/v1/%66iles/file-1", object("file-1")),
            ("/v1/files%2Ffile-1", object("file-1")),
            ("/v1//files/./file-1", object("file-1")),
            ("/v1/x/../files/file-1", object("file-1")),
            ("/v1\\files\\file-1", object("file-1")),
            ("/V1/Files/file-1", object("file-1")),
            // A prefix a route strips before dialling.
            ("/openai/v1/files/file-1", object("file-1")),
            // The ID keeps its case and is decoded.
            ("/v1/files/File%2D1", object("File-1")),
            // Not a collection.
            ("/v1/chat/completions", PathTarget::None),
            ("/v1/filesx/file-1", PathTarget::None),
            ("/v1/messages", PathTarget::None),
        ] {
            assert_eq!(c.classify(path), want, "{path}");
        }
    }

    /// An endpoint segment under a collection is not an ID, however it is
    /// spelled; and at the same start the longer collection wins whatever
    /// the configured order.
    #[test]
    fn endpoints_are_not_ids_and_the_longer_collection_wins() {
        let rules = Rules::new(
            vec![
                collection("/v1/chat", &[]),
                collection("/v1/threads", &["runs"]),
                collection("/v1/chat/completions", &[]),
            ],
            vec![],
            vec![],
            vec![],
        )
        .unwrap();
        for (path, want) in [
            ("/v1/threads/runs", PathTarget::Endpoint(1)),
            ("/v1/threads/RUNS", PathTarget::Endpoint(1)),
            ("/v1/threads/%72uns", PathTarget::Endpoint(1)),
            (
                "/v1/threads/thread_1/runs",
                PathTarget::Object("thread_1".into()),
            ),
            ("/v1/chat/completions", PathTarget::Collection(2)),
            ("/v1/chat/completions/c1", PathTarget::Object("c1".into())),
            ("/v1/chat/other", PathTarget::Object("other".into())),
        ] {
            assert_eq!(rules.classify(path), want, "{path}");
        }
    }

    #[test]
    fn collection_paths_and_members_are_validated() {
        let bad = |p: &str| Collection::new(p, &[], Record::Always, None).is_err();
        for p in [
            "v1/files",
            "/",
            "/v1/files/",
            "/v1/*",
            "/v1//files",
            "/v1/./files",
            "/v1/%66",
        ] {
            assert!(bad(p), "{p}");
        }
        assert!(!bad("/v1/files"));
        for e in ["", "a/b", "..", "*"] {
            assert!(
                Collection::new("/v1/threads", &[e.to_string()], Record::Always, None).is_err(),
                "{e:?}"
            );
        }
        assert!(Rules::new(vec![], vec![], vec![], vec![]).is_err());
        assert!(Rules::new(
            vec![collection("/v1/files", &[]), collection("/V1/Files", &[])],
            vec![],
            vec![],
            vec![]
        )
        .is_err());
        for m in ["", "*", "a.b", "**x", "a*b"] {
            assert!(MemberPattern::parse(m).is_err(), "{m:?}");
        }
        for m in ["a.b.c", "a.", "a.*b"] {
            assert!(OwnedMember::parse(m).is_err(), "{m:?}");
        }
    }

    #[test]
    fn body_references_are_found_at_any_depth_and_in_duplicates() {
        let rules = file_rules();
        let ids = |body: &str| rules.references(body.as_bytes());
        let found = |v: &[&str]| BodyReferences::Ids(v.iter().map(|s| s.to_string()).collect());
        assert_eq!(
            ids(r#"{"input_file_id":"f1","endpoint":"/v1/chat/completions"}"#),
            found(&["f1"])
        );
        assert_eq!(
            ids(r#"{"messages":[{"content":[{"type":"file","file":{"file_id":"f2"}}]}]}"#),
            found(&["f2"])
        );
        assert_eq!(
            ids(r#"{"input_file_id":"mine","input_file_id":"theirs"}"#),
            found(&["mine", "theirs"])
        );
        assert_eq!(
            ids(r#"{"file_ids":["a","b"],"x":{"vector_file_ids":["c"]}}"#),
            found(&["a", "b", "c"])
        );
        // An escaped member name is still the member name.
        assert_eq!(ids(r#"{"file_id":"f3"}"#), found(&["f3"]));
        // Other members, and non-string values, are not references.
        assert_eq!(ids(r#"{"file_id_note":"x","file_id":7}"#), found(&[]));
        assert_eq!(ids(r#"{"model":"m","messages":[]}"#), BodyReferences::None);
        assert_eq!(ids("purpose=batch&file_id=x"), BodyReferences::None);
        assert_eq!(ids(r#"{"file_id":"f4""#), BodyReferences::Unparseable);
    }

    /// Configured reference members: by name and suffix; a string, each
    /// string of an array, and the `id` of an object; never inside an opaque
    /// member; and an object without `id` names nothing.
    #[test]
    fn configured_reference_members_name_objects_in_every_value_shape() {
        let rules = Rules::new(
            vec![collection("/v1/responses", &[])],
            patterns(&["previous_response_id", "conversation", "container", "*_ids"]),
            vec![],
            vec!["metadata".into()],
        )
        .unwrap();
        let ids = |body: &str| rules.references(body.as_bytes());
        let found = |v: &[&str]| BodyReferences::Ids(v.iter().map(|s| s.to_string()).collect());
        assert_eq!(
            ids(r#"{"previous_response_id":"r1","conversation":{"id":"c1"}}"#),
            found(&["r1", "c1"])
        );
        assert_eq!(
            ids(r#"{"tools":[{"type":"file_search","vector_store_ids":["v1","v2"]}]}"#),
            found(&["v1", "v2"])
        );
        assert_eq!(
            ids(r#"{"tools":[{"container":{"type":"auto"}},{"container":"k1"}]}"#),
            found(&["k1"])
        );
        assert_eq!(
            ids(r#"{"metadata":{"conversation":"mine","x_ids":["y"]},"input":"hi"}"#),
            found(&[])
        );
        assert_eq!(
            ids(r#"{"conversation":"c2","conversation":"c3"}"#),
            found(&["c2", "c3"])
        );
    }

    #[test]
    fn a_response_names_the_created_id_and_its_owned_members() {
        let rules = file_rules();
        let body =
            br#"{"id":"batch_1","input_file_id":"f1","output_file_id":"f2","error_file_id":null}"#;
        let files = vec!["f1".to_string(), "f2".to_string()];
        assert_eq!(
            rules.owned_by_response(body, true),
            Some(ResponseOwned {
                created: Some("batch_1".into()),
                files: files.clone()
            })
        );
        assert_eq!(
            rules.owned_by_response(body, false),
            Some(ResponseOwned {
                created: None,
                files
            })
        );
        assert_eq!(rules.owned_by_response(b"[1]", true), None);

        let nested = Rules::new(
            vec![collection("/v1/uploads", &[])],
            vec![],
            ["file.id", "result_files", "thread_id"]
                .iter()
                .map(|m| OwnedMember::parse(m).unwrap())
                .collect(),
            vec![],
        )
        .unwrap();
        let body = br#"{"id":"up_1","file":{"id":"f9"},"result_files":["f7"],"thread_id":"t1","assistant_id":"a1"}"#;
        assert_eq!(
            nested.owned_by_response(body, true),
            Some(ResponseOwned {
                created: Some("up_1".into()),
                files: vec!["f9".into(), "f7".into(), "t1".into()]
            })
        );
    }

    #[test]
    fn the_first_event_with_json_names_the_created_id() {
        let first = |s: &str| created_in_first_event(s.as_bytes());
        let found = |id: &str| FirstEvent::Found(id.to_string());
        assert_eq!(
            first("data: {\"id\":\"chatcmpl-1\",\"choices\":[]}\n\n"),
            found("chatcmpl-1")
        );
        assert_eq!(
            first(
                "event: response.created\r\ndata: {\"type\":\"response.created\",\r\ndata: \"response\":{\"id\":\"resp_1\"}}\r\n\r\n"
            ),
            found("resp_1")
        );
        assert_eq!(
            first(": keep-alive\n\ndata: {\"id\":\"x\"}\n\n"),
            found("x")
        );
        assert_eq!(first("data: {\"id\":\"x\"}"), FirstEvent::NeedMore);
        assert!(matches!(
            first("data: {\"type\":\"t\"}\n\ndata: {\"id\":\"late\"}\n\n"),
            FirstEvent::NotFound(_)
        ));
        assert!(matches!(
            first("data: {\"a\":{\"id\":\"1\"},\"b\":{\"id\":\"2\"}}\n\n"),
            FirstEvent::NotFound(_)
        ));
    }

    /// Recording reads the top-level member; every duplicate counts, an
    /// absent member takes the rule's side, and a body that does not parse
    /// is recorded.
    #[test]
    fn a_create_is_recorded_by_its_rule() {
        let if_true = Record::IfTrue("store".into());
        let unless_false = Record::UnlessFalse("store".into());
        let r = |rule: &Record, body: &str| records(rule, Some(body.as_bytes()));
        assert!(records(&Record::Always, None));
        assert!(r(&if_true, r#"{"store":true}"#));
        assert!(!r(&if_true, r#"{"store":false}"#));
        assert!(!r(&if_true, r#"{"model":"m"}"#));
        assert!(!r(&if_true, r#"{"metadata":{"store":true}}"#));
        assert!(r(&if_true, r#"{"store":false,"store":true}"#));
        assert!(r(&if_true, r#"{"store":true}"#));
        assert!(r(&if_true, r#"{"store":tru"#));
        assert!(!records(&if_true, None));
        assert!(r(&unless_false, r#"{"model":"m"}"#));
        assert!(!r(&unless_false, r#"{"store":false}"#));
        assert!(r(&unless_false, r#"{"store":"false"}"#));
        assert!(r(&unless_false, r#"{"store":false,"store":true}"#));
        assert!(records(&unless_false, None));
    }

    fn wait(rx: oneshot::Receiver<LookupAnswer>) -> LookupAnswer {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(10), rx)
                    .await
                    .expect("lookup answered")
                    .expect("owners thread alive")
            })
    }

    #[test]
    fn a_recorded_owner_is_cached_at_once_and_reaches_the_store() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        let owners = ObjectOwners::new(store.clone());
        owners.record("file-1".into(), TenantId::new("a"), None);
        assert_eq!(owners.check_cached("a", &["file-1".into()]), Cached::Owned);
        assert_eq!(
            owners.check_cached("b", &["file-1".into()]),
            Cached::NotOwned
        );

        // The store write is asynchronous; a read through the same queue is
        // ordered after it.
        let answer = wait(owners.lookup(vec!["file-1".into()])).unwrap();
        assert_eq!(answer, vec![Some(TenantId::new("a"))]);
        assert_eq!(
            store.object_owner("file-1").unwrap().map(|o| o.tenant),
            Some(TenantId::new("a"))
        );
    }

    #[test]
    fn another_replicas_owner_is_read_from_the_store_and_cached() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        store
            .claim_object("file-9", &TenantId::new("a"), None)
            .unwrap();
        let owners = ObjectOwners::new(store);
        assert_eq!(
            owners.check_cached("a", &["file-9".into(), "file-x".into()]),
            Cached::Unknown(vec!["file-9".into(), "file-x".into()])
        );
        let answer = wait(owners.lookup(vec!["file-9".into(), "file-x".into()])).unwrap();
        assert_eq!(answer, vec![Some(TenantId::new("a")), None]);
        assert_eq!(owners.check_cached("a", &["file-9".into()]), Cached::Owned);
        assert_eq!(
            owners.check_cached("a", &["file-x".into()]),
            Cached::Unknown(vec!["file-x".into()]),
            "an unknown id is not cached as anything"
        );
    }

    /// A cached owner stops counting when its row expires: the next request
    /// reads the store, which has no live owner either, so the object is
    /// refused rather than served from the cache.
    #[test]
    fn an_expired_cached_owner_is_unknown_not_owned() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        let owners = ObjectOwners::new(store);
        owners.record("resp-1".into(), TenantId::new("a"), Some(Duration::ZERO));
        assert_eq!(
            owners.check_cached("a", &["resp-1".into()]),
            Cached::Unknown(vec!["resp-1".into()])
        );
        assert_eq!(
            wait(owners.lookup(vec!["resp-1".into()])).unwrap(),
            vec![None]
        );
        owners.record(
            "resp-2".into(),
            TenantId::new("a"),
            Some(Duration::from_secs(3600)),
        );
        assert_eq!(owners.check_cached("a", &["resp-2".into()]), Cached::Owned);
    }

    /// A claim the store settles for an earlier owner corrects this
    /// replica's cache: the store wins.
    #[test]
    fn the_stores_earlier_owner_wins_over_a_local_record() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        store
            .claim_object("file-1", &TenantId::new("a"), None)
            .unwrap();
        let owners = ObjectOwners::new(store);
        owners.record("file-1".into(), TenantId::new("b"), None);
        let answer = wait(owners.lookup(vec!["file-1".into()])).unwrap();
        assert_eq!(answer, vec![Some(TenantId::new("a"))]);
        assert_eq!(
            owners.check_cached("b", &["file-1".into()]),
            Cached::NotOwned
        );
    }

    /// A store that cannot answer is an error the filter turns into a 503,
    /// never "no owner". `ProbeStore` keeps the trait's refusing default.
    #[test]
    fn a_failing_store_is_an_error_not_an_absent_owner() {
        let owners = ObjectOwners::new(Arc::new(
            crate::window_usage::test_store::ProbeStore::default(),
        ));
        assert!(wait(owners.lookup(vec!["file-1".into()])).is_err());
    }
}
