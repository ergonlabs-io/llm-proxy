//! Tenant ownership of provider objects (files, batches): the parts that do
//! not touch a stream. [`crate::object_ownership_filter`] applies them.
//!
//! A provider issues object IDs in one namespace per provider account, and
//! every tenant reaches the provider through the proxy's account. A tenant
//! that learns another tenant's ID could otherwise read, cancel or delete
//! that object, or feed it to a model, through the proxy. The proxy records
//! which tenant created each object and refuses everyone else.
//!
//! # What names an object
//!
//! - A request path that contains a configured collection's segments,
//!   contiguous and in order, followed by one more segment: that segment is
//!   the ID, and anything after it (`/content`, `/cancel`) is the same
//!   object. Matching runs on the path after percent-decoding and resolving
//!   `.` and `..` segments, so an encoded or dotted path cannot slip past it.
//!   It matches anywhere in the path, so a prefix that a route strips
//!   before dialling cannot hide a collection either.
//! - In a JSON request body, the string value of any member named `file_id`
//!   or ending in `_file_id`, and every string in an array member named
//!   `file_ids` or ending in `_file_ids`, at any depth. Duplicate members
//!   are all checked, since a provider's parser may keep either one.
//!
//! # Unknown IDs
//!
//! An ID no tenant owns (created before ownership was recorded, or outside
//! the proxy) is refused exactly like another tenant's: unset never means
//! open (AGENTS.md "Fail-open controls"). An operator assigns such an object
//! to its tenant through the admin API.
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

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use tokio::sync::oneshot;

use crate::auth::TenantId;
use crate::control::{ControlPlaneStore, StoreError};

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

/// The configured object collections, each as its lowercased path segments.
#[derive(Debug, Clone)]
pub struct Collections(Vec<Vec<String>>);

/// What a request path names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathTarget {
    /// No collection.
    None,
    /// A collection itself: a POST creates, anything else lists.
    Collection,
    /// One object in a collection, by ID.
    Object(String),
}

impl Collections {
    /// Validates each collection path. The error names the offending index
    /// and why.
    pub fn parse(paths: &[String]) -> Result<Self, (usize, String)> {
        if paths.is_empty() {
            return Err((0, "at least one collection is required".into()));
        }
        let mut out = Vec::with_capacity(paths.len());
        for (i, path) in paths.iter().enumerate() {
            let Some(rest) = path.strip_prefix('/') else {
                return Err((i, format!("{path:?} must start with '/'")));
            };
            if rest.is_empty() || rest.ends_with('/') {
                return Err((i, format!("{path:?} must name a path and not end with '/'")));
            }
            if path.contains(['*', '?', '%', '\\']) {
                return Err((
                    i,
                    format!("{path:?} must not contain '*', '?', '%' or '\\'"),
                ));
            }
            let segments: Vec<String> = rest.split('/').map(str::to_ascii_lowercase).collect();
            if segments
                .iter()
                .any(|s| s.is_empty() || s == "." || s == "..")
            {
                return Err((
                    i,
                    format!("{path:?} must not contain an empty, '.' or '..' segment"),
                ));
            }
            out.push(segments);
        }
        Ok(Collections(out))
    }

    /// What `raw_path` (the request target's path, without the query) names.
    /// See the module doc for the matching rule.
    pub fn classify(&self, raw_path: &str) -> PathTarget {
        let segments = normalized_segments(raw_path);
        let lowered: Vec<String> = segments.iter().map(|s| s.to_ascii_lowercase()).collect();
        // The earliest match in the path wins, so a collection named inside
        // another object's ID cannot be preferred over the real one.
        let mut best: Option<(usize, usize)> = None;
        for collection in &self.0 {
            let n = collection.len();
            if let Some(start) = lowered.windows(n).position(|w| w == collection.as_slice()) {
                if best.is_none_or(|(s, _)| start < s) {
                    best = Some((start, n));
                }
            }
        }
        match best {
            None => PathTarget::None,
            Some((start, n)) => match segments.get(start + n) {
                None => PathTarget::Collection,
                Some(id) => PathTarget::Object(id.clone()),
            },
        }
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

/// Whether a JSON member name references a file, or a list of files.
fn reference_key(key: &str) -> Reference {
    if key == "file_id" || key.ends_with("_file_id") {
        Reference::One
    } else if key == "file_ids" || key.ends_with("_file_ids") {
        Reference::Many
    } else {
        Reference::No
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Reference {
    No,
    One,
    Many,
}

/// The file IDs a request body references.
#[derive(Debug, PartialEq, Eq)]
pub enum BodyReferences {
    /// The body cannot reference a file: it is not JSON, or no member name
    /// could spell one.
    None,
    /// Every referenced ID, duplicates included.
    Ids(Vec<String>),
    /// The body may spell a reference but does not parse as JSON. The
    /// provider's parser may still accept it, so it is refused, not passed.
    Unparseable,
}

/// See the module doc. A body is parsed only when its bytes could spell a
/// reference member: the literal `file_id`, or a `\u` escape that could
/// spell it without the literal. Anything else passes without a parse.
pub fn file_references(body: &[u8]) -> BodyReferences {
    let first = body.iter().find(|b| !b.is_ascii_whitespace());
    if !matches!(first, Some(b'{') | Some(b'[')) {
        return BodyReferences::None;
    }
    let could_spell = |needle: &[u8]| body.windows(needle.len()).any(|w| w == needle);
    if !could_spell(b"file_id") && !could_spell(b"\\u") {
        return BodyReferences::None;
    }
    let mut found = Vec::new();
    let mut de = serde_json::Deserializer::from_slice(body);
    let walked = Walk {
        found: &mut found,
        collect: Reference::No,
    }
    .deserialize(&mut de)
    .and_then(|()| de.end());
    match walked {
        Ok(()) => BodyReferences::Ids(found),
        Err(_) => BodyReferences::Unparseable,
    }
}

/// Walks a JSON document without building it, collecting reference values.
///
/// Rust note: a `DeserializeSeed` rather than `serde_json::Value`, because
/// `Value` keeps only the last of two members with the same name, and the
/// provider may keep the first.
struct Walk<'a> {
    found: &'a mut Vec<String>,
    /// How the member this value belongs to references files.
    collect: Reference,
}

impl<'de> DeserializeSeed<'de> for Walk<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<(), D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Walk<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_str<E>(self, v: &str) -> Result<(), E> {
        if self.collect != Reference::No {
            self.found.push(v.to_string());
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        // Strings directly in a `*_file_ids` array are references; an
        // element that is itself an object starts over by member name.
        let collect = if self.collect == Reference::Many {
            Reference::One
        } else {
            Reference::No
        };
        while seq
            .next_element_seed(Walk {
                found: self.found,
                collect,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
            map.next_value_seed(Walk {
                found: self.found,
                collect: reference_key(&key),
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

/// What a 2xx JSON response body says the caller now owns.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ResponseOwned {
    /// The top-level `id`, read only from a create's response.
    pub created: Option<String>,
    /// The files the top-level reference members name: a batch's
    /// `output_file_id` appears only once the batch completes, and the
    /// provider created that file for the batch's owner.
    pub files: Vec<String>,
}

/// See [`ResponseOwned`]. `None` when the body is not a JSON object.
pub fn owned_by_response(body: &[u8], created: bool) -> Option<ResponseOwned> {
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
        match (reference_key(key), value) {
            (Reference::One, serde_json::Value::String(id)) => owned.files.push(id.clone()),
            (Reference::Many, serde_json::Value::Array(items)) => owned
                .files
                .extend(items.iter().filter_map(|v| v.as_str().map(str::to_string))),
            _ => {}
        }
    }
    Some(owned)
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
    cache: Mutex<HashMap<String, TenantId>>,
    claim_failed: Warn,
    claim_conflict: Warn,
}

impl Shared {
    fn remember(&self, id: String, tenant: TenantId) {
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if cache.len() >= CACHE_CAP && !cache.contains_key(&id) {
            cache.clear();
        }
        cache.insert(id, tenant);
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
        let mut unknown = Vec::new();
        for id in ids {
            match cache.get(id) {
                Some(owner) if owner.as_str() == tenant => {}
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

    /// Records `tenant` as the owner of `id`: in the cache at once, so the
    /// next request on this replica sees it, and in the store on the owners
    /// thread. An owner already cached is kept; the store's answer then
    /// settles it.
    pub fn record(&self, id: String, tenant: TenantId) {
        {
            let mut cache = self
                .shared
                .cache
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if cache.len() >= CACHE_CAP && !cache.contains_key(&id) {
                cache.clear();
            }
            cache.entry(id.clone()).or_insert_with(|| tenant.clone());
        }
        if self.jobs.try_send(Job::Claim { id, tenant }).is_err() {
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
            Job::Claim { id, tenant } => match store.claim_object(&id, &tenant) {
                Ok(owner) => {
                    if owner != tenant {
                        shared.claim_conflict.emit(|suppressed| {
                            tracing::warn!(
                                creator = tenant.as_str(),
                                owner = owner.as_str(),
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
                            shared.remember(id, owner.clone());
                            Ok(Some(owner))
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

    fn collections() -> Collections {
        Collections::parse(&[
            "/v1/files".to_string(),
            "/v1/batches".to_string(),
            "/v1/messages/batches".to_string(),
        ])
        .unwrap()
    }

    #[test]
    fn paths_name_collections_and_objects_however_they_are_spelled() {
        let c = collections();
        let object = |id: &str| PathTarget::Object(id.to_string());
        for (path, want) in [
            ("/v1/files", PathTarget::Collection),
            ("/v1/files/", PathTarget::Collection),
            ("/v1/files/file-1", object("file-1")),
            ("/v1/files/file-1/content", object("file-1")),
            ("/v1/batches/b1/cancel", object("b1")),
            ("/v1/messages/batches/mb1/results", object("mb1")),
            ("/v1/messages/batches", PathTarget::Collection),
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

    #[test]
    fn collection_paths_are_validated() {
        let bad = |p: &str| Collections::parse(&[p.to_string()]).is_err();
        assert!(Collections::parse(&[]).is_err());
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
    }

    #[test]
    fn body_references_are_found_at_any_depth_and_in_duplicates() {
        let ids = |body: &str| file_references(body.as_bytes());
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

    #[test]
    fn a_response_names_the_created_id_and_its_file_references() {
        let body =
            br#"{"id":"batch_1","input_file_id":"f1","output_file_id":"f2","error_file_id":null}"#;
        let files = vec!["f1".to_string(), "f2".to_string()];
        assert_eq!(
            owned_by_response(body, true),
            Some(ResponseOwned {
                created: Some("batch_1".into()),
                files: files.clone()
            })
        );
        assert_eq!(
            owned_by_response(body, false),
            Some(ResponseOwned {
                created: None,
                files
            })
        );
        assert_eq!(owned_by_response(b"[1]", true), None);
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
        owners.record("file-1".into(), TenantId::new("a"));
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
            store.object_owner("file-1").unwrap(),
            Some(TenantId::new("a"))
        );
    }

    #[test]
    fn another_replicas_owner_is_read_from_the_store_and_cached() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        store.claim_object("file-9", &TenantId::new("a")).unwrap();
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

    /// A claim the store settles for an earlier owner corrects this
    /// replica's cache: the store wins.
    #[test]
    fn the_stores_earlier_owner_wins_over_a_local_record() {
        let store = Arc::new(InMemoryControlPlaneStore::default());
        store.claim_object("file-1", &TenantId::new("a")).unwrap();
        let owners = ObjectOwners::new(store);
        owners.record("file-1".into(), TenantId::new("b"));
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
