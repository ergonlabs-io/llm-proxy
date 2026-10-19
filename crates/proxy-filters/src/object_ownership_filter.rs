//! `llmproxy.object_ownership`: refuses a request that names a provider
//! object the caller's tenant does not own, before the upstream is dialled,
//! and records the owner of every object a tenant creates. What names an
//! object, and where owners live, is in [`crate::object_ownership`]'s module
//! doc.
//!
//! # Decisions
//!
//! - A path naming an object: the caller's tenant must own it.
//! - A collection's own path, or an endpoint under it: a POST creates. Any
//!   other method on the collection lists the provider account every tenant
//!   shares, so it is refused; on an endpoint it names no object.
//! - A JSON request body that references objects: the tenant must own every
//!   one. A body that could spell a reference but does not parse is refused
//!   with 400, since the provider's parser may still accept it.
//! - No authenticated tenant on any of these: refused.
//!
//! A refusal is the same 404 whether another tenant owns the object or none
//! does, so the response does not reveal that an ID exists. An ID no tenant
//! owns is refused, never passed (AGENTS.md "Fail-open controls"). When the
//! store cannot answer, the request gets 503 and a warning with repeats
//! suppressed: this control fails closed. A cache miss holds the request on
//! an off-worker store read (ADR-0012).
//!
//! # Recording
//!
//! A 2xx JSON response to a create records its top-level `id` for the
//! caller's tenant, for the collection's owner TTL; a `text/event-stream`
//! response records the ID its first event names, as soon as that event has
//! arrived. A create is recorded only when the collection's record rule
//! says so (`store: true`, for example). A 2xx JSON response to a create or
//! to an owned object also records the objects its owned members name, for
//! good. The response is never held: it streams through, and the owner
//! enters this replica's cache as the body ends (or the first event does),
//! before the stream completes. The store write follows on the owners
//! thread.

use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::{Method, StatusCode};
use prost_reflect::DynamicMessage;
use proxy_config::ConfigError;
use proxy_http::filter::{
    DecoderCallbacks, EncoderCallbacks, FactoryContext, FilterDataStatus, FilterHeadersStatus,
    FilterInstanceFactory, FilterTrailersStatus, HttpFilter, HttpFilterFactory, RequestHeaders,
    ResponseHeaders, ResponseTrailers,
};
use tokio::sync::oneshot;

use crate::auth::TenantId;
use crate::auth_filter;
use crate::control::ControlPlane;
use crate::object_ownership::{
    created_in_first_event, records, BodyReferences, Cached, Collection, FirstEvent, LookupAnswer,
    MemberPattern, ObjectOwners, OwnedMember, PathTarget, Record, Rules, MAX_FIRST_EVENT_BYTES,
};

/// Type URL this filter is registered under.
pub const TYPE_URL: &str = "type.llmproxy.dev/llmproxy.filters.v0.ObjectOwnership";

const DENY_DETAILS: &str = "object_not_owned";
const UNAVAILABLE_DETAILS: &str = "object_owner_unavailable";
const UNPARSEABLE_DETAILS: &str = "object_reference_unparseable";

/// How long a request waits for a store read before it gets 503.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

/// Most response bytes read for owners. Object responses are small; a larger
/// one is passed through unread.
const MAX_RESPONSE_BYTES: usize = 1 << 20;

fn invalid(field_path: impl Into<String>, reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue {
        field_path: field_path.into(),
        reason: reason.into(),
    }
}

fn strings(config: &DynamicMessage, field: &str) -> Vec<String> {
    config
        .get_field_by_name(field)
        .and_then(|v| {
            v.as_list().map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
        })
        .unwrap_or_default()
}

fn parse_collection(item: &DynamicMessage, at: &str) -> Result<Collection, ConfigError> {
    let path = item
        .get_field_by_name("path")
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    let member = item
        .get_field_by_name("record_member")
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    let number = item
        .get_field_by_name("record")
        .and_then(|v| v.as_enum_number())
        .unwrap_or(0);
    let record = match (number, member.is_empty()) {
        (0, true) => Record::Always,
        (1, false) => Record::IfTrue(member),
        (2, false) => Record::UnlessFalse(member),
        (0, false) => {
            return Err(invalid(
                format!("{at}.record_member"),
                "is only read by RECORD_IF_TRUE and RECORD_UNLESS_FALSE",
            ))
        }
        (1 | 2, true) => {
            return Err(invalid(
                format!("{at}.record_member"),
                "is required by RECORD_IF_TRUE and RECORD_UNLESS_FALSE",
            ))
        }
        (other, _) => {
            return Err(invalid(
                format!("{at}.record"),
                format!(
                    "unknown value {other}; expected ALWAYS, RECORD_IF_TRUE or RECORD_UNLESS_FALSE"
                ),
            ))
        }
    };
    let ttl = item
        .get_field_by_name("owner_ttl_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let ttl = (ttl > 0).then(|| Duration::from_secs(ttl));
    Collection::new(&path, &strings(item, "endpoints"), record, ttl)
        .map_err(|reason| invalid(at, reason))
}

/// Reads `typed_config`. Every error names the offending field.
pub fn parse_config(config: &DynamicMessage) -> Result<Rules, ConfigError> {
    let mut collections = Vec::new();
    for (i, path) in strings(config, "collections").iter().enumerate() {
        collections.push(
            Collection::new(path, &[], Record::Always, None)
                .map_err(|reason| invalid(format!("typed_config.collections[{i}]"), reason))?,
        );
    }
    let detailed = config
        .get_field_by_name("collection")
        .and_then(|v| {
            v.as_list().map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_message().cloned())
                    .collect::<Vec<_>>()
            })
        })
        .unwrap_or_default();
    for (i, item) in detailed.iter().enumerate() {
        collections.push(parse_collection(
            item,
            &format!("typed_config.collection[{i}]"),
        )?);
    }
    let mut references = Vec::new();
    for (i, name) in strings(config, "reference_members").iter().enumerate() {
        references.push(
            MemberPattern::parse(name).map_err(|reason| {
                invalid(format!("typed_config.reference_members[{i}]"), reason)
            })?,
        );
    }
    let mut owned = Vec::new();
    for (i, path) in strings(config, "owned_members").iter().enumerate() {
        owned.push(
            OwnedMember::parse(path)
                .map_err(|reason| invalid(format!("typed_config.owned_members[{i}]"), reason))?,
        );
    }
    let opaque = strings(config, "opaque_members");
    for (i, name) in opaque.iter().enumerate() {
        if name.is_empty() || name.contains(['*', '.']) {
            return Err(invalid(
                format!("typed_config.opaque_members[{i}]"),
                format!("{name:?} must be a member name, without '*' or '.'"),
            ));
        }
    }
    Rules::new(collections, references, owned, opaque)
        .map_err(|reason| invalid("typed_config", reason))
}

/// [`HttpFilterFactory`] for [`TYPE_URL`].
#[derive(Default)]
pub struct ObjectOwnershipFilterFactory;

impl HttpFilterFactory for ObjectOwnershipFilterFactory {
    fn type_url(&self) -> &'static str {
        TYPE_URL
    }

    /// The response is read as it streams through, never held.
    fn may_buffer_response(&self) -> bool {
        false
    }

    fn create(
        &self,
        config: &DynamicMessage,
        ctx: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, ConfigError> {
        let rules = Arc::new(parse_config(config)?);
        // Owners live in the store the auth filter's `ControlPlane` holds,
        // so this filter needs `llmproxy.auth` earlier in the same chain.
        let control_plane = ctx
            .get(auth_filter::TYPE_URL)
            .ok_or_else(|| {
                invalid(
                    "typed_config",
                    "llmproxy.object_ownership requires llmproxy.auth earlier in the same \
                     filter chain -- the owners live in its control-plane store",
                )
            })?
            .downcast::<ControlPlane>()
            .expect(
                "the control-plane singleton registered under auth_filter::TYPE_URL \
                 is always a ControlPlane",
            );
        // One owners cache and thread per chain, shared by every worker:
        // `create` runs once per worker and the first call builds it. Keyed
        // by `TYPE_URL`, so it is also the marker the admin API looks for.
        let owners = ctx
            .get_or_try_init(TYPE_URL, || {
                Ok(Arc::new(ObjectOwners::new(control_plane.store()))
                    as Arc<dyn std::any::Any + Send + Sync>)
            })?
            .downcast::<ObjectOwners>()
            .map_err(|_| invalid("typed_config", "object ownership state type collision"))?;
        Ok(Box::new(ObjectOwnershipInstanceFactory { owners, rules }))
    }
}

struct ObjectOwnershipInstanceFactory {
    owners: Arc<ObjectOwners>,
    rules: Arc<Rules>,
}

impl FilterInstanceFactory for ObjectOwnershipInstanceFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(ObjectOwnershipFilter {
            owners: Arc::clone(&self.owners),
            rules: Arc::clone(&self.rules),
            started: false,
            tenant: None,
            target: PathTarget::None,
            create: None,
            record: false,
            path_owned: false,
            body_done: false,
            lookup: Lookup::Idle,
            response: None,
        })
    }
}

/// A store read for owners the cache did not know.
enum Lookup {
    Idle,
    /// Sent to the owners thread; [`HttpFilter::poll_pending`] waits for it.
    Waiting(oneshot::Receiver<LookupAnswer>),
    /// The answer, applied when the filter manager calls the held callback
    /// again. `Err` carries why the store could not answer.
    Answered(Result<Vec<Option<TenantId>>, String>),
}

/// What one ownership check decided.
enum Step {
    /// The tenant owns every ID: continue.
    Owned,
    /// A local reply has been sent.
    Refused,
    /// A store read is in flight: hold the callback.
    Hold,
}

/// A response body being read for owners.
enum Capture {
    /// A JSON body, read whole.
    Json { buf: BytesMut, overflowed: bool },
    /// An event stream, read until its first event names the created ID.
    Events(BytesMut),
}

/// Per-stream instance.
struct ObjectOwnershipFilter {
    owners: Arc<ObjectOwners>,
    rules: Arc<Rules>,
    /// `decode_headers` has classified the request. It is called again after
    /// a held lookup, and must not classify twice.
    started: bool,
    tenant: Option<String>,
    target: PathTarget,
    /// A POST to a collection or an endpoint under it: the collection.
    create: Option<usize>,
    /// The create is recorded, by its collection's record rule.
    record: bool,
    /// The path names an object the tenant owns.
    path_owned: bool,
    /// The request body has been checked.
    body_done: bool,
    lookup: Lookup,
    response: Option<Capture>,
}

impl ObjectOwnershipFilter {
    /// Decides whether the tenant owns every one of `ids`: from the answer
    /// of a lookup this filter held for, else from the cache, else by
    /// starting a lookup.
    fn authorize(&mut self, cb: &mut dyn DecoderCallbacks, ids: &[String]) -> Step {
        let tenant = self.tenant.clone();
        if let Lookup::Answered(answer) = std::mem::replace(&mut self.lookup, Lookup::Idle) {
            return match answer {
                Ok(owners) => {
                    let owned = owners.iter().all(|owner| {
                        owner.as_ref().map(TenantId::as_str) == tenant.as_deref()
                            && tenant.is_some()
                    });
                    if owned {
                        Step::Owned
                    } else {
                        deny(cb);
                        Step::Refused
                    }
                }
                Err(reason) => {
                    self.owners.unavailable.emit(|suppressed| {
                        tracing::warn!(
                            reason = reason.as_str(),
                            suppressed,
                            "llmproxy.object_ownership: object owners could not be read, so \
                             requests naming uncached objects are refused with 503"
                        );
                    });
                    cb.send_local_reply(
                        StatusCode::SERVICE_UNAVAILABLE,
                        r#"{"error":{"message":"object ownership is unavailable"}}"#,
                        Some(json_content_type()),
                        UNAVAILABLE_DETAILS,
                    );
                    Step::Refused
                }
            };
        }
        let Some(tenant) = tenant else {
            deny(cb);
            return Step::Refused;
        };
        match self.owners.check_cached(&tenant, ids) {
            Cached::Owned => Step::Owned,
            Cached::NotOwned => {
                deny(cb);
                Step::Refused
            }
            Cached::Unknown(unknown) => {
                self.lookup = Lookup::Waiting(self.owners.lookup(unknown));
                Step::Hold
            }
        }
    }

    /// The owner TTL of the collection a create is in.
    fn created_ttl(&self) -> Option<Duration> {
        self.create
            .and_then(|index| self.rules.collection(index).owner_ttl)
    }

    fn record(&self, id: String, ttl: Option<Duration>) {
        if let Some(tenant) = &self.tenant {
            self.owners.record(id, TenantId::new(tenant.clone()), ttl);
        }
    }

    /// Records what a finished 2xx response says the tenant owns.
    fn finish_response(&mut self) {
        match self.response.take() {
            None => {}
            Some(Capture::Events(_)) => {
                self.warn_unrecorded("event stream ended before an event named the created ID")
            }
            Some(Capture::Json { buf, overflowed }) => {
                let created = self.create.is_some();
                let owned = if overflowed {
                    None
                } else {
                    self.rules.owned_by_response(&buf, created)
                };
                let Some(owned) = owned else {
                    if created {
                        self.warn_unrecorded("not a JSON object within the size limit");
                    }
                    return;
                };
                if created && owned.created.is_none() {
                    self.warn_unrecorded("no top-level string `id`");
                }
                if let Some(id) = owned.created {
                    self.record(id, self.created_ttl());
                }
                for id in owned.files {
                    self.record(id, None);
                }
            }
        }
    }

    /// Reads the created ID from an event stream's first event, recording it
    /// as soon as it arrives.
    fn read_events(&mut self, data: &[u8]) {
        let Some(Capture::Events(buf)) = &mut self.response else {
            return;
        };
        let room = MAX_FIRST_EVENT_BYTES.saturating_sub(buf.len());
        buf.extend_from_slice(&data[..data.len().min(room)]);
        match created_in_first_event(buf) {
            FirstEvent::Found(id) => {
                self.response = None;
                self.record(id, self.created_ttl());
            }
            FirstEvent::NotFound(why) => {
                self.response = None;
                self.warn_unrecorded(why);
            }
            FirstEvent::NeedMore if room < data.len() => {
                self.response = None;
                self.warn_unrecorded("event stream named no created ID within the size limit");
            }
            FirstEvent::NeedMore => {}
        }
    }

    fn warn_unrecorded(&self, why: &'static str) {
        self.owners.unrecorded.emit(|suppressed| {
            tracing::warn!(
                why,
                suppressed,
                "llmproxy.object_ownership: a create succeeded but its response did not say \
                 what it created ({why}), so no owner was recorded and the object is refused to \
                 every tenant"
            );
        });
    }
}

fn json_content_type() -> proxy_http::filter::HeaderMutationFn {
    Box::new(|headers: &mut http::HeaderMap| {
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
    })
}

/// The one refusal: the same body whether the object is another tenant's or
/// nobody's.
fn deny(cb: &mut dyn DecoderCallbacks) {
    cb.send_local_reply(
        StatusCode::NOT_FOUND,
        r#"{"error":{"message":"object not found"}}"#,
        Some(json_content_type()),
        DENY_DETAILS,
    );
}

impl HttpFilter for ObjectOwnershipFilter {
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        if !self.started {
            self.started = true;
            // Rust note: clone out of the `RefMut` guard so it is dropped
            // before the `send_local_reply` calls below.
            self.tenant = cb.stream_info().auth.tenant.clone();
            self.target = self.rules.classify(headers.uri.path());
            let post = headers.method == Method::POST;
            match self.target {
                PathTarget::None => return FilterHeadersStatus::Continue,
                PathTarget::Endpoint(_) if !post => {
                    self.target = PathTarget::None;
                    return FilterHeadersStatus::Continue;
                }
                _ if self.tenant.is_none() => {
                    deny(cb);
                    return FilterHeadersStatus::Continue;
                }
                PathTarget::Collection(index) | PathTarget::Endpoint(index) if post => {
                    self.create = Some(index);
                    // Without a body; `decode_data` decides again with one.
                    self.record = records(&self.rules.collection(index).record, None);
                    return FilterHeadersStatus::Continue;
                }
                PathTarget::Collection(_) | PathTarget::Endpoint(_) => {
                    deny(cb);
                    return FilterHeadersStatus::Continue;
                }
                PathTarget::Object(_) => {}
            }
        }
        let PathTarget::Object(id) = &self.target else {
            return FilterHeadersStatus::Continue;
        };
        if self.path_owned {
            return FilterHeadersStatus::Continue;
        }
        let ids = [id.clone()];
        match self.authorize(cb, &ids) {
            Step::Owned => {
                self.path_owned = true;
                FilterHeadersStatus::Continue
            }
            // The local reply ends the chain; the status is not read.
            Step::Refused => FilterHeadersStatus::Continue,
            Step::Hold => FilterHeadersStatus::StopIteration,
        }
    }

    /// The filter manager delivers the request body as one buffered chunk,
    /// so the whole body is checked in one call. After a held lookup the
    /// same call is made again with the same body.
    fn decode_data(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        data: &mut Bytes,
        _end_stream: bool,
    ) -> FilterDataStatus {
        if self.body_done {
            return FilterDataStatus::Continue;
        }
        if let Some(index) = self.create {
            self.record = records(&self.rules.collection(index).record, Some(data));
        }
        let ids = match self.rules.references(data) {
            BodyReferences::None => Vec::new(),
            BodyReferences::Ids(ids) => ids,
            BodyReferences::Unparseable => {
                self.body_done = true;
                cb.send_local_reply(
                    StatusCode::BAD_REQUEST,
                    r#"{"error":{"message":"request body references an object but is not valid JSON"}}"#,
                    Some(json_content_type()),
                    UNPARSEABLE_DETAILS,
                );
                return FilterDataStatus::Continue;
            }
        };
        if ids.is_empty() {
            self.body_done = true;
            return FilterDataStatus::Continue;
        }
        match self.authorize(cb, &ids) {
            Step::Owned | Step::Refused => {
                self.body_done = true;
                FilterDataStatus::Continue
            }
            Step::Hold => FilterDataStatus::StopIterationAndBuffer,
        }
    }

    fn encode_headers(
        &mut self,
        _cb: &mut dyn EncoderCallbacks,
        headers: &mut ResponseHeaders,
        end_stream: bool,
    ) -> FilterHeadersStatus {
        let created = self.create.is_some() && self.record;
        if (created || self.path_owned) && headers.status.is_success() {
            let events = headers
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| {
                    v.trim_start()
                        .to_ascii_lowercase()
                        .starts_with("text/event-stream")
                });
            self.response = match (events, created) {
                (true, true) => Some(Capture::Events(BytesMut::new())),
                // An owned object's event stream names nothing to record.
                (true, false) => None,
                (false, _) => Some(Capture::Json {
                    buf: BytesMut::new(),
                    overflowed: false,
                }),
            };
        }
        if end_stream {
            self.finish_response();
        }
        FilterHeadersStatus::Continue
    }

    fn encode_data(
        &mut self,
        _cb: &mut dyn EncoderCallbacks,
        data: &mut Bytes,
        end_stream: bool,
    ) -> FilterDataStatus {
        match &mut self.response {
            Some(Capture::Json { buf, overflowed }) => {
                if buf.len() + data.len() > MAX_RESPONSE_BYTES {
                    *overflowed = true;
                    buf.clear();
                } else if !*overflowed {
                    buf.extend_from_slice(data);
                }
            }
            Some(Capture::Events(_)) => self.read_events(data),
            None => {}
        }
        if end_stream {
            self.finish_response();
        }
        FilterDataStatus::Continue
    }

    fn encode_trailers(
        &mut self,
        _cb: &mut dyn EncoderCallbacks,
        _trailers: &mut ResponseTrailers,
    ) -> FilterTrailersStatus {
        self.finish_response();
        FilterTrailersStatus::Continue
    }

    /// Waits for a held lookup, at most [`LOOKUP_TIMEOUT`]. The answer is
    /// applied when the filter manager calls the held callback again.
    fn poll_pending<'a>(
        &'a mut self,
    ) -> Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>>> {
        if !matches!(self.lookup, Lookup::Waiting(_)) {
            return None;
        }
        let Lookup::Waiting(answer) = std::mem::replace(&mut self.lookup, Lookup::Idle) else {
            unreachable!("checked just above");
        };
        Some(Box::pin(async move {
            let answer = match tokio::time::timeout(LOOKUP_TIMEOUT, answer).await {
                Ok(Ok(Ok(owners))) => Ok(owners),
                Ok(Ok(Err(e))) => Err(e.to_string()),
                Ok(Err(_)) => Err("the object owners thread stopped".to_string()),
                Err(_) => Err(format!(
                    "the store did not answer within {}s",
                    LOOKUP_TIMEOUT.as_secs()
                )),
            };
            self.lookup = Lookup::Answered(answer);
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(json: serde_json::Value) -> DynamicMessage {
        let desc = proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.ObjectOwnership")
            .expect("ObjectOwnership resolves");
        DynamicMessage::deserialize(desc, json).expect("proto JSON")
    }

    fn rejected(json: serde_json::Value) -> String {
        match parse_config(&config(json.clone())) {
            Err(ConfigError::InvalidValue { field_path, .. }) => field_path,
            other => panic!("{json}: {other:?}"),
        }
    }

    /// Strict config: every malformed field fails the load with its dotted
    /// path (AGENTS.md invariant 1), and a valid one parses.
    #[test]
    fn malformed_fields_fail_with_their_path() {
        use serde_json::json;
        let ok = json!({
            "collections": ["/v1/files"],
            "collection": [{
                "path": "/v1/chat/completions",
                "record": "RECORD_IF_TRUE",
                "record_member": "store",
                "owner_ttl_seconds": 60,
            }],
            "reference_members": ["*_file_id", "conversation"],
            "owned_members": ["file.id"],
            "opaque_members": ["metadata"],
        });
        let rules = parse_config(&config(ok)).expect("valid");
        assert_eq!(rules.collection(1).owner_ttl, Some(Duration::from_secs(60)));
        assert_eq!(rules.collection(1).record, Record::IfTrue("store".into()));

        for (json, path) in [
            (json!({}), "typed_config"),
            (
                json!({"collections": ["files"]}),
                "typed_config.collections[0]",
            ),
            (
                json!({"collection": [{"path": "/v1/a", "endpoints": ["x/y"]}]}),
                "typed_config.collection[0]",
            ),
            (
                json!({"collection": [{"path": "/v1/a", "record": "RECORD_IF_TRUE"}]}),
                "typed_config.collection[0].record_member",
            ),
            (
                json!({"collection": [{"path": "/v1/a", "record_member": "store"}]}),
                "typed_config.collection[0].record_member",
            ),
            (
                json!({"collection": [{"path": "/v1/a", "record": 7, "record_member": "s"}]}),
                "typed_config.collection[0].record",
            ),
            (
                json!({"collections": ["/v1/a"], "reference_members": ["a.b"]}),
                "typed_config.reference_members[0]",
            ),
            (
                json!({"collections": ["/v1/a"], "owned_members": ["a.b.c"]}),
                "typed_config.owned_members[0]",
            ),
            (
                json!({"collections": ["/v1/a"], "opaque_members": ["*meta"]}),
                "typed_config.opaque_members[0]",
            ),
            (
                json!({"collections": ["/v1/a"], "collection": [{"path": "/v1/a"}]}),
                "typed_config",
            ),
        ] {
            assert_eq!(rejected(json.clone()), path, "{json}");
        }
    }
}
