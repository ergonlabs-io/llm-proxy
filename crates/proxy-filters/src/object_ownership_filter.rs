//! `llmproxy.object_ownership`: refuses a request that names a provider
//! object (a file or batch ID) the caller's tenant does not own, before the
//! upstream is dialled, and records the owner of every object a tenant
//! creates. What names an object, and where owners live, is in
//! [`crate::object_ownership`]'s module doc.
//!
//! # Decisions
//!
//! - A path naming an object: the caller's tenant must own it.
//! - A collection's own path: a POST creates. Any other method lists the
//!   provider account every tenant shares, so it is refused.
//! - A JSON request body that references files: the tenant must own every
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
//! caller's tenant. A 2xx JSON response to a create or to an owned object
//! also records the files its top-level reference members name. The
//! response is never held: it streams through, and the owner enters this
//! replica's cache as the body ends, before the stream completes. The store
//! write follows on the owners thread.

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
    file_references, owned_by_response, BodyReferences, Cached, Collections, LookupAnswer,
    ObjectOwners, PathTarget,
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

/// Reads `typed_config.collections`.
pub fn parse_config(config: &DynamicMessage) -> Result<Collections, ConfigError> {
    let paths: Vec<String> = config
        .get_field_by_name("collections")
        .and_then(|v| {
            v.as_list().map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
        })
        .unwrap_or_default();
    Collections::parse(&paths).map_err(|(i, reason)| {
        if paths.is_empty() {
            invalid("typed_config.collections", reason)
        } else {
            invalid(format!("typed_config.collections[{i}]"), reason)
        }
    })
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
        let collections = Arc::new(parse_config(config)?);
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
        Ok(Box::new(ObjectOwnershipInstanceFactory {
            owners,
            collections,
        }))
    }
}

struct ObjectOwnershipInstanceFactory {
    owners: Arc<ObjectOwners>,
    collections: Arc<Collections>,
}

impl FilterInstanceFactory for ObjectOwnershipInstanceFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(ObjectOwnershipFilter {
            owners: Arc::clone(&self.owners),
            collections: Arc::clone(&self.collections),
            started: false,
            tenant: None,
            target: PathTarget::None,
            create: false,
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
#[derive(Default)]
struct Capture {
    buf: BytesMut,
    overflowed: bool,
}

/// Per-stream instance.
struct ObjectOwnershipFilter {
    owners: Arc<ObjectOwners>,
    collections: Arc<Collections>,
    /// `decode_headers` has classified the request. It is called again after
    /// a held lookup, and must not classify twice.
    started: bool,
    tenant: Option<String>,
    target: PathTarget,
    /// A POST to a collection.
    create: bool,
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

    /// Records what a finished 2xx response says the tenant owns.
    fn finish_response(&mut self) {
        let Some(capture) = self.response.take() else {
            return;
        };
        let Some(tenant) = self.tenant.clone() else {
            return;
        };
        let owned = if capture.overflowed {
            None
        } else {
            owned_by_response(&capture.buf, self.create)
        };
        let owned = match owned {
            Some(owned) => owned,
            None => {
                if self.create {
                    self.warn_unrecorded("is not a JSON object within the size limit");
                }
                return;
            }
        };
        if self.create && owned.created.is_none() {
            self.warn_unrecorded("has no top-level string `id`");
        }
        for id in owned.created.into_iter().chain(owned.files) {
            self.owners.record(id, TenantId::new(tenant.clone()), None);
        }
    }

    fn warn_unrecorded(&self, why: &'static str) {
        self.owners.unrecorded.emit(|suppressed| {
            tracing::warn!(
                why,
                suppressed,
                "llmproxy.object_ownership: a create succeeded but its response {why}, so no \
                 owner was recorded and the object is refused to every tenant"
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
            self.target = self.collections.classify(headers.uri.path());
            match self.target {
                PathTarget::None => return FilterHeadersStatus::Continue,
                _ if self.tenant.is_none() => {
                    deny(cb);
                    return FilterHeadersStatus::Continue;
                }
                PathTarget::Collection if headers.method == Method::POST => {
                    self.create = true;
                    return FilterHeadersStatus::Continue;
                }
                PathTarget::Collection => {
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
        let ids = match file_references(data) {
            BodyReferences::None => Vec::new(),
            BodyReferences::Ids(ids) => ids,
            BodyReferences::Unparseable => {
                self.body_done = true;
                cb.send_local_reply(
                    StatusCode::BAD_REQUEST,
                    r#"{"error":{"message":"request body references a file but is not valid JSON"}}"#,
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
        if (self.create || self.path_owned) && headers.status.is_success() {
            self.response = Some(Capture::default());
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
        if let Some(capture) = &mut self.response {
            if capture.buf.len() + data.len() > MAX_RESPONSE_BYTES {
                capture.overflowed = true;
                capture.buf.clear();
            } else if !capture.overflowed {
                capture.buf.extend_from_slice(data);
            }
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
