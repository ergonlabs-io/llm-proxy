//! Entry points for the cargo-fuzz targets in `fuzz/`. Not a public API: the
//! module exists only with the `fuzzing` feature (and under `test`). The
//! handlers run unchanged against an in-memory control plane; the parsers
//! return what the matching `GET` would render, so a target can check a
//! write round-trips.

use std::pin::Pin;
use std::task::{Context, Poll};

use http_body_util::Full;
use hyper::body::{Body as _, Bytes};
use hyper::Response;
use proxy_control::auth::{HmacSecret, KeySet};
use proxy_control::control::{ControlPlane, InMemoryControlPlaneStore};

/// A handler's answer: status code and body bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    pub body: Bytes,
}

impl Answer {
    fn from_response(response: Response<Full<Bytes>>) -> Self {
        let status = response.status().as_u16();
        let mut body = response.into_body();
        // A `Full` body is ready on its first poll; nothing here waits.
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let body = match Pin::new(&mut body).poll_frame(&mut cx) {
            Poll::Ready(Some(Ok(frame))) => frame.into_data().unwrap_or_default(),
            _ => Bytes::new(),
        };
        Answer { status, body }
    }
}

/// The admin write handlers that need only a control plane, over an empty
/// in-memory store.
pub struct Harness {
    control_plane: ControlPlane,
}

impl Harness {
    pub fn new(hmac_secret: &[u8]) -> Self {
        let control_plane = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(hmac_secret),
            KeySet::new(),
        )
        .expect("an empty in-memory store loads");
        Harness { control_plane }
    }

    pub fn control_plane(&self) -> &ControlPlane {
        &self.control_plane
    }

    /// `POST /keys`.
    pub fn mint_key(&self, body: &[u8]) -> Answer {
        Answer::from_response(super::handle_mint_key(&self.control_plane, body))
    }

    /// `POST /tenants`.
    pub fn create_tenant(&self, body: &[u8]) -> Answer {
        Answer::from_response(super::handle_create_tenant(&self.control_plane, body))
    }

    /// `PUT /keys/{id}/budget`.
    pub fn set_key_budget(&self, key_id: &str, body: &[u8]) -> Answer {
        Answer::from_response(super::handle_set_key_budget(
            &self.control_plane,
            key_id,
            body,
        ))
    }

    /// `PUT /tenants/{id}/trace_export`.
    pub fn set_trace_export(&self, tenant: &str, body: &[u8]) -> Answer {
        Answer::from_response(super::handle_set_trace_export(
            &self.control_plane,
            tenant,
            body,
        ))
    }

    /// `GET /keys`.
    pub fn list_keys(&self) -> Answer {
        Answer::from_response(super::handle_list_keys(&self.control_plane))
    }
}

/// A policy body (`PUT /tenants/{id}/policy`, `PUT /keys/{id}/policy`),
/// rendered as `GET /keys` shows it; `Err` is the refusal's status.
pub fn parse_model_policy(body: &[u8]) -> Result<serde_json::Value, u16> {
    super::parse_model_policy(body)
        .map(|access| super::render_model_access(&access))
        .map_err(|response| response.status().as_u16())
}

/// A limits body (`PUT /tenants/{id}/limits`, `PUT /keys/{id}/limits`),
/// rendered as `GET /keys` shows it (`None` clears the row).
pub fn parse_limits(body: &[u8]) -> Result<Option<serde_json::Value>, u16> {
    super::parse_limits(body)
        .map(|limits| limits.map(super::render_limits))
        .map_err(|response| response.status().as_u16())
}

/// A budget body (`PUT /tenants/{id}/budget`, `PUT /keys/{id}/budget`):
/// `Some((max_micro_usd, max_usd as GET renders it))`, or `None` to clear.
pub fn parse_budget(body: &[u8]) -> Result<Option<(u64, String)>, u16> {
    let request: super::SetBudgetRequest =
        super::parse_json_body(body).map_err(|response| response.status().as_u16())?;
    let Some(spec) = request.budget else {
        return Ok(None);
    };
    // The key form is the one that names `include_byok_in_limit`.
    let micros = if spec.include_byok_in_limit.is_some() {
        super::key_budget_from_spec(spec).map(|budget| budget.max_micros)
    } else {
        super::budget_from_spec(spec).map(|budget| budget.max_micros)
    }
    .map_err(|response| response.status().as_u16())?
    .as_micros();
    Ok(Some((micros, super::render_micro_usd(micros))))
}
