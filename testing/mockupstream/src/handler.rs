//! Routes the four endpoints this mock upstream speaks, reads (and caps)
//! the request body, resolves a response [`crate::profiles::Profile`] by
//! `model`, and dispatches to the pre-rendered response builders in
//! [`crate::frames`].

use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use serde_json::json;

use crate::frames::{self, AnthropicFrames, Draw, OpenAiFrames, ResponseBody, StreamConfig};
use crate::profiles::{Profile, ProfileSet};
use crate::request::{self, MAX_BODY_BYTES};
use crate::stats::{InFlightGuard, Stats};

/// Everything one accepted connection's request handlers share: the
/// pre-rendered frame sets (one build per process, at startup), the profile
/// table, and the request counters. Cheap to clone (an `Arc` bump) per
/// connection/request.
pub struct AppState {
    openai: OpenAiFrames,
    anthropic: AnthropicFrames,
    prompt_tokens: u32,
    profiles: ProfileSet,
    pub stats: Arc<Stats>,
}

impl AppState {
    pub fn new(cfg: StreamConfig, profiles: ProfileSet) -> Self {
        Self {
            openai: OpenAiFrames::new(),
            anthropic: AnthropicFrames::new(&cfg),
            prompt_tokens: cfg.prompt_tokens,
            profiles,
            stats: Arc::new(Stats::default()),
        }
    }
}

/// Draw this request's timing/length from its resolved profile, given an
/// RNG. Split out from [`draw_response_shape`] so a test can hand it a
/// seeded `SmallRng` and get a reproducible draw -- see this module's tests.
fn draw_response_shape_with_rng(profile: &Profile, rng: &mut impl Rng) -> Draw {
    let ttft = profile.sample_ttft(rng);
    let k = profile.sample_length(rng);
    let inter_token_delays = (0..k).map(|_| profile.sample_inter_token(rng)).collect();
    Draw {
        ttft,
        inter_token_delays,
    }
}

/// Draw this request's timing/length from its resolved profile.
///
/// Rust note: `SmallRng` is a fast, non-cryptographic PRNG -- exactly what a
/// mock's response shaping needs, unlike `StdRng`/`thread_rng`'s stronger
/// (and slower) guarantees. Seeding a fresh one per request from the OS
/// (`from_entropy`) keeps it entirely on the stack of this one request's
/// task: no shared `Mutex`/`RwLock`-guarded generator, so nothing here ever
/// contends a lock across the `.await`s in `frames::stream_body` -- the
/// crate doc's "no `Mutex` on the request path" rule, extended to the new
/// per-request randomness.
fn draw_response_shape(profile: &Profile) -> Draw {
    let mut rng = SmallRng::from_entropy();
    draw_response_shape_with_rng(profile, &mut rng)
}

/// Non-streaming responses don't need TTFT/inter-token delays (there's
/// nothing to pace -- the whole body goes out at once), just the drawn
/// output length. Same split-for-testability shape as
/// [`draw_response_shape`]/[`draw_response_shape_with_rng`].
fn draw_length_with_rng(profile: &Profile, rng: &mut impl Rng) -> u32 {
    profile.sample_length(rng)
}

fn draw_length(profile: &Profile) -> u32 {
    let mut rng = SmallRng::from_entropy();
    draw_length_with_rng(profile, &mut rng)
}

/// Handle one request. Infallible at the HTTP level -- every outcome this
/// mock can produce (including "body too large" and "unknown route") is
/// rendered as a normal `Response`, never a connection-level error.
pub async fn handle(req: Request<Incoming>, state: Arc<AppState>) -> Response<ResponseBody> {
    match (req.method().clone(), req.uri().path()) {
        (Method::POST, "/v1/chat/completions") => {
            handle_dialect(req, &state, Dialect::OpenAi).await
        }
        (Method::POST, "/v1/messages") => handle_dialect(req, &state, Dialect::Anthropic).await,
        // Read by scripts/scale-experiment-remote.sh's stream sampler. The
        // underscore prefix keeps it clear of every provider API path.
        (Method::GET, "/_mock/stats") => json_response(Bytes::from(
            serde_json::to_vec(&state.stats.take_snapshot())
                .expect("snapshot is always serializable"),
        )),
        (Method::GET, "/health") => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(frames::full_body(Bytes::from_static(b"ok")))
            .expect("static health response is always valid"),
        _ => {
            state.stats.record_rejected();
            json_error(
                StatusCode::NOT_FOUND,
                &format!("no such route: {} {}", req.method(), req.uri().path()),
            )
        }
    }
}

enum Dialect {
    OpenAi,
    Anthropic,
}

async fn handle_dialect(
    req: Request<Incoming>,
    state: &AppState,
    dialect: Dialect,
) -> Response<ResponseBody> {
    let guard = state.stats.enter();
    let body = match read_capped_body(req).await {
        Ok(bytes) => bytes,
        Err(resp) => {
            state.stats.record_rejected();
            return *resp;
        }
    };
    let meta = request::parse_request_meta(&body);
    // The crate doc's "do not retain the body" rule: `body` goes out of
    // scope at the end of this function and is never stored anywhere past
    // `parse_request_meta`.
    state.stats.record_request(meta.stream);

    // A `model` naming no configured profile is load-test input, not an
    // error -- `resolve` always returns something (`ProfileSet`'s
    // `"default"` entry, never removable). See `crate::profiles`.
    let profile = state.profiles.resolve(&meta.model);

    let response = match dialect {
        Dialect::OpenAi => {
            if meta.stream {
                let draw = draw_response_shape(profile);
                sse_response(
                    state
                        .openai
                        .stream_body(&meta.model, state.prompt_tokens, draw),
                )
            } else {
                let k = draw_length(profile);
                json_response(frames::openai_completion_body(
                    state.prompt_tokens,
                    k,
                    &meta.model,
                ))
            }
        }
        Dialect::Anthropic => {
            if meta.stream {
                let draw = draw_response_shape(profile);
                sse_response(state.anthropic.stream_body(&meta.model, draw))
            } else {
                let k = draw_length(profile);
                json_response(frames::anthropic_message_body(
                    state.prompt_tokens,
                    k,
                    &meta.model,
                ))
            }
        }
    };
    hold_until_body_ends(response, guard)
}

/// Move the in-flight guard into the response body, so the request stays
/// counted until hyper drops the body: when the last frame is written, or
/// when the client disconnects mid-stream.
fn hold_until_body_ends(
    response: Response<ResponseBody>,
    guard: InFlightGuard,
) -> Response<ResponseBody> {
    response.map(|inner| {
        HeldBody {
            inner,
            _guard: guard,
        }
        .boxed()
    })
}

/// A response body that carries an [`InFlightGuard`] and is otherwise the
/// body it wraps. It must forward `size_hint`: hyper frames a response by its
/// exact size hint, so a wrapper that reports an unknown size (as
/// `map_frame` does) turns every fixed-length JSON reply into HTTP/1.1
/// chunked encoding and drops `content-length` from h2 replies. The proxy
/// then forwards that framing, which makes the proxy look like it re-encodes.
struct HeldBody {
    inner: ResponseBody,
    _guard: InFlightGuard,
}

impl hyper::body::Body for HeldBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    // Rust note: `ResponseBody` is a `BoxBody`, which is `Unpin`, so
    // `Pin::new` reaches the inner body without a pin projection.
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        std::pin::Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// Read the whole request body, capped at [`MAX_BODY_BYTES`]. Returns the
/// bytes on success, or an already-rendered 413 response on overflow.
///
/// Rust note: the response rides in a `Box` because `Response` alone is over
/// the size at which clippy considers an `Err` variant too large to carry by
/// value; the single caller unboxes it immediately.
async fn read_capped_body(req: Request<Incoming>) -> Result<Bytes, Box<Response<ResponseBody>>> {
    let limited = Limited::new(req.into_body(), MAX_BODY_BYTES);
    match limited.collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(_) => {
            // `Limited`'s only error is a length-limit overflow (any
            // transport-level read error would also land here, but this is
            // a mock upstream serving loopback load-test traffic, so folding
            // both into one 413 is an acceptable simplification -- a real
            // provider's exact error taxonomy isn't the thing under test).
            Err(Box::new(json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                &format!("request body exceeds {MAX_BODY_BYTES} bytes"),
            )))
        }
    }
}

fn json_response(bytes: Bytes) -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(frames::full_body(bytes))
        .expect("status/headers are always valid")
}

fn sse_response(body: ResponseBody) -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .body(body)
        .expect("status/headers are always valid")
}

fn json_error(status: StatusCode, message: &str) -> Response<ResponseBody> {
    let body = serde_json::to_vec(&json!({"error": {"message": message}}))
        .expect("error value is always serializable");
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(frames::full_body(Bytes::from(body)))
        .expect("status/headers are always valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiles::Dist;
    use rand::rngs::SmallRng;
    use rand::SeedableRng;

    fn profile(
        name: &str,
        ttft: (u64, u64),
        inter_token: (u64, u64),
        length: (u64, u64),
    ) -> Profile {
        Profile {
            name: name.to_string(),
            ttft_ms: Dist {
                min: ttft.0,
                max: ttft.1,
            },
            inter_token_ms: Dist {
                min: inter_token.0,
                max: inter_token.1,
            },
            length: Dist {
                min: length.0,
                max: length.1,
            },
        }
    }

    /// Acceptance: two requests to the same profile draw different lengths
    /// and/or timings. Seeded so the test itself is deterministic, per
    /// `draw_response_shape_with_rng`'s doc -- this is the pure sampler this
    /// module's production `draw_response_shape` is a thin `from_entropy`
    /// wrapper around.
    #[test]
    fn two_draws_against_the_same_profile_differ() {
        let p = profile("mock-medium", (200, 400), (15, 30), (300, 600));
        let mut rng_a = SmallRng::seed_from_u64(1);
        let mut rng_b = SmallRng::seed_from_u64(2);
        let a = draw_response_shape_with_rng(&p, &mut rng_a);
        let b = draw_response_shape_with_rng(&p, &mut rng_b);
        assert!(
            a.ttft != b.ttft || a.k() != b.k() || a.inter_token_delays != b.inter_token_delays,
            "two differently-seeded draws against the same profile produced identical output"
        );
    }

    /// A request stays counted while its body is alive: through a finished
    /// read of every frame, and through a body dropped mid-stream (the
    /// client went away).
    #[tokio::test]
    async fn in_flight_lasts_as_long_as_the_response_body() {
        let in_flight = |s: &Stats| s.in_flight.load(std::sync::atomic::Ordering::Relaxed);
        let stats = Arc::new(Stats::default());
        let frames = OpenAiFrames::new();
        let draw = || Draw {
            ttft: std::time::Duration::ZERO,
            inter_token_delays: vec![std::time::Duration::ZERO; 3],
        };

        let read_to_end = hold_until_body_ends(
            sse_response(frames.stream_body("m", 10, draw())),
            stats.enter(),
        );
        assert_eq!(in_flight(&stats), 1);
        read_to_end.into_body().collect().await.unwrap();
        assert_eq!(in_flight(&stats), 0);

        let abandoned = hold_until_body_ends(
            sse_response(frames.stream_body("m", 10, draw())),
            stats.enter(),
        );
        assert_eq!(in_flight(&stats), 1);
        drop(abandoned);
        assert_eq!(in_flight(&stats), 0);
        assert_eq!(stats.take_snapshot().peak_in_flight, 1);
    }

    /// Same property for the non-streaming length draw.
    #[test]
    fn two_length_draws_against_the_same_profile_can_differ() {
        let p = profile("mock-medium", (200, 400), (15, 30), (300, 600));
        let mut rng_a = SmallRng::seed_from_u64(1);
        let mut rng_b = SmallRng::seed_from_u64(2);
        let a = draw_length_with_rng(&p, &mut rng_a);
        let b = draw_length_with_rng(&p, &mut rng_b);
        assert_ne!(a, b);
    }
}
