//! WP-30: a lean, standalone, long-lived mock LLM provider for capacity/load
//! testing.
//!
//! # Why this exists instead of reusing `testing/diffrig`'s mocks
//!
//! `testing/diffrig/src/upstreams/openai.rs` already has `OpenAiUpstream`,
//! and reusing it would be the obvious move -- do not. Those mocks record
//! every request into a `RequestLog`/`ChatRequestLog`, an
//! `Arc<Mutex<Vec<..>>>` that grows without bound and is locked on every
//! request. Under a capacity sweep that lock becomes contended and the `Vec`
//! becomes the memory profile, so a report built against it would measure
//! the mock, not the proxy under test. This crate exists to be boring and
//! fast on the request path instead: no `Mutex`, no unbounded state, and
//! every constant response fragment rendered exactly once at startup (see
//! `frames`).
//!
//! # Module map
//! - [`request`]: the two facts (`stream`, `model`) this crate ever reads
//!   out of a request body, and nothing else -- the body itself is never
//!   retained.
//! - [`frames`]: pre-rendered `Bytes` fragments for both dialects'
//!   streaming and non-streaming response shapes -- the content-delta
//!   fragment rendered once at startup, the length/timing-dependent
//!   terminal frame rendered fresh per request. See its module doc.
//! - [`profiles`]: named per-request distributions for TTFT, inter-token
//!   delay, and streamed length (`mock-fast-short`/`mock-medium`/
//!   `mock-slow-long` built in, `--profiles <file>` to add/override),
//!   selected by the request's `model` -- see
//!   `internal-docs/scale-test-plan.md` §3/§5.
//! - [`handler`]: routes `POST /v1/chat/completions`, `POST /v1/messages`,
//!   `GET /health`, turns anything else into a 404, and draws each
//!   request's timing/length from its resolved profile.
//! - [`stats`]: `AtomicU64` request counters and the optional periodic
//!   stderr printer (`--stats-interval-secs`).
//!
//! `main.rs` (the `mock-upstream` binary) is the thin part: CLI parsing,
//! binding the listener, and picking the downstream protocol builder
//! (`--protocol http1|http2|auto`).

pub mod frames;
pub mod handler;
pub mod profiles;
pub mod request;
pub mod stats;
