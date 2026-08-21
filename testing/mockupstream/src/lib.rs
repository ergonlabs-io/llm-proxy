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
//!   streaming and non-streaming response shapes, built once at startup
//!   from the CLI's `--ttft-ms`/`--inter-token-ms`/`--tokens`/
//!   `--prompt-tokens`.
//! - [`handler`]: routes `POST /v1/chat/completions`, `POST /v1/messages`,
//!   `GET /health`, and turns anything else into a 404.
//! - [`stats`]: `AtomicU64` request counters and the optional periodic
//!   stderr printer (`--stats-interval-secs`).
//!
//! `main.rs` (the `mock-upstream` binary) is the thin part: CLI parsing,
//! binding the listener, and picking the downstream protocol builder
//! (`--protocol http1|http2|auto`).

pub mod frames;
pub mod handler;
pub mod request;
pub mod stats;
