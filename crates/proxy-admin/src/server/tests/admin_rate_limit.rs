//! Review M9: repeated bad admin tokens are rate-limited per peer, and every
//! refusal is logged with the peer address (never the presented token).
//!
//! `#[tokio::test]` runs on one thread, so the server's connection tasks run
//! on the test's thread and the thread-local capture below sees their events.

use std::collections::BTreeMap;

use super::*;
use crate::server::auth_limit::MAX_FAILURES;

/// Records every event's fields, rendered, on the current thread.
#[derive(Default)]
struct Capture(Mutex<Vec<BTreeMap<String, String>>>);

impl tracing::Subscriber for Capture {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Fields(BTreeMap<String, String>);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0
                    .insert(field.name().to_string(), format!("{value:?}"));
            }
        }
        let mut fields = Fields(BTreeMap::new());
        event.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }
    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

#[tokio::test]
async fn repeated_bad_tokens_are_refused_with_429_and_logged_with_the_peer() {
    let capture = Arc::new(Capture::default());
    let _guard = tracing::subscriber::set_default(Arc::clone(&capture));
    let (factory_state, _handle) = factory_state_with_control_plane();
    let (_server, addr) = start_full(
        snapshot_with_secret(),
        None,
        factory_state,
        Some(ADMIN_TOKEN.to_string()),
    )
    .await;
    let guess = "guessed-token-SENTINEL";

    for attempt in 1..=MAX_FAILURES {
        let (status, _, _) = request(addr, "GET", "/keys", Some(guess), "").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "attempt {attempt}");
    }
    let (status, headers, _) = request(addr, "GET", "/keys", Some(guess), "").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = headers["retry-after"].to_str().unwrap().parse().unwrap();
    assert!((1..=60).contains(&retry_after), "{retry_after}");
    // The right token inside the burst is refused too, so a guess cannot be
    // confirmed by the response.
    let (status, _, _) = request(addr, "GET", "/keys", Some(ADMIN_TOKEN), "").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    let events = capture.0.lock().unwrap().clone();
    let refused = events
        .iter()
        .filter(|event| event["message"].contains("missing or invalid bearer token"))
        .count();
    let limited = events
        .iter()
        .filter(|event| event["message"].contains("refused (429)"))
        .count();
    assert_eq!(refused, MAX_FAILURES as usize, "one line per bad token");
    assert_eq!(
        limited, 1,
        "the switch to 429 is logged once, not per request"
    );
    for event in events.iter().filter(|event| event.contains_key("peer")) {
        assert_eq!(event["peer"], "127.0.0.1", "{event:?}");
    }
    assert!(
        events
            .iter()
            .flat_map(|event| event.values())
            .all(|value| !value.contains("SENTINEL") && !value.contains(ADMIN_TOKEN)),
        "no presented token may be logged"
    );
}
