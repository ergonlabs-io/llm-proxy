//! The one endpoint classifier (ADR-0010 decision 1).
//!
//! Every place that needs to know what kind of LLM call a request is (which
//! usage parser reads it, which output-token field bounds it, which OTel
//! operation it is, whether a spend or token control can count it) asks
//! [`Endpoint::classify`]. Keeping one answer stops the copies from drifting
//! apart: a suffix check that learns `/v1/messages/batches` in one place and
//! not another is a metering gap.
//!
//! It reads the client-facing method and path, before any upstream path
//! rewrite, and matches whole path segments, never raw suffixes.

use http::Method;

/// What a request is, as far as metering is concerned.
///
/// `Unmetered` covers every path the classifier does not know, so an endpoint
/// a provider adds later is unmetered until it is designed in.
///
/// The `Default` is `Unmetered`: a stream that was never classified is refused
/// under every control, never admitted as a text endpoint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Endpoint {
    /// `POST .../chat/completions`.
    ChatCompletions,
    /// `POST .../completions` (legacy text completions).
    Completions,
    /// `POST .../responses` (OpenAI Responses).
    Responses,
    /// `POST .../messages` (Anthropic Messages).
    Messages,
    /// `POST .../embeddings`.
    Embeddings,
    /// `POST .../images/generations`.
    ImageGeneration,
    /// `POST .../images/edits`.
    ImageEdit,
    /// `POST .../audio/speech`.
    Speech,
    /// `POST .../audio/transcriptions`.
    Transcription,
    /// `POST .../audio/translations`.
    Translation,
    /// A WebSocket upgrade on `.../realtime`: one long-lived session whose
    /// usage arrives in event frames (`response.done`), not in a response
    /// body. Classified by [`Endpoint::classify_upgrade`].
    Realtime,
    /// Paths no provider bills: `GET .../models`, `GET .../usage` and
    /// `POST .../messages/count_tokens`.
    Free,
    /// Everything else: batches, files, retrievals of stored objects, and any
    /// path not listed above.
    #[default]
    Unmetered,
}

impl Endpoint {
    /// Classify a request by its method and its client-facing path (no query
    /// string: pass [`http::Uri::path`]).
    ///
    /// Only `POST` creates a generation. A `GET` on a generation path
    /// retrieves or lists stored objects, so it is `Unmetered`, not metered
    /// as a new call.
    pub fn classify(method: &Method, path: &str) -> Endpoint {
        let mut segments = path.rsplit('/');
        let last = segments.next().unwrap_or_default();
        let parent = segments.next().unwrap_or_default();
        if method == Method::GET {
            return match last {
                "models" | "usage" => Endpoint::Free,
                _ => Endpoint::Unmetered,
            };
        }
        if method != Method::POST {
            return Endpoint::Unmetered;
        }
        match (parent, last) {
            ("messages", "count_tokens") => Endpoint::Free,
            ("chat", "completions") => Endpoint::ChatCompletions,
            (_, "completions") => Endpoint::Completions,
            (_, "responses") => Endpoint::Responses,
            (_, "messages") => Endpoint::Messages,
            (_, "embeddings") => Endpoint::Embeddings,
            ("images", "generations") => Endpoint::ImageGeneration,
            ("images", "edits") => Endpoint::ImageEdit,
            ("audio", "speech") => Endpoint::Speech,
            ("audio", "transcriptions") => Endpoint::Transcription,
            ("audio", "translations") => Endpoint::Translation,
            _ => Endpoint::Unmetered,
        }
    }

    /// Classify a WebSocket upgrade request by its client-facing path (an
    /// h1 `GET` with `Upgrade: websocket`, or an h2 extended `CONNECT` with
    /// `:protocol websocket`). A session on `.../realtime` is
    /// [`Endpoint::Realtime`]; any other upgrade is `Unmetered`.
    pub fn classify_upgrade(path: &str) -> Endpoint {
        match path.rsplit('/').next() {
            Some("realtime") => Endpoint::Realtime,
            _ => Endpoint::Unmetered,
        }
    }

    /// A stable snake_case name, for metric labels and logs. The set is
    /// closed, so it is safe as a label value.
    pub fn label(self) -> &'static str {
        match self {
            Endpoint::ChatCompletions => "chat_completions",
            Endpoint::Completions => "completions",
            Endpoint::Responses => "responses",
            Endpoint::Messages => "messages",
            Endpoint::Embeddings => "embeddings",
            Endpoint::ImageGeneration => "image_generation",
            Endpoint::ImageEdit => "image_edit",
            Endpoint::Speech => "speech",
            Endpoint::Transcription => "transcription",
            Endpoint::Translation => "translation",
            Endpoint::Realtime => "realtime",
            Endpoint::Free => "free",
            Endpoint::Unmetered => "unmetered",
        }
    }

    /// The five text endpoints whose responses report token usage the proxy
    /// can read today.
    pub fn reports_text_tokens(self) -> bool {
        matches!(
            self,
            Endpoint::ChatCompletions
                | Endpoint::Completions
                | Endpoint::Responses
                | Endpoint::Messages
                | Endpoint::Embeddings
        )
    }
}

/// A realtime session's model: its `model` query parameter, percent-decoded
/// (`+` is a space, as in a form). The first occurrence wins. `None` when
/// absent, empty, or not UTF-8 after decoding.
pub fn realtime_model(uri: &http::Uri) -> Option<String> {
    let query = uri.query()?;
    let raw = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("model="))?;
    let decoded = percent_decode(raw)?;
    (!decoded.is_empty()).then_some(decoded)
}

/// `uri` with its first `model` query parameter set to `model`, every other
/// parameter kept as sent: the session asks the provider for the model it
/// was routed to (AGENTS.md invariant 6). `None` when `uri` has no `model`
/// parameter or the result is not a valid URI.
pub fn with_realtime_model(uri: &http::Uri, model: &str) -> Option<http::Uri> {
    let query = uri.query()?;
    let mut replaced = false;
    let pairs: Vec<String> = query
        .split('&')
        .map(|pair| {
            if !replaced && pair.starts_with("model=") {
                replaced = true;
                format!("model={}", percent_encode(model))
            } else {
                pair.to_string()
            }
        })
        .collect();
    if !replaced {
        return None;
    }
    let path_and_query = format!("{}?{}", uri.path(), pairs.join("&"));
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(path_and_query.parse().ok()?);
    http::Uri::from_parts(parts).ok()
}

fn percent_decode(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = raw.get(i + 1..i + 3)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 2;
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// Percent-encode everything but RFC 3986 unreserved characters.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_each_known_path_and_nothing_else() {
        let post = Method::POST;
        let get = Method::GET;
        for (method, path, expected) in [
            (&post, "/v1/chat/completions", Endpoint::ChatCompletions),
            (&post, "/v1/completions", Endpoint::Completions),
            (&post, "/v1/responses", Endpoint::Responses),
            (&post, "/v1/messages", Endpoint::Messages),
            (&post, "/v1/embeddings", Endpoint::Embeddings),
            (&post, "/v1/images/generations", Endpoint::ImageGeneration),
            (&post, "/v1/images/edits", Endpoint::ImageEdit),
            (&post, "/v1/audio/speech", Endpoint::Speech),
            (&post, "/v1/audio/transcriptions", Endpoint::Transcription),
            (&post, "/v1/audio/translations", Endpoint::Translation),
            (&get, "/v1/models", Endpoint::Free),
            (&get, "/v1/usage", Endpoint::Free),
            (&post, "/v1/messages/count_tokens", Endpoint::Free),
            // Segments, not suffixes: a batch under `messages` is not a message.
            (&post, "/v1/messages/batches", Endpoint::Unmetered),
            (&post, "/v1/batches", Endpoint::Unmetered),
            (&post, "/v1/files", Endpoint::Unmetered),
            (&post, "/v1/images/variations", Endpoint::Unmetered),
            (&post, "/v1/chat/completions/", Endpoint::Unmetered),
            // Retrievals are not new generations.
            (&get, "/v1/responses", Endpoint::Unmetered),
            (&get, "/v1/batches/batch_1", Endpoint::Unmetered),
            (&post, "/v1/models", Endpoint::Unmetered),
            (&Method::DELETE, "/v1/files/file_1", Endpoint::Unmetered),
            (&post, "/", Endpoint::Unmetered),
            (&post, "", Endpoint::Unmetered),
        ] {
            assert_eq!(
                Endpoint::classify(method, path),
                expected,
                "{method} {path}"
            );
        }
    }

    /// Only a WebSocket on `.../realtime` is a realtime session; a plain
    /// request on that path, or an upgrade elsewhere, is not.
    #[test]
    fn only_an_upgrade_on_realtime_is_a_realtime_session() {
        assert_eq!(
            Endpoint::classify_upgrade("/v1/realtime"),
            Endpoint::Realtime
        );
        assert_eq!(
            Endpoint::classify_upgrade("/openai/realtime"),
            Endpoint::Realtime
        );
        assert_eq!(
            Endpoint::classify_upgrade("/v1/realtime/x"),
            Endpoint::Unmetered
        );
        assert_eq!(Endpoint::classify_upgrade("/v1/chat"), Endpoint::Unmetered);
        assert_eq!(
            Endpoint::classify(&Method::GET, "/v1/realtime"),
            Endpoint::Unmetered
        );
        assert_eq!(Endpoint::Realtime.label(), "realtime");
    }

    #[test]
    fn the_realtime_model_is_read_from_and_written_to_the_query() {
        let uri: http::Uri = "/v1/realtime?x=1&model=gpt%2Drealtime+v2&model=other"
            .parse()
            .unwrap();
        assert_eq!(realtime_model(&uri).as_deref(), Some("gpt-realtime v2"));
        let rewritten = with_realtime_model(&uri, "provider/model 1").unwrap();
        assert_eq!(
            rewritten.to_string(),
            "/v1/realtime?x=1&model=provider%2Fmodel%201&model=other"
        );
        assert_eq!(
            realtime_model(&rewritten).as_deref(),
            Some("provider/model 1")
        );
        for none in [
            "/v1/realtime",
            "/v1/realtime?model=",
            "/v1/realtime?model=%zz",
        ] {
            assert_eq!(realtime_model(&none.parse().unwrap()), None, "{none}");
        }
        assert!(with_realtime_model(&"/v1/realtime?x=1".parse().unwrap(), "m").is_none());
    }
}
