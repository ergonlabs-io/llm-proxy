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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    /// Paths no provider bills: `GET .../models`, `GET .../usage` and
    /// `POST .../messages/count_tokens`.
    Free,
    /// Everything else: batches, files, retrievals of stored objects, and any
    /// path not listed above.
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
}
