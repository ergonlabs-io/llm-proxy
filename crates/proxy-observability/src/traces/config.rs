//! Trace-export configuration contracts (ADR-0008), shared by the config
//! readers and the runtime. `node.metadata["io.llmproxy.traces"]` in Envoy
//! mode, `observability.traces` in the dialect. Process-level and
//! boot-scoped, like the ledger.

use std::path::PathBuf;
use std::time::Duration;

pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 1 << 20;
pub const DEFAULT_MAX_RESPONSE_BODY_BYTES: usize = 4 << 20;
pub const DEFAULT_MAX_MEMORY_BYTES: usize = 256 << 20;
pub const DEFAULT_MAX_QUEUED_TRACES: usize = 4096;
pub const DEFAULT_SEGMENT_MAX_BYTES: u64 = 64 << 20;
pub const DEFAULT_SEGMENT_MAX_AGE: Duration = Duration::from_secs(300);
pub const DEFAULT_MAX_OPEN_SEGMENTS: usize = 64;
pub const DEFAULT_ZSTD_WINDOW_LOG: u8 = 24;
pub const DEFAULT_UPLOAD_TIMEOUT: Duration = Duration::from_secs(120);

pub const BODY_BYTES_RANGE: std::ops::RangeInclusive<u64> = 1024..=(64 << 20);
pub const SEGMENT_MAX_BYTES_RANGE: std::ops::RangeInclusive<u64> = (1 << 20)..=(1 << 30);
pub const SEGMENT_MAX_AGE_RANGE_SECS: std::ops::RangeInclusive<f64> = 10.0..=3600.0;
pub const MAX_QUEUED_TRACES_RANGE: std::ops::RangeInclusive<u64> = 1..=(1 << 20);
pub const MAX_OPEN_SEGMENTS_RANGE: std::ops::RangeInclusive<u64> = 1..=4096;
pub const ZSTD_WINDOW_LOG_RANGE: std::ops::RangeInclusive<u64> = 20..=27;
pub const MAX_DISK_BYTES_RANGE: std::ops::RangeInclusive<u64> = (1 << 20)..=(1 << 50);
pub const MAX_MEMORY_BYTES_RANGE: std::ops::RangeInclusive<u64> = (1 << 20)..=(1 << 40);
pub const UPLOAD_TIMEOUT_RANGE_SECS: std::ops::RangeInclusive<f64> = 1.0..=3600.0;
/// zstd encoder windows across every open segment.
pub const MAX_ZSTD_WINDOW_TOTAL: u64 = 2 << 30;

/// How sealed segments are compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceCodec {
    /// The default: every warehouse loader reads it.
    Gzip,
    /// Long-window zstd for consumers that can read it (ADR-0008 decision 11).
    Zstd { window_log: u8 },
}

impl TraceCodec {
    /// The segment file and object suffix.
    pub fn extension(self) -> &'static str {
        match self {
            Self::Gzip => "jsonl.gz",
            Self::Zstd { .. } => "jsonl.zst",
        }
    }
}

/// Static object-store credentials. They live only here, never on a route
/// or cluster (AGENTS.md invariant 6). `Debug` never renders a secret.
#[derive(Clone, PartialEq, Eq)]
pub struct S3Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

impl std::fmt::Debug for S3Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// An S3-compatible upload destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Destination {
    pub bucket: String,
    /// Required, never inferred (ADR-0008 decision 11).
    pub region: String,
    /// `scheme://host[:port]`; `None` means `https://s3.<region>.amazonaws.com`.
    pub endpoint: Option<String>,
    pub path_style: bool,
    /// Key prefix without leading or trailing `/`; may be empty.
    pub prefix: String,
    pub credentials: S3Credentials,
    pub upload_timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceExportConfig {
    /// Segments are written here; one process at a time.
    pub directory: PathBuf,
    /// Every segment on disk, open or sealed, uploaded or not.
    pub max_disk_bytes: u64,
    /// Directory destination only: sealed segments older than this go.
    pub max_age: Option<Duration>,
    pub codec: TraceCodec,
    pub max_request_body_bytes: usize,
    pub max_response_body_bytes: usize,
    /// Every retained body byte, in flight and queued.
    pub max_memory_bytes: usize,
    /// Captures in flight plus queued.
    pub max_queued_traces: usize,
    pub segment_max_bytes: u64,
    pub segment_max_age: Duration,
    pub max_open_segments: usize,
    pub s3: Option<S3Destination>,
}

impl TraceExportConfig {
    /// The largest line one trace can produce: both bodies, base64-expanded,
    /// plus record headroom.
    pub fn max_line_bytes(&self) -> u64 {
        let bodies = (self.max_request_body_bytes + self.max_response_body_bytes) as u64;
        bodies.div_ceil(3) * 4 + (1 << 20)
    }

    /// Rules that relate fields. `Err` names the offending field, relative to
    /// the block, and why; each reader prefixes its own path.
    pub fn validate(&self) -> Result<(), (&'static str, String)> {
        if self.max_memory_bytes < self.max_request_body_bytes + self.max_response_body_bytes {
            return Err((
                "max_memory_bytes",
                "must be at least max_request_body_bytes + max_response_body_bytes".into(),
            ));
        }
        if self.s3.is_some() && self.max_age.is_some() {
            return Err((
                "max_age",
                "not permitted with s3: uploaded objects expire by the bucket's lifecycle rules"
                    .into(),
            ));
        }
        if self.segment_max_bytes < self.max_line_bytes() {
            return Err((
                "segment_max_bytes",
                format!(
                    "must be at least {}: the largest line (both body caps base64-expanded, \
                     plus 1 MiB), so a segment holds more than one line",
                    self.max_line_bytes()
                ),
            ));
        }
        let needed = (self.max_open_segments as u64)
            .saturating_mul(self.segment_max_bytes)
            .saturating_mul(2);
        if self.max_disk_bytes < needed {
            return Err((
                "max_disk_bytes",
                format!(
                    "must be at least {needed}: 2 x max_open_segments x segment_max_bytes, so \
                     open segments alone cannot fill it"
                ),
            ));
        }
        if let TraceCodec::Zstd { window_log } = self.codec {
            let total = (self.max_open_segments as u64).saturating_mul(1u64 << window_log);
            if total > MAX_ZSTD_WINDOW_TOTAL {
                return Err((
                    "zstd_window_log",
                    "max_open_segments x 2^zstd_window_log must not exceed 2 GiB".into(),
                ));
            }
        }
        if let Some(s3) = &self.s3 {
            if !s3.path_style && s3.bucket.contains('.') {
                return Err((
                    "s3.path_style",
                    "must be true for a bucket name containing '.' (virtual-hosted style breaks \
                     the wildcard certificate)"
                        .into(),
                ));
            }
        }
        Ok(())
    }
}

/// Whether `prefix` is a valid key prefix: empty, or `/`-separated non-empty
/// segments with no `.` or `..` segment.
pub fn valid_prefix(prefix: &str) -> bool {
    prefix.is_empty()
        || prefix
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// Whether `bucket` follows the S3 bucket naming rules that matter here:
/// 3-63 bytes of lowercase letters, digits, `.` and `-`, starting and ending
/// with a letter or digit.
pub fn valid_bucket(bucket: &str) -> bool {
    let b = bucket.as_bytes();
    (3..=63).contains(&b.len())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'.' || *c == b'-')
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
}

/// Whether `endpoint` is `http(s)://host[:port]` with nothing else.
pub fn valid_endpoint(endpoint: &str) -> bool {
    let Ok(uri) = endpoint.parse::<http::Uri>() else {
        return false;
    };
    matches!(uri.scheme_str(), Some("http" | "https"))
        && uri.host().is_some_and(|h| !h.is_empty())
        && uri.authority().is_some_and(|a| !a.as_str().contains('@'))
        && uri
            .path_and_query()
            .is_none_or(|p| p.as_str() == "/" || p.as_str().is_empty())
        && !endpoint.ends_with('/')
}
