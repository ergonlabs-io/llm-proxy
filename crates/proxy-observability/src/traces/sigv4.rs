//! AWS Signature Version 4 for the trace uploader (ADR-0008 decision 7).
//!
//! Generic over service and region, and over the signed headers, unlike the
//! Bedrock signer in `proxy-http`, which hard-codes its service and is not
//! reachable from here. The caller passes the canonical URI already encoded
//! exactly as it will be sent: S3 does not normalise or re-encode the path,
//! so the request-target and the canonical URI must be the same string
//! (design note section 7.2).

use ring::{digest, hmac};

/// Bytes S3 keeps unencoded in a path segment (RFC 3986 unreserved).
fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// Encodes one path segment (or query component) once.
pub fn uri_encode(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for b in segment.bytes() {
        if unreserved(b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `/a/b/c` with each segment encoded once; `/` separators kept.
pub fn encode_path(segments: &[&str]) -> String {
    let mut out = String::new();
    for segment in segments {
        out.push('/');
        out.push_str(&uri_encode(segment));
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, bytes).as_ref())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data)
        .as_ref()
        .to_vec()
}

/// One request to sign. `headers` are the headers to sign, names in
/// lowercase, values as sent; `host` must be among them.
pub struct Request<'a> {
    pub method: &'a str,
    pub canonical_uri: &'a str,
    /// `(name, value)` pairs, unencoded; encoded and sorted here.
    pub query: &'a [(&'a str, &'a str)],
    pub headers: &'a [(&'a str, &'a str)],
    pub payload_sha256: &'a str,
}

/// Credentials and scope.
pub struct Scope<'a> {
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    pub region: &'a str,
    pub service: &'a str,
    /// `YYYYMMDDTHHMMSSZ`.
    pub amz_date: &'a str,
}

/// The `Authorization` header value.
pub fn authorization(request: &Request<'_>, scope: &Scope<'_>) -> String {
    let mut query: Vec<(String, String)> = request
        .query
        .iter()
        .map(|(k, v)| (uri_encode(k), uri_encode(v)))
        .collect();
    query.sort();
    let canonical_query = query
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let mut headers: Vec<(String, String)> = request
        .headers
        .iter()
        .map(|(k, v)| {
            let value = v.split_whitespace().collect::<Vec<_>>().join(" ");
            (k.to_ascii_lowercase(), value)
        })
        .collect();
    headers.sort();
    let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        request.method,
        request.canonical_uri,
        canonical_query,
        canonical_headers,
        signed_headers,
        request.payload_sha256
    );
    let date = &scope.amz_date[..8];
    let credential_scope = format!("{date}/{}/{}/aws4_request", scope.region, scope.service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{credential_scope}\n{}",
        scope.amz_date,
        sha256_hex(canonical_request.as_bytes())
    );
    let k_date = hmac_sha256(
        format!("AWS4{}", scope.secret_access_key).as_bytes(),
        date.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, scope.region.as_bytes());
    let k_service = hmac_sha256(&k_region, scope.service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, \
         Signature={signature}",
        scope.access_key_id
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS's published Signature Version 4 example (IAM `ListUsers`, in the
    /// "Create a signed AWS API request" walkthrough): the signature is AWS's,
    /// not this code's, so a mistake in the canonical request, the scope or
    /// the key derivation fails here.
    #[test]
    fn aws_published_example_signs_to_awss_signature() {
        let auth = authorization(
            &Request {
                method: "GET",
                canonical_uri: "/",
                query: &[("Action", "ListUsers"), ("Version", "2010-05-08")],
                headers: &[
                    (
                        "content-type",
                        "application/x-www-form-urlencoded; charset=utf-8",
                    ),
                    ("host", "iam.amazonaws.com"),
                    ("x-amz-date", "20150830T123600Z"),
                ],
                payload_sha256: &sha256_hex(b""),
            },
            &Scope {
                access_key_id: "AKIDEXAMPLE",
                secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                region: "us-east-1",
                service: "iam",
                amz_date: "20150830T123600Z",
            },
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date, \
             Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    /// Segment keys carry `=` and percent-encoded ids; each is encoded once,
    /// so `=` becomes `%3D` and a literal `%` becomes `%25`, and `/` between
    /// segments stays.
    #[test]
    fn key_segments_are_encoded_once() {
        assert_eq!(
            encode_path(&[
                "bucket",
                "pre",
                "tenant=a%2Fb",
                "date=2026-10-01",
                "n-1-0.jsonl.gz"
            ]),
            "/bucket/pre/tenant%3Da%252Fb/date%3D2026-10-01/n-1-0.jsonl.gz"
        );
        assert_eq!(uri_encode("é ~"), "%C3%A9%20~");
    }
}
