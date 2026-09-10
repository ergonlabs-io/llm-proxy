//! Provider credentials applied after the decode chain has produced the final
//! upstream request body.
//!
//! Static API keys are the only implemented provider mechanism today.  They
//! do not need the body, but deliberately travel through this seam anyway:
//! Bedrock SigV4 signs the final payload hash and Vertex's minted OAuth token
//! belongs to the same per-attempt, provider-owned operation.  Keeping static
//! credentials on the old header-mutation path while adding a second signing
//! call site would make it very easy for a future implementation to sign the
//! client body rather than the body a Lane-H filter rewrote.

use bytes::Bytes;

use crate::filter::RequestHeaders;

/// Applies credentials for the cluster selected for one upstream attempt.
///
/// The request has already passed every decode filter when this is called, so
/// `body` is exactly what reaches the upstream.  Implementations must fail
/// closed: a signer/minting failure must return an error instead of sending an
/// unauthenticated request to a provider.
pub(crate) trait CredentialProvider {
    fn apply(
        &self,
        request: &mut RequestHeaders,
        body: &Bytes,
    ) -> Result<(), CredentialProviderError>;
}

#[derive(Debug, thiserror::Error)]
#[error("provider credential could not be applied")]
pub(crate) struct CredentialProviderError;

/// The existing static-header mechanism, now expressed through the same
/// post-body seam that body-dependent schemes will use.
pub(crate) struct StaticHeaderCredentials<'a> {
    headers: &'a [proxy_config::ir::HeaderMutation],
}

impl<'a> StaticHeaderCredentials<'a> {
    pub(crate) fn new(headers: &'a [proxy_config::ir::HeaderMutation]) -> Self {
        Self { headers }
    }
}

impl CredentialProvider for StaticHeaderCredentials<'_> {
    fn apply(
        &self,
        request: &mut RequestHeaders,
        _body: &Bytes,
    ) -> Result<(), CredentialProviderError> {
        // `apply_header_mutations` intentionally preserves the existing
        // Envoy-compatible malformed-header behavior (warn and skip).  The
        // dialect validates its own emitted values before they reach this
        // point; a future signing/minting implementation instead returns a
        // `CredentialProviderError`, which the router maps to a local 503.
        crate::router::apply_header_mutations(self.headers, &mut request.headers);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, Method, Uri};

    use super::{CredentialProvider, StaticHeaderCredentials};
    use crate::filter::RequestHeaders;

    #[test]
    fn static_credentials_apply_to_the_final_request() {
        let headers = vec![proxy_config::ir::HeaderMutation {
            key: "authorization".to_string(),
            value: "Bearer provider-secret".to_string(),
            action: proxy_config::ir::HeaderAppendAction::OverwriteIfExistsOrAdd,
        }];
        let mut request = RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static("/rewritten"),
            headers: HeaderMap::new(),
        };

        StaticHeaderCredentials::new(&headers)
            .apply(&mut request, &bytes::Bytes::from_static(b"rewritten-body"))
            .expect("static credentials are valid");

        assert_eq!(
            request.headers.get("authorization"),
            Some(&HeaderValue::from_static("Bearer provider-secret"))
        );
    }
}
