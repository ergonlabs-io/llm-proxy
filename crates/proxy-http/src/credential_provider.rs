//! Applies cluster credentials per upstream attempt, after request transforms,
//! so fallback uses the credentials of the cluster actually dialled.

use bytes::Bytes;
use chrono::Utc;
use futures::future::BoxFuture;
use ring::{digest, hmac};

use crate::filter::RequestHeaders;

/// Applies credentials for the cluster selected for one upstream attempt.
///
/// `body` is the final upstream payload. Implementations fail closed on
/// signing or credential errors.
pub(crate) trait CredentialProvider {
    /// Async providers must keep token refresh off the request worker and fail
    /// closed when no usable token is available.
    fn apply<'a>(
        &'a self,
        request: &'a mut RequestHeaders,
        body: &'a Bytes,
    ) -> BoxFuture<'a, Result<(), CredentialProviderError>>;
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CredentialProviderError {
    #[error("provider credential could not be applied")]
    Failed,
    /// A minted-token cluster has no unexpired token published. Fails closed
    /// (ADR-0005, amendment 2026-10-17).
    #[error("no unexpired minted token is published for this provider")]
    TokenUnavailable,
}

/// Applies configured static credential headers.
pub(crate) struct StaticHeaderCredentials<'a> {
    headers: &'a [proxy_config::ir::HeaderMutation],
}

/// Applies the selected cluster's credentials after request transforms, so
/// credentials do not leak across a fallback aggregate.
pub(crate) struct ProviderCredentials<'a> {
    runtime: Option<&'a proxy_config::ir::ProviderRuntimeConfig>,
    headers: &'a [proxy_config::ir::HeaderMutation],
    /// The cluster's published token cell, for an `OAuth2JwtBearer` credential.
    minted: Option<&'a proxy_cluster::minted_credential::MintedCredential>,
    /// Tenant mode (ADR-0007): the cluster's slot and the tenant's secret for
    /// it. Written last, over whatever the operator credential set.
    tenant: Option<(
        &'a proxy_config::ir::TenantCredentialSlot,
        &'a crate::tenant_credentials::TenantSecret,
    )>,
}

impl<'a> ProviderCredentials<'a> {
    pub(crate) fn new(
        runtime: Option<&'a proxy_config::ir::ProviderRuntimeConfig>,
        headers: &'a [proxy_config::ir::HeaderMutation],
    ) -> Self {
        Self {
            runtime,
            headers,
            minted: None,
            tenant: None,
        }
    }

    /// The selected cluster's token cell; read, never refreshed, here.
    pub(crate) fn with_minted(
        mut self,
        minted: Option<&'a proxy_cluster::minted_credential::MintedCredential>,
    ) -> Self {
        self.minted = minted;
        self
    }

    /// Overwrite the slot's header with the tenant's secret after the
    /// cluster's own credential has been applied. The slot lives on the
    /// cluster, so the tenant key follows the member actually dialled
    /// (AGENTS.md invariant 6).
    pub(crate) fn with_tenant(
        mut self,
        slot: &'a proxy_config::ir::TenantCredentialSlot,
        secret: &'a crate::tenant_credentials::TenantSecret,
    ) -> Self {
        self.tenant = Some((slot, secret));
        self
    }
}

impl CredentialProvider for ProviderCredentials<'_> {
    fn apply<'a>(
        &'a self,
        request: &'a mut RequestHeaders,
        body: &'a Bytes,
    ) -> BoxFuture<'a, Result<(), CredentialProviderError>> {
        Box::pin(async move {
            StaticHeaderCredentials::new(self.headers)
                .apply(request, body)
                .await?;
            let applied = match self.runtime.and_then(|runtime| runtime.credential.as_ref()) {
                None => Ok(()),
                Some(proxy_config::ir::ProviderCredential::VertexOAuth2 { access_token }) => {
                    let value = format!("Bearer {access_token}");
                    let value = http::HeaderValue::from_str(&value)
                        .map_err(|_| CredentialProviderError::Failed)?;
                    request.headers.insert("authorization", value);
                    Ok(())
                }
                Some(proxy_config::ir::ProviderCredential::OAuth2JwtBearer(_)) => {
                    // No token, or an expired one: fail closed rather than
                    // send the request unauthenticated or wait for a mint.
                    let value = self
                        .minted
                        .and_then(|minted| minted.bearer(std::time::Instant::now()))
                        .ok_or(CredentialProviderError::TokenUnavailable)?;
                    request.headers.insert("authorization", value);
                    Ok(())
                }
                Some(proxy_config::ir::ProviderCredential::BedrockSigV4 {
                    region,
                    access_key_id,
                    secret_access_key,
                    session_token,
                }) => sign_bedrock_request(
                    request,
                    body,
                    region,
                    access_key_id,
                    secret_access_key,
                    session_token.as_deref(),
                ),
            };
            applied?;
            if let Some((slot, secret)) = self.tenant {
                let name = http::HeaderName::from_bytes(slot.header.as_bytes())
                    .map_err(|_| CredentialProviderError::Failed)?;
                let mut value = http::HeaderValue::from_str(&format!(
                    "{}{}",
                    slot.value_prefix,
                    secret.expose()
                ))
                .map_err(|_| CredentialProviderError::Failed)?;
                // Prevent credential exposure through HPACK indexing or Debug.
                value.set_sensitive(true);
                // ADR-0007 decision 5 and AGENTS.md invariant 6: clear every
                // supported credential header to prevent sending the operator
                // key alongside the tenant credential.
                for shape in ["authorization", "x-api-key", "api-key"] {
                    request.headers.remove(shape);
                }
                request.headers.insert(name, value);
            }
            Ok(())
        })
    }
}

fn sign_bedrock_request(
    request: &mut RequestHeaders,
    body: &Bytes,
    region: &str,
    access_key_id: &str,
    secret_access_key: &str,
    session_token: Option<&str>,
) -> Result<(), CredentialProviderError> {
    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    sign_bedrock_request_at(
        request,
        body,
        region,
        access_key_id,
        secret_access_key,
        session_token,
        &timestamp,
    )
}

fn sign_bedrock_request_at(
    request: &mut RequestHeaders,
    body: &Bytes,
    region: &str,
    access_key_id: &str,
    secret_access_key: &str,
    session_token: Option<&str>,
    timestamp: &str,
) -> Result<(), CredentialProviderError> {
    const SERVICE: &str = "bedrock";
    let date = &timestamp[..8];
    let payload_hash = hex_digest(body);
    request.headers.insert(
        "x-amz-date",
        http::HeaderValue::from_str(timestamp).map_err(|_| CredentialProviderError::Failed)?,
    );
    request.headers.insert(
        "x-amz-content-sha256",
        http::HeaderValue::from_str(&payload_hash).map_err(|_| CredentialProviderError::Failed)?,
    );
    if let Some(token) = session_token {
        request.headers.insert(
            "x-amz-security-token",
            http::HeaderValue::from_str(token).map_err(|_| CredentialProviderError::Failed)?,
        );
    }

    let host = request
        .headers
        .get(http::header::HOST)
        .ok_or(CredentialProviderError::Failed)?
        .to_str()
        .map_err(|_| CredentialProviderError::Failed)?;
    let canonical_uri = if request.uri.path().is_empty() {
        "/"
    } else {
        request.uri.path()
    };
    let canonical_query = canonical_query(request.uri.query().unwrap_or(""));
    let mut canonical_headers = format!(
        "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}",
        host.trim(),
        payload_hash,
        timestamp
    );
    if let Some(token) = session_token {
        canonical_headers.push_str(&format!("\nx-amz-security-token:{}", token.trim()));
    }
    let signed_headers = if session_token.is_some() {
        "host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
    } else {
        "host;x-amz-content-sha256;x-amz-date"
    };
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        request.method,
        canonical_uri,
        canonical_query,
        canonical_headers,
        signed_headers,
        payload_hash
    );
    let canonical_hash = hex_digest(canonical_request.as_bytes());
    let scope = format!("{date}/{region}/{SERVICE}/aws4_request");
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{canonical_hash}");
    let date_key = hmac_bytes(
        format!("AWS4{secret_access_key}").as_bytes(),
        date.as_bytes(),
    );
    let region_key = hmac_bytes(&date_key, region.as_bytes());
    let service_key = hmac_bytes(&region_key, SERVICE.as_bytes());
    let signing_key = hmac_bytes(&service_key, b"aws4_request");
    let signature = hex_bytes(&hmac_bytes(&signing_key, string_to_sign.as_bytes()));
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key_id}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    );
    request.headers.insert(
        "authorization",
        http::HeaderValue::from_str(&authorization).map_err(|_| CredentialProviderError::Failed)?,
    );
    Ok(())
}

fn canonical_query(query: &str) -> String {
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (uri_encode(key.as_bytes()), uri_encode(value.as_bytes()))
        })
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn uri_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(*byte as char);
        } else {
            use std::fmt::Write;
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

fn hex_digest(bytes: &[u8]) -> String {
    hex_bytes(digest::digest(&digest::SHA256, bytes).as_ref())
}

fn hmac_bytes(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data)
        .as_ref()
        .to_vec()
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

impl<'a> StaticHeaderCredentials<'a> {
    pub(crate) fn new(headers: &'a [proxy_config::ir::HeaderMutation]) -> Self {
        Self { headers }
    }
}

impl CredentialProvider for StaticHeaderCredentials<'_> {
    fn apply<'a>(
        &'a self,
        request: &'a mut RequestHeaders,
        _body: &'a Bytes,
    ) -> BoxFuture<'a, Result<(), CredentialProviderError>> {
        Box::pin(async move {
            // Preserve Envoy's malformed-header behavior: warn and skip.
            crate::router::apply_header_mutations(self.headers, &mut request.headers);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, Method, Uri};

    use super::{CredentialProvider, ProviderCredentials, StaticHeaderCredentials};
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

        futures::executor::block_on(
            StaticHeaderCredentials::new(&headers)
                .apply(&mut request, &bytes::Bytes::from_static(b"rewritten-body")),
        )
        .expect("static credentials are valid");

        assert_eq!(
            request.headers.get("authorization"),
            Some(&HeaderValue::from_static("Bearer provider-secret"))
        );
    }

    #[test]
    fn bedrock_signature_uses_final_body_and_required_headers() {
        let runtime = proxy_config::ir::ProviderRuntimeConfig {
            credential: Some(proxy_config::ir::ProviderCredential::BedrockSigV4 {
                region: "us-east-1".to_string(),
                access_key_id: "AKIDEXAMPLE".to_string(),
                secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
                session_token: None,
            }),
            path_template: None,
            model_rewrites: Vec::new(),
            request_field_policy: Default::default(),
            tenant_credential: None,
        };
        let mut request = RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static("/model/anthropic.claude-3/invoke"),
            headers: HeaderMap::from_iter([(
                http::header::HOST,
                HeaderValue::from_static("bedrock-runtime.us-east-1.amazonaws.com"),
            )]),
        };
        futures::executor::block_on(
            ProviderCredentials::new(Some(&runtime), &[])
                .apply(&mut request, &bytes::Bytes::from_static(b"final-body")),
        )
        .expect("signature should be valid");
        assert!(request.headers.contains_key("authorization"));
        assert_eq!(
            request.headers["x-amz-content-sha256"]
                .to_str()
                .unwrap()
                .len(),
            64
        );
        assert!(request.headers["authorization"]
            .to_str()
            .unwrap()
            .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
    }

    #[test]
    fn vertex_credential_replaces_any_client_authorization() {
        let runtime = proxy_config::ir::ProviderRuntimeConfig {
            credential: Some(proxy_config::ir::ProviderCredential::VertexOAuth2 {
                access_token: "published-token".to_string(),
            }),
            path_template: None,
            model_rewrites: Vec::new(),
            request_field_policy: Default::default(),
            tenant_credential: None,
        };
        let mut request = RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static("/vertex"),
            headers: HeaderMap::from_iter([(
                http::header::AUTHORIZATION,
                HeaderValue::from_static("Bearer client-token"),
            )]),
        };
        futures::executor::block_on(
            ProviderCredentials::new(Some(&runtime), &[])
                .apply(&mut request, &bytes::Bytes::from_static(b"body")),
        )
        .expect("Vertex credential should be valid");
        assert_eq!(
            request.headers["authorization"],
            HeaderValue::from_static("Bearer published-token")
        );
    }
}
