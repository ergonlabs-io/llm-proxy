//! WP-22 increment 1: decoding an SDS-delivered
//! `envoy.extensions.transport_sockets.tls.v3.Secret` resource.
//!
//! **Scope note, read before extending this file.** [`DynamicSecret`] lives
//! in `proxy-xds` only for this increment. Increment 2 (the resolver wiring
//! -- hooking a decoded secret into the WP-08 `ArcSwap` / `SwapCertResolver`
//! seam, plus naming which secrets a listener actually subscribes to via
//! `tls_certificate_sds_secret_configs`) moves this type into
//! `proxy-config/src/ir.rs` alongside the existing (static-only) `TlsSecret`
//! -- `ir.rs` is owned by another lane this batch, so that move is
//! deliberately not made here. `apply.rs`'s own module doc records the same
//! shape of deferral for RDS.
//!
//! # Ground rule #1, applied to `Secret`
//!
//! Every field this message (and the messages it nests) can carry either
//! lowers into [`DynamicSecret`] or is refused with its full dotted path --
//! never silently dropped. Concretely, this increment supports exactly:
//! - `tls_certificate.certificate_chain` / `.private_key`, each an
//!   `inline_bytes` or `inline_string` [`DataSource`] -- nothing else in
//!   `TlsCertificate` (`pkcs12`, `watched_directory`, `private_key_provider`,
//!   `password`, `ocsp_staple`, `signed_certificate_timestamp`) is
//!   implemented;
//! - `validation_context.trusted_ca`, same `DataSource` restriction --
//!   nothing else in `CertificateValidationContext` is implemented;
//! - `session_ticket_keys` and `generic_secret` are real `Secret.type` cases
//!   this proxy simply does not act on yet, refused by name;
//! - an unset `type` oneof is refused, not treated as a no-op.
//!
//! A `filename`/`environment_variable` `DataSource` is refused rather than
//! read, deliberately: a control plane handing this proxy a *path* to read
//! (or an env var name to look up) is a materially different trust model
//! from handing it bytes directly, and is not this feature.

use prost::Message;
use proxy_api::envoy::config::core::v3::data_source::Specifier;
use proxy_api::envoy::config::core::v3::DataSource;
use proxy_api::envoy::extensions::transport_sockets::tls::v3::secret::Type as SecretOneof;
use proxy_api::envoy::extensions::transport_sockets::tls::v3::{
    CertificateValidationContext, Secret as SecretProto, TlsCertificate,
};
use proxy_config::ConfigError;

/// One decoded SDS `Secret`, restricted to the two cases this proxy acts on.
/// See this module's own doc for exactly which sub-fields are supported.
///
/// Rust note: no `PartialEq` derive here, matching `ClusterConfig` /
/// `ListenerConfig` in `proxy-config`'s IR (see `apply.rs`'s `Entry<T>` doc)
/// -- `Entry<T>`'s hand-written `PartialEq` compares only the raw bytes a
/// resource arrived as, so nothing here needs to compare for equality.
#[derive(Debug, Clone)]
pub struct DynamicSecret {
    /// `Secret.name` -- what an `SdsSecretConfig.name` subscribes to.
    pub name: String,
    pub kind: SecretKind,
}

/// Which `Secret.type` oneof case [`DynamicSecret::kind`] holds, and the
/// bytes lowered out of it.
#[derive(Debug, Clone)]
pub enum SecretKind {
    TlsCertificate {
        certificate_chain: Vec<u8>,
        private_key: Vec<u8>,
    },
    ValidationContext {
        trusted_ca: Vec<u8>,
    },
}

/// Build a [`ConfigError::UnsupportedField`] -- the same variant
/// `proxy-config`'s own `lower.rs` raises for a field outside its allowlist,
/// reused here rather than inventing a parallel error shape for the same
/// idea (ground rule #1's dotted-path requirement applies identically to a
/// dynamically-delivered resource).
fn unsupported(path: impl Into<String>, reason: impl Into<String>) -> ConfigError {
    ConfigError::UnsupportedField {
        field_path: path.into(),
        reason: reason.into(),
    }
}

/// Resolve one `DataSource` to its bytes, requiring `inline_bytes` or
/// `inline_string` -- see this module's doc for why `filename` and
/// `environment_variable` are refused rather than read. `path` roots the
/// `DataSource` itself, so the error names its exact sub-field
/// (`<path>.filename`, `<path>.environment_variable`, ...).
fn inline_data_source(ds: &DataSource, path: &str) -> Result<Vec<u8>, ConfigError> {
    if ds.watched_directory.is_some() {
        return Err(unsupported(
            format!("{path}.watched_directory"),
            "an SDS-delivered secret carries its bytes inline; there is no file to watch",
        ));
    }
    match &ds.specifier {
        Some(Specifier::InlineBytes(bytes)) => Ok(bytes.clone()),
        Some(Specifier::InlineString(s)) => Ok(s.clone().into_bytes()),
        Some(Specifier::Filename(_)) => Err(unsupported(
            format!("{path}.filename"),
            "an SDS-delivered secret must carry its bytes inline (inline_bytes/inline_string); \
             a control plane naming a filesystem path for this proxy to read is a different \
             feature and is not implemented",
        )),
        Some(Specifier::EnvironmentVariable(_)) => Err(unsupported(
            format!("{path}.environment_variable"),
            "an SDS-delivered secret must carry its bytes inline (inline_bytes/inline_string); \
             environment_variable is not implemented for SDS delivery",
        )),
        None => Err(unsupported(
            path.to_string(),
            "DataSource has no specifier set",
        )),
    }
}

/// Lower a `TlsCertificate` oneof case, requiring `certificate_chain` and
/// `private_key` and refusing every other field it can carry (see this
/// module's doc).
fn convert_tls_certificate(
    cert: &TlsCertificate,
    path: &str,
) -> Result<(Vec<u8>, Vec<u8>), ConfigError> {
    let chain_path = format!("{path}.certificate_chain");
    let key_path = format!("{path}.private_key");

    let Some(chain_ds) = cert.certificate_chain.as_ref() else {
        return Err(unsupported(
            chain_path,
            "a tls_certificate secret must set certificate_chain",
        ));
    };
    let Some(key_ds) = cert.private_key.as_ref() else {
        return Err(unsupported(
            key_path,
            "a tls_certificate secret must set private_key",
        ));
    };
    let certificate_chain = inline_data_source(chain_ds, &chain_path)?;
    let private_key = inline_data_source(key_ds, &key_path)?;

    if cert.pkcs12.is_some() {
        return Err(unsupported(
            format!("{path}.pkcs12"),
            "PKCS12-bundled certificates are not implemented",
        ));
    }
    if cert.watched_directory.is_some() {
        return Err(unsupported(
            format!("{path}.watched_directory"),
            "explicit rotation-watch directories are not implemented",
        ));
    }
    if cert.private_key_provider.is_some() {
        return Err(unsupported(
            format!("{path}.private_key_provider"),
            "BoringSSL private-key-provider plugins are not implemented",
        ));
    }
    if cert.password.is_some() {
        return Err(unsupported(
            format!("{path}.password"),
            "password-encrypted private keys are not implemented",
        ));
    }
    if cert.ocsp_staple.is_some() {
        return Err(unsupported(
            format!("{path}.ocsp_staple"),
            "OCSP stapling is not implemented",
        ));
    }
    if !cert.signed_certificate_timestamp.is_empty() {
        return Err(unsupported(
            format!("{path}.signed_certificate_timestamp"),
            "signed certificate timestamps are not implemented",
        ));
    }

    Ok((certificate_chain, private_key))
}

/// Lower a `CertificateValidationContext` oneof case, requiring `trusted_ca`
/// and refusing every other field it can carry (see this module's doc).
fn convert_validation_context(
    vc: &CertificateValidationContext,
    path: &str,
) -> Result<Vec<u8>, ConfigError> {
    let ca_path = format!("{path}.trusted_ca");
    let Some(trusted_ca_ds) = vc.trusted_ca.as_ref() else {
        return Err(unsupported(
            ca_path,
            "a validation_context secret must set trusted_ca",
        ));
    };
    let trusted_ca = inline_data_source(trusted_ca_ds, &ca_path)?;

    if vc.ca_certificate_provider_instance.is_some() {
        return Err(unsupported(
            format!("{path}.ca_certificate_provider_instance"),
            "certificate-provider-instance CAs are not implemented",
        ));
    }
    if vc.system_root_certs.is_some() {
        return Err(unsupported(
            format!("{path}.system_root_certs"),
            "system_root_certs is not implemented for an SDS-delivered validation context",
        ));
    }
    if vc.watched_directory.is_some() {
        return Err(unsupported(
            format!("{path}.watched_directory"),
            "explicit rotation-watch directories are not implemented",
        ));
    }
    if !vc.verify_certificate_spki.is_empty() {
        return Err(unsupported(
            format!("{path}.verify_certificate_spki"),
            "SPKI pinning is not implemented",
        ));
    }
    if !vc.verify_certificate_hash.is_empty() {
        return Err(unsupported(
            format!("{path}.verify_certificate_hash"),
            "certificate-hash pinning is not implemented",
        ));
    }
    if !vc.match_typed_subject_alt_names.is_empty() {
        return Err(unsupported(
            format!("{path}.match_typed_subject_alt_names"),
            "SAN matching on an SDS-delivered validation context is not implemented",
        ));
    }
    // Rust note: `match_subject_alt_names` carries `#[deprecated]` on the
    // generated field -- reading it to check it is unset is exactly the kind
    // of read the lint exists to flag on ordinary use, so it is silenced
    // locally rather than at the module level.
    #[allow(deprecated)]
    if !vc.match_subject_alt_names.is_empty() {
        return Err(unsupported(
            format!("{path}.match_subject_alt_names"),
            "SAN matching on an SDS-delivered validation context is not implemented",
        ));
    }
    if vc.require_signed_certificate_timestamp.is_some() {
        return Err(unsupported(
            format!("{path}.require_signed_certificate_timestamp"),
            "signed certificate timestamp enforcement is not implemented",
        ));
    }
    if vc.crl.is_some() {
        return Err(unsupported(
            format!("{path}.crl"),
            "certificate revocation lists are not implemented",
        ));
    }
    if vc.allow_expired_certificate {
        return Err(unsupported(
            format!("{path}.allow_expired_certificate"),
            "accepting expired certificates on an SDS-delivered validation context is not \
             implemented",
        ));
    }
    if vc.trust_chain_verification != 0 {
        return Err(unsupported(
            format!("{path}.trust_chain_verification"),
            "only the default VERIFY_TRUST_CHAIN mode is implemented",
        ));
    }
    if vc.custom_validator_config.is_some() {
        return Err(unsupported(
            format!("{path}.custom_validator_config"),
            "custom certificate validators are not implemented",
        ));
    }
    if vc.only_verify_leaf_cert_crl {
        return Err(unsupported(
            format!("{path}.only_verify_leaf_cert_crl"),
            "certificate revocation lists are not implemented",
        ));
    }
    if vc.max_verify_depth.is_some() {
        return Err(unsupported(
            format!("{path}.max_verify_depth"),
            "a custom verify depth is not implemented",
        ));
    }

    Ok(trusted_ca)
}

/// Decode one SDS `Secret` resource's raw bytes into a [`DynamicSecret`].
/// `path` roots the dotted field path any error is reported under -- see
/// `apply.rs`'s `sds_path` for how a caller derives it.
pub fn decode_secret(any: &prost_types::Any, path: &str) -> Result<DynamicSecret, ConfigError> {
    let secret = SecretProto::decode(any.value.as_slice())
        .map_err(|e| ConfigError::Parse(format!("cannot decode `{}`: {e}", any.type_url)))?;
    let name = secret.name.clone();

    let kind = match &secret.r#type {
        Some(SecretOneof::TlsCertificate(cert)) => {
            let (certificate_chain, private_key) =
                convert_tls_certificate(cert, &format!("{path}.tls_certificate"))?;
            SecretKind::TlsCertificate {
                certificate_chain,
                private_key,
            }
        }
        Some(SecretOneof::ValidationContext(vc)) => {
            let trusted_ca = convert_validation_context(vc, &format!("{path}.validation_context"))?;
            SecretKind::ValidationContext { trusted_ca }
        }
        Some(SecretOneof::SessionTicketKeys(_)) => {
            return Err(unsupported(
                format!("{path}.session_ticket_keys"),
                "TLS session-ticket-key rotation via SDS is not implemented",
            ));
        }
        Some(SecretOneof::GenericSecret(_)) => {
            return Err(unsupported(
                format!("{path}.generic_secret"),
                "generic (filter-consumed, non-TLS) SDS secrets are not implemented",
            ));
        }
        None => {
            return Err(unsupported(
                path.to_string(),
                "Secret.type is unset -- exactly one of tls_certificate/session_ticket_keys/\
                 validation_context/generic_secret must be set",
            ));
        }
    };

    Ok(DynamicSecret { name, kind })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn any_of<T: Message>(msg: &T, type_name: &str) -> prost_types::Any {
        prost_types::Any {
            type_url: format!("type.googleapis.com/{type_name}"),
            value: msg.encode_to_vec(),
        }
    }

    fn inline_bytes(bytes: &[u8]) -> DataSource {
        DataSource {
            specifier: Some(Specifier::InlineBytes(bytes.to_vec())),
            ..Default::default()
        }
    }

    fn filename_source(path: &str) -> DataSource {
        DataSource {
            specifier: Some(Specifier::Filename(path.to_string())),
            ..Default::default()
        }
    }

    const SECRET_TYPE: &str = "envoy.extensions.transport_sockets.tls.v3.Secret";

    #[test]
    fn a_well_formed_inline_tls_certificate_secret_decodes() {
        let secret = SecretProto {
            name: "cert-1".to_string(),
            r#type: Some(SecretOneof::TlsCertificate(TlsCertificate {
                certificate_chain: Some(inline_bytes(b"chain-bytes")),
                private_key: Some(inline_bytes(b"key-bytes")),
                ..Default::default()
            })),
        };
        let any = any_of(&secret, SECRET_TYPE);
        let decoded = decode_secret(&any, "sds.secrets[cert-1]").expect("must decode");

        assert_eq!(decoded.name, "cert-1");
        match decoded.kind {
            SecretKind::TlsCertificate {
                certificate_chain,
                private_key,
            } => {
                assert_eq!(certificate_chain, b"chain-bytes");
                assert_eq!(private_key, b"key-bytes");
            }
            SecretKind::ValidationContext { .. } => panic!("expected TlsCertificate"),
        }
    }

    #[test]
    fn a_well_formed_validation_context_secret_decodes() {
        let secret = SecretProto {
            name: "ca-1".to_string(),
            r#type: Some(SecretOneof::ValidationContext(
                CertificateValidationContext {
                    trusted_ca: Some(inline_bytes(b"ca-bytes")),
                    ..Default::default()
                },
            )),
        };
        let any = any_of(&secret, SECRET_TYPE);
        let decoded = decode_secret(&any, "sds.secrets[ca-1]").expect("must decode");

        assert_eq!(decoded.name, "ca-1");
        match decoded.kind {
            SecretKind::ValidationContext { trusted_ca } => {
                assert_eq!(trusted_ca, b"ca-bytes");
            }
            SecretKind::TlsCertificate { .. } => panic!("expected ValidationContext"),
        }
    }

    #[test]
    fn a_filename_data_source_is_refused_with_its_full_dotted_path() {
        let secret = SecretProto {
            name: "cert-1".to_string(),
            r#type: Some(SecretOneof::TlsCertificate(TlsCertificate {
                certificate_chain: Some(filename_source("/etc/certs/chain.pem")),
                private_key: Some(inline_bytes(b"key-bytes")),
                ..Default::default()
            })),
        };
        let any = any_of(&secret, SECRET_TYPE);
        let err = decode_secret(&any, "sds.secrets[cert-1]").unwrap_err();
        let ConfigError::UnsupportedField { field_path, .. } = err else {
            panic!("expected UnsupportedField, got {err:?}");
        };
        assert_eq!(
            field_path,
            "sds.secrets[cert-1].tls_certificate.certificate_chain.filename"
        );
    }

    #[test]
    fn a_generic_secret_is_refused_by_name() {
        let secret = SecretProto {
            name: "opaque-1".to_string(),
            r#type: Some(SecretOneof::GenericSecret(
                proxy_api::envoy::extensions::transport_sockets::tls::v3::GenericSecret {
                    secret: Some(inline_bytes(b"whatever")),
                    ..Default::default()
                },
            )),
        };
        let any = any_of(&secret, SECRET_TYPE);
        let err = decode_secret(&any, "sds.secrets[opaque-1]").unwrap_err();
        let ConfigError::UnsupportedField { field_path, .. } = err else {
            panic!("expected UnsupportedField, got {err:?}");
        };
        assert_eq!(field_path, "sds.secrets[opaque-1].generic_secret");
    }

    #[test]
    fn an_unset_type_oneof_is_refused() {
        let secret = SecretProto {
            name: "empty-1".to_string(),
            r#type: None,
        };
        let any = any_of(&secret, SECRET_TYPE);
        let err = decode_secret(&any, "sds.secrets[empty-1]").unwrap_err();
        let ConfigError::UnsupportedField { field_path, reason } = err else {
            panic!("expected UnsupportedField, got {err:?}");
        };
        assert_eq!(field_path, "sds.secrets[empty-1]");
        assert!(reason.contains("Secret.type is unset"));
    }
}
