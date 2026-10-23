//! Strict decoder for `node.metadata["io.llmproxy.admin_tls"]`: TLS on the
//! admin listener (the dialect's `admin.tls`). Envoy's admin has no TLS of
//! its own, so this is our namespace beside the ledger and trace ones, and
//! the dialect lowers into it (AGENTS.md invariant 5).
//!
//! `google.protobuf.Struct` is opaque to the reflective surface walk, so
//! AGENTS.md invariant 1 is enforced here by hand: every unknown key and
//! every bad value fails with its full dotted path.

use crate::error::ConfigError;
use crate::ir::{DataSourceIR, DownstreamTlsSpec, TlsCertificateIR, TlsParametersIR, TlsVersion};
use prost_types::value::Kind;
use std::path::PathBuf;

pub(crate) const ADMIN_TLS_METADATA_KEY: &str = "io.llmproxy.admin_tls";

const FIELDS: &[&str] = &["cert_file", "key_file"];

fn invalid(path: impl Into<String>, reason: &str) -> ConfigError {
    ConfigError::InvalidValue {
        field_path: path.into(),
        reason: reason.into(),
    }
}

/// Read `node.metadata["io.llmproxy.admin_tls"]`. `None` when absent: the
/// admin listener serves plain HTTP. `admin_configured` is whether the
/// bootstrap has an `admin` block; TLS without one would be inert, and an
/// inert block is a silent accept.
pub(crate) fn convert(
    node: Option<&proxy_api::envoy::config::core::v3::Node>,
    path: &str,
    admin_configured: bool,
) -> Result<Option<DownstreamTlsSpec>, ConfigError> {
    let Some(value) = node
        .and_then(|n| n.metadata.as_ref())
        .and_then(|m| m.fields.get(ADMIN_TLS_METADATA_KEY))
    else {
        return Ok(None);
    };
    let root = format!("{path}.metadata[\"{ADMIN_TLS_METADATA_KEY}\"]");
    if !admin_configured {
        return Err(invalid(&root, "requires an admin address"));
    }
    let Some(Kind::StructValue(s)) = &value.kind else {
        return Err(invalid(&root, "must be an object"));
    };
    // Rust note: `Struct::fields` is a `HashMap`; sort so the reported key
    // is the same on every run.
    let mut unknown: Vec<_> = s
        .fields
        .keys()
        .filter(|k| !FIELDS.contains(&k.as_str()))
        .collect();
    unknown.sort();
    if let Some(k) = unknown.first() {
        return Err(ConfigError::UnsupportedField {
            field_path: format!("{root}.{k}"),
            reason: format!(
                "unsupported admin TLS field; supported: {}",
                FIELDS.join(", ")
            ),
        });
    }
    let file = |key: &str| -> Result<DataSourceIR, ConfigError> {
        match s.fields.get(key).and_then(|v| v.kind.as_ref()) {
            None => Err(invalid(format!("{root}.{key}"), "is required")),
            Some(Kind::StringValue(v)) if v.is_empty() => {
                Err(invalid(format!("{root}.{key}"), "must not be empty"))
            }
            Some(Kind::StringValue(v)) => Ok(DataSourceIR::File(PathBuf::from(v))),
            Some(_) => Err(invalid(format!("{root}.{key}"), "must be a string")),
        }
    };
    Ok(Some(DownstreamTlsSpec {
        certificates: vec![TlsCertificateIR {
            cert_chain: file("cert_file")?,
            private_key: file("key_file")?,
        }],
        certificate_sds_names: Vec::new(),
        // A downstream context with no `tls_params`: Envoy's server-side
        // TLS_AUTO range.
        params: TlsParametersIR {
            min_version: TlsVersion::V1_2,
            max_version: TlsVersion::V1_3,
            cipher_suites: Vec::new(),
            ecdh_curves: Vec::new(),
        },
        // The admin server speaks HTTP/1.1 only.
        alpn_protocols: vec!["http/1.1".to_string()],
        validation: None,
        validation_sds_name: None,
        require_client_certificate: false,
        disable_stateless_session_resumption: false,
    }))
}
