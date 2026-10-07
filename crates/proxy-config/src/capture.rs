//! Strict decoder for the handwritten metadata-only capture namespace.
#[cfg(unix)]
mod unix {
    use crate::error::ConfigError;
    use prost_types::{value::Kind, Struct, Value};
    use proxy_observability::{capture_policy::*, capture_transport::*};
    use std::{path::PathBuf, time::Duration};
    const ROOT: &str = "node.metadata[\"io.llmproxy.capture\"]";
    fn error(path: impl Into<String>, reason: &str) -> ConfigError {
        ConfigError::InvalidValue {
            field_path: path.into(),
            reason: reason.into(),
        }
    }
    fn object<'a>(value: &'a Value, path: &str, keys: &[&str]) -> Result<&'a Struct, ConfigError> {
        let Some(Kind::StructValue(s)) = &value.kind else {
            return Err(error(path, "must be an object"));
        };
        let mut unknown: Vec<_> = s
            .fields
            .keys()
            .filter(|k| !keys.contains(&k.as_str()))
            .collect();
        unknown.sort();
        if let Some(k) = unknown.first() {
            return Err(ConfigError::UnsupportedField {
                field_path: format!("{path}.{k}"),
                reason: "unsupported capture field".into(),
            });
        }
        Ok(s)
    }
    fn required<'a>(s: &'a Struct, key: &str, path: &str) -> Result<&'a Value, ConfigError> {
        s.fields
            .get(key)
            .ok_or_else(|| error(format!("{path}.{key}"), "required"))
    }
    fn number(
        s: &Struct,
        key: &str,
        path: &str,
        default: Option<usize>,
        min: usize,
        max: usize,
    ) -> Result<usize, ConfigError> {
        let p = format!("{path}.{key}");
        let Some(v) = s.fields.get(key) else {
            return default.ok_or_else(|| error(&p, "required"));
        };
        let Some(Kind::NumberValue(n)) = v.kind else {
            return Err(error(&p, "must be an integer"));
        };
        if !n.is_finite()
            || n.fract() != 0.0
            || n < min as f64
            || n > max as f64
            || n > 9_007_199_254_740_991.0
        {
            return Err(error(&p, "integer outside supported range"));
        }
        Ok(n as usize)
    }
    fn text(s: &Struct, key: &str, path: &str) -> Result<String, ConfigError> {
        let p = format!("{path}.{key}");
        let v = required(s, key, path)?;
        let Some(Kind::StringValue(v)) = &v.kind else {
            return Err(error(&p, "must be a string"));
        };
        if v.is_empty() || v.len() > 128 || v.chars().any(char::is_control) {
            return Err(error(&p, "must be 1–128 bytes without control characters"));
        }
        Ok(v.clone())
    }
    fn socket(s: &Struct, path: &str) -> Result<PathBuf, ConfigError> {
        let p = format!("{path}.unix_socket_path");
        let v = text(s, "unix_socket_path", path)?;
        // Darwin has the smallest supported pathname sockaddr_un envelope.
        if v.len() > 103 || !PathBuf::from(&v).is_absolute() {
            return Err(error(
                p,
                "must be an absolute Unix pathname of at most 103 bytes",
            ));
        }
        Ok(v.into())
    }
    fn seconds(
        s: &Struct,
        key: &str,
        path: &str,
        default: Duration,
        min: f64,
        max: f64,
    ) -> Result<Duration, ConfigError> {
        let Some(v) = s.fields.get(key) else {
            return Ok(default);
        };
        let p = format!("{path}.{key}");
        let Some(Kind::NumberValue(n)) = v.kind else {
            return Err(error(p, "must be numeric seconds"));
        };
        if !n.is_finite() || n < min || n > max {
            return Err(error(p, "duration outside supported range"));
        }
        Duration::try_from_secs_f64(n).map_err(|_| error(p, "duration is not representable"))
    }
    pub(crate) fn convert(
        node: Option<&proxy_api::envoy::config::core::v3::Node>,
    ) -> Result<Option<EndUserCaptureConfig>, ConfigError> {
        let Some(value) = node
            .and_then(|n| n.metadata.as_ref())
            .and_then(|m| m.fields.get("io.llmproxy.capture"))
        else {
            return Ok(None);
        };
        let root = object(
            value,
            ROOT,
            &[
                "version",
                "metadata",
                "policy",
                "endpoint",
                "budgets",
                "transport",
                "emergency_control",
            ],
        )?;
        number(root, "version", ROOT, None, 1, 1)?;
        let mp = format!("{ROOT}.metadata");
        let metadata = root
            .fields
            .get("metadata")
            .map(|v| {
                object(
                    v,
                    &mp,
                    &[
                        "enabled",
                        "max_attempts",
                        "max_record_retained_bytes",
                        "max_encoded_record_bytes",
                    ],
                )
            })
            .transpose()?;
        let enabled = match metadata.and_then(|s| s.fields.get("enabled")) {
            None => false,
            Some(Value {
                kind: Some(Kind::BoolValue(b)),
            }) => *b,
            _ => return Err(error(format!("{mp}.enabled"), "must be boolean")),
        };
        if !enabled {
            if let Some(m) = metadata {
                if let Some(k) = m.fields.keys().filter(|k| k.as_str() != "enabled").min() {
                    return Err(error(
                        format!("{mp}.{k}"),
                        "not permitted when capture is disabled",
                    ));
                }
            }
            if let Some(k) = root
                .fields
                .keys()
                .filter(|k| !matches!(k.as_str(), "version" | "metadata"))
                .min()
            {
                return Err(error(
                    format!("{ROOT}.{k}"),
                    "not permitted when capture is disabled",
                ));
            }
            return Ok(None);
        }
        let m = metadata.unwrap();
        let metadata = MetadataCapturePolicy {
            max_attempts: number(m, "max_attempts", &mp, Some(8), 1, 64)? as u16,
            max_record_retained_bytes: number(
                m,
                "max_record_retained_bytes",
                &mp,
                Some(65536),
                4096,
                65536,
            )?,
            max_encoded_record_bytes: number(
                m,
                "max_encoded_record_bytes",
                &mp,
                Some(524288),
                4096,
                524288,
            )?,
        };
        let pp = format!("{ROOT}.policy");
        let policy = object(required(root, "policy", ROOT)?, &pp, &["version"])?;
        let policy_version = metadata.effective_version(&text(policy, "version", &pp)?);
        let ep = format!("{ROOT}.endpoint");
        let endpoint = object(
            required(root, "endpoint", ROOT)?,
            &ep,
            &[
                "unix_socket_path",
                "expected_agent_uid",
                "expected_node_id",
                "producer_id",
            ],
        )?;
        let endpoint = AgentTransportConfig {
            socket_path: socket(endpoint, &ep)?,
            expected_agent_uid: number(
                endpoint,
                "expected_agent_uid",
                &ep,
                None,
                0,
                u32::MAX as usize,
            )? as u32,
            expected_node_id: text(endpoint, "expected_node_id", &ep)?,
            producer_id: text(endpoint, "producer_id", &ep)?,
        };
        let cp = format!("{ROOT}.emergency_control");
        let c = object(
            required(root, "emergency_control", ROOT)?,
            &cp,
            &["unix_socket_path", "operator_uid"],
        )?;
        let emergency_control = LocalCaptureControl {
            unix_socket_path: socket(c, &cp)?,
            operator_uid: number(c, "operator_uid", &cp, None, 0, u32::MAX as usize)? as u32,
        };
        if emergency_control.unix_socket_path == endpoint.socket_path {
            return Err(error(
                format!("{cp}.unix_socket_path"),
                "must differ from agent socket",
            ));
        }
        let mut budgets = CaptureBudgets::default();
        let bp = format!("{ROOT}.budgets");
        if let Some(v) = root.fields.get("budgets") {
            let b = object(
                v,
                &bp,
                &[
                    "max_active_requests",
                    "max_request_state_bytes",
                    "max_queue_events",
                    "max_queue_retained_bytes",
                    "max_in_flight_events",
                    "max_transport_retained_bytes",
                    "max_capture_memory_bytes",
                ],
            )?;
            budgets.max_active_requests = number(
                b,
                "max_active_requests",
                &bp,
                Some(budgets.max_active_requests),
                1,
                65536,
            )?;
            budgets.max_request_state_bytes = number(
                b,
                "max_request_state_bytes",
                &bp,
                Some(budgets.max_request_state_bytes),
                4096,
                65536,
            )?;
            budgets.max_queue_events = number(
                b,
                "max_queue_events",
                &bp,
                Some(budgets.max_queue_events),
                1,
                65536,
            )?;
            budgets.max_in_flight_events = number(
                b,
                "max_in_flight_events",
                &bp,
                Some(budgets.max_in_flight_events),
                1,
                16,
            )?;
            budgets.max_queue_retained_bytes = number(
                b,
                "max_queue_retained_bytes",
                &bp,
                Some(budgets.max_queue_retained_bytes),
                1,
                usize::MAX,
            )?;
            budgets.max_transport_retained_bytes = number(
                b,
                "max_transport_retained_bytes",
                &bp,
                Some(budgets.max_transport_retained_bytes),
                1,
                usize::MAX,
            )?;
            budgets.max_capture_memory_bytes = number(
                b,
                "max_capture_memory_bytes",
                &bp,
                Some(budgets.max_capture_memory_bytes),
                1,
                usize::MAX,
            )?;
        }
        budgets
            .validate(&metadata)
            .map_err(|(field, why)| error(format!("{bp}.{field}"), why))?;
        let mut transport = CaptureTransportLimits::default();
        let tp = format!("{ROOT}.transport");
        if let Some(v) = root.fields.get("transport") {
            let t = object(
                v,
                &tp,
                &[
                    "connect_deadline_seconds",
                    "write_deadline_seconds",
                    "ack_deadline_seconds",
                    "event_deadline_seconds",
                    "backoff_initial_seconds",
                    "backoff_max_seconds",
                    "max_attempts",
                    "drain_deadline_seconds",
                ],
            )?;
            transport.connect_deadline = seconds(
                t,
                "connect_deadline_seconds",
                &tp,
                transport.connect_deadline,
                0.01,
                5.0,
            )?;
            transport.write_deadline = seconds(
                t,
                "write_deadline_seconds",
                &tp,
                transport.write_deadline,
                0.01,
                10.0,
            )?;
            transport.ack_deadline = seconds(
                t,
                "ack_deadline_seconds",
                &tp,
                transport.ack_deadline,
                0.01,
                30.0,
            )?;
            transport.event_deadline = seconds(
                t,
                "event_deadline_seconds",
                &tp,
                transport.event_deadline,
                0.1,
                60.0,
            )?;
            transport.backoff_initial = seconds(
                t,
                "backoff_initial_seconds",
                &tp,
                transport.backoff_initial,
                0.01,
                5.0,
            )?;
            transport.backoff_max = seconds(
                t,
                "backoff_max_seconds",
                &tp,
                transport.backoff_max,
                0.01,
                30.0,
            )?;
            transport.drain_deadline = seconds(
                t,
                "drain_deadline_seconds",
                &tp,
                transport.drain_deadline,
                0.1,
                30.0,
            )?;
            transport.max_attempts = number(t, "max_attempts", &tp, Some(4), 1, 16)? as u16;
            if transport.backoff_initial > transport.backoff_max {
                return Err(error(
                    format!("{tp}.backoff_initial_seconds"),
                    "must not exceed backoff_max_seconds",
                ));
            }
        }
        Ok(Some(EndUserCaptureConfig {
            metadata,
            policy_version,
            endpoint,
            budgets,
            transport,
            emergency_control,
        }))
    }
}
#[cfg(unix)]
pub(crate) use unix::convert;
