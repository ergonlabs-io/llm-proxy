//! Dialect parsing: `${VAR}` env interpolation -> strict YAML parse ->
//! semantic validation (checks the schema cannot express, like route ->
//! provider references).
//!
//! Same error-quality bar as Envoy mode: every failure names a field path or
//! the offending value; unknown fields are always errors.

use proxy_config::{ConfigError, ConfigWarning};

use crate::lower::resolved_dialect;
use crate::model::{
    is_valid_provider_name, Listen, ModelProviderRef, ProviderModelRef, SimpleConfig, RESERVED_KEYS,
};

/// Parse dialect YAML from a file.
pub fn load_simple_config_file(path: &std::path::Path) -> Result<SimpleConfig, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;
    parse_simple_config(&text)
}

/// Parse dialect YAML text: interpolate `${VAR}`s, deserialize strictly,
/// validate semantics.
pub fn parse_simple_config(text: &str) -> Result<SimpleConfig, ConfigError> {
    let interpolated = interpolate_env(text, &|name| std::env::var(name).ok())?;
    parse_interpolated(&interpolated)
}

/// Testable core: caller supplies the env lookup.
pub fn parse_simple_config_with_env(
    text: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<SimpleConfig, ConfigError> {
    parse_interpolated(&interpolate_env(text, env)?)
}

fn parse_interpolated(text: &str) -> Result<SimpleConfig, ConfigError> {
    let de = serde_yaml::Deserializer::from_str(text);
    let config: SimpleConfig = serde_path_to_error::deserialize(de).map_err(map_serde_error)?;
    validate_semantics(&config)?;
    Ok(config)
}

/// Turn a serde error into our error currency, keeping the field path and
/// special-casing v0's reserved top-level keys.
fn map_serde_error(err: serde_path_to_error::Error<serde_yaml::Error>) -> ConfigError {
    let path = err.path().to_string();
    let message = err.inner().to_string();
    if let Some(field) = extract_unknown_field(&message) {
        // serde_path_to_error's path already ends with the unknown field.
        let field_path = if path == "." || path.is_empty() {
            field.clone()
        } else {
            path
        };
        if RESERVED_KEYS.contains(&field.as_str()) {
            return ConfigError::UnsupportedField {
                field_path,
                reason: format!(
                    "`{field}` is reserved for a future schema version; \
                     v0 rejects it so it can be added compatibly later"
                ),
            };
        }
        return ConfigError::UnknownField { field_path };
    }
    ConfigError::InvalidValue {
        field_path: if path == "." || path.is_empty() {
            "<root>".to_string()
        } else {
            path
        },
        reason: message,
    }
}

fn extract_unknown_field(message: &str) -> Option<String> {
    let rest = message.split("unknown field `").nth(1)?;
    Some(rest[..rest.find('`')?].to_string())
}

/// Replace `${VAR}` with the environment value; `$${` escapes a literal `${`.
/// A missing variable is an error naming the variable — never an empty string.
fn interpolate_env(
    text: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<String, ConfigError> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find("${") {
        if rest[..pos].ends_with('$') {
            // `$${` -> literal `${`
            out.push_str(&rest[..pos - 1]);
            out.push_str("${");
            rest = &rest[pos + 2..];
            continue;
        }
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 2..];
        let end = after.find('}').ok_or_else(|| {
            ConfigError::Parse("unterminated `${` environment reference".to_string())
        })?;
        let name = &after[..end];
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(ConfigError::Parse(format!(
                "`${{{name}}}` is not a valid environment variable reference"
            )));
        }
        let value = env(name).ok_or_else(|| {
            ConfigError::Parse(format!(
                "environment variable `{name}` is not set (referenced as ${{{name}}})"
            ))
        })?;
        out.push_str(&value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn validate_semantics(config: &SimpleConfig) -> Result<(), ConfigError> {
    if config.version != 0 {
        return Err(ConfigError::InvalidValue {
            field_path: "version".to_string(),
            reason: format!(
                "this build understands schema version 0, not {}",
                config.version
            ),
        });
    }
    if config.providers.is_empty() {
        return Err(ConfigError::InvalidValue {
            field_path: "providers".to_string(),
            reason: "at least one provider is required".to_string(),
        });
    }
    for (name, provider) in &config.providers {
        let path = format!("providers.{name}");
        if !is_valid_provider_name(name) {
            return Err(ConfigError::InvalidValue {
                field_path: path,
                reason: format!(
                    "`{name}` is not a valid provider name (lowercase letters, digits, hyphens)"
                ),
            });
        }
        if provider.api_key.is_some() && provider.api_key_file.is_some() {
            return Err(ConfigError::InvalidValue {
                field_path: path,
                reason: "set either api_key or api_key_file, not both".to_string(),
            });
        }
        if provider.effective_base_url(name).is_none() {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{path}.base_url"),
                reason: format!(
                    "base_url is required for `{name}` (only providers named/typed \
                     openai or anthropic have an implied URL)"
                ),
            });
        }
    }

    if config.routes.is_empty() {
        return Err(ConfigError::InvalidValue {
            field_path: "routes".to_string(),
            reason: "at least one route is required".to_string(),
        });
    }
    for (i, route) in config.routes.iter().enumerate() {
        if route.model.is_empty() {
            return Err(ConfigError::InvalidValue {
                field_path: format!("routes[{i}].model"),
                reason: "model pattern must not be empty".to_string(),
            });
        }
        check_provider_ref(config, &route.provider, &format!("routes[{i}].provider"))?;
        for (j, fallback) in route.fallbacks.iter().enumerate() {
            check_provider_ref(config, fallback, &format!("routes[{i}].fallbacks[{j}]"))?;
        }
        if let Some(retries) = &route.retries {
            if retries.attempts > 5 {
                return Err(ConfigError::InvalidValue {
                    field_path: format!("routes[{i}].retries.attempts"),
                    reason: "at most 5 retry attempts are allowed".to_string(),
                });
            }
        }
    }

    for (name, model) in &config.models {
        let path = format!("models.{name}");
        if model.providers.is_empty() {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{path}.providers"),
                reason: "at least one provider is required".to_string(),
            });
        }
        for (i, entry) in model.providers.iter().enumerate() {
            // The field path for the entry itself -- there is no
            // `.provider` sub-path the way `routes[i].provider` has one,
            // because the entry IS the provider reference, whether it's the
            // shorthand string or the object form (mirrors how
            // `check_provider_ref` below points at `routes[i].provider`
            // as a whole, not deeper).
            let entry_path = format!("{path}.providers[{i}]");
            let provider_name = entry.provider();
            let Some(provider) = config.providers.get(provider_name) else {
                let known = config
                    .providers
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(ConfigError::InvalidValue {
                    field_path: entry_path,
                    reason: format!(
                        "unknown provider `{provider_name}` (defined providers: {known})"
                    ),
                });
            };
            // `resolved_dialect` returns `None` exactly for "type is
            // dialect-ambiguous (vertex/bedrock) and no explicit `dialect`
            // was set" -- the same function `lower.rs` uses to compute the
            // real dialect, so the two can never drift on what counts as
            // "resolvable".
            if resolved_dialect(provider_name, provider, entry.dialect()).is_none() {
                let type_name = provider.effective_type(provider_name).as_str();
                let (field_path, reason) = match entry {
                    // The shorthand string form has no `dialect` field to
                    // point at -- tell the user which form to switch to
                    // rather than naming a field that doesn't exist here.
                    ModelProviderRef::Shorthand(_) => (
                        entry_path,
                        format!(
                            "`{type_name}` providers serve more than one wire format under \
                             one type (e.g. Vertex hosts Anthropic-, Google-, and \
                             OpenAI-shaped models), so `dialect` cannot be derived here; the \
                             shorthand string form cannot carry `dialect` -- use the object \
                             form ({{ provider, model, dialect }}) and set it explicitly"
                        ),
                    ),
                    ModelProviderRef::Full(_) => (
                        format!("{entry_path}.dialect"),
                        format!(
                            "`{type_name}` providers serve more than one wire format under \
                             one type (e.g. Vertex hosts Anthropic-, Google-, and \
                             OpenAI-shaped models), so `dialect` cannot be derived here and \
                             must be set explicitly"
                        ),
                    ),
                };
                return Err(ConfigError::InvalidValue { field_path, reason });
            }
        }
    }

    for (i, limit) in config.limits.iter().enumerate() {
        if limit.tokens_per_minute.is_none()
            && limit.requests_per_minute.is_none()
            && limit.concurrent_sessions.is_none()
        {
            return Err(ConfigError::InvalidValue {
                field_path: format!("limits[{i}]"),
                reason: "a limit needs at least one of tokens_per_minute, \
                         requests_per_minute, concurrent_sessions"
                    .to_string(),
            });
        }
    }

    if let Some(listen) = &config.listen {
        let addr = match listen {
            Listen::Address(a) => a,
            Listen::Full(spec) => &spec.address,
        };
        parse_host_port(addr, "listen")?;
    }
    if let Some(admin) = &config.admin {
        parse_host_port(admin, "admin")?;
    }
    Ok(())
}

fn check_provider_ref(
    config: &SimpleConfig,
    reference: &ProviderModelRef,
    path: &str,
) -> Result<(), ConfigError> {
    if !config.providers.contains_key(&reference.provider) {
        let known = config
            .providers
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        return Err(ConfigError::InvalidValue {
            field_path: path.to_string(),
            reason: format!(
                "unknown provider `{}` (defined providers: {known})",
                reference.provider
            ),
        });
    }
    Ok(())
}

/// Parse `host:port` (IPv6 in brackets) into (host, port).
pub fn parse_host_port(s: &str, path: &str) -> Result<(String, u16), ConfigError> {
    let bad = |reason: String| ConfigError::InvalidValue {
        field_path: path.to_string(),
        reason,
    };
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| bad(format!("`{s}` is missing the closing `]`")))?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| bad(format!("`{s}` is missing `:port` after `]`")))?;
        (host.to_string(), port)
    } else {
        let (host, port) = s
            .rsplit_once(':')
            .ok_or_else(|| bad(format!("`{s}` is not `host:port`")))?;
        (host.to_string(), port)
    };
    let port: u16 = port
        .parse()
        .map_err(|_| bad(format!("`{s}` has an invalid port")))?;
    if host.is_empty() {
        return Err(bad(format!("`{s}` has an empty host")));
    }
    Ok((host, port))
}

/// Heuristic used by the binary for a helpful cross-mode error: does this text
/// look like a dialect config (vs an Envoy bootstrap)?
pub fn looks_like_simple_config(text: &str) -> bool {
    text.lines().any(|l| {
        let l = l.trim_end();
        l == "providers:" || l.starts_with("version:")
    })
}

/// Inverse heuristic: does this look like an Envoy bootstrap?
pub fn looks_like_envoy_bootstrap(text: &str) -> bool {
    text.lines()
        .any(|l| matches!(l.trim_end(), "static_resources:" | "dynamic_resources:"))
}

/// Warnings type re-exported for lowering.
pub type Warnings = Vec<ConfigWarning>;
