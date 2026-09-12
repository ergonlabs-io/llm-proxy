//! Dialect parsing: `${VAR}` env interpolation -> strict YAML parse ->
//! semantic validation (checks the schema cannot express, like route ->
//! provider references).
//!
//! Same error-quality bar as Envoy mode: every failure names a field path or
//! the offending value; unknown fields are always errors.

use proxy_config::{ConfigError, ConfigFrontEnd, ConfigWarning};

use crate::lower::{classify_model_key, dialect_from_models, resolved_dialect};
use crate::model::{
    is_valid_provider_name, Listen, ModelProviderRef, Provider, ProviderModelRef, ProviderType,
    SimpleConfig, RESERVED_KEYS,
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
        return ConfigError::UnknownField {
            field_path,
            front_end: ConfigFrontEnd::Dialect,
        };
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
        match provider.effective_type(name) {
            ProviderType::AzureOpenai => validate_azure_provider(name, provider)?,
            _ => {
                if provider.deployment.is_some() {
                    return Err(ConfigError::InvalidValue {
                        field_path: format!("{path}.deployment"),
                        reason: "deployment is only valid for azure-openai providers".into(),
                    });
                }
                if provider.api_version.is_some() {
                    return Err(ConfigError::InvalidValue {
                        field_path: format!("{path}.api_version"),
                        reason: "api_version is only valid for azure-openai providers".into(),
                    });
                }
            }
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
        // WP-49 increment 2: a catalogue key's `*` placement must be exact,
        // a single trailing wildcard, or the bare `*` -- anything else (a
        // mid-string glob, more than one `*`) is a load error naming this
        // path, never silently treated as a literal or as `routes[].model`'s
        // wider `safe_regex` grammar.
        classify_model_key(name).map_err(|reason| ConfigError::InvalidValue {
            field_path: path.clone(),
            reason,
        })?;
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

    // `routes:` references, checked only now that the `models:` loop above has
    // validated every entry -- `dialect_from_models` reads those entries, and
    // a models-surface error deserves its own more specific message first.
    //
    // A `ProviderModelRef` is `{ provider, model }` and nothing else: only
    // `models:`'s object form carries `dialect`. So for a dialect-ambiguous
    // type the wire format has to come from a `models:` entry, and when none
    // pins it the old behaviour was to answer `openai` silently. That sends an
    // Anthropic-shaped response to the OpenAI usage parser, which reads no
    // usage at all, which lets the token limiter fail open (it warns now, but
    // it still admits the request uncharged) -- a quota bypass produced by a
    // config the loader accepted. Ground rule #1: name the path and refuse.
    for (i, route) in config.routes.iter().enumerate() {
        check_route_ref_dialect(config, &route.provider, &format!("routes[{i}].provider"))?;
        for (j, fallback) in route.fallbacks.iter().enumerate() {
            check_route_ref_dialect(config, fallback, &format!("routes[{i}].fallbacks[{j}]"))?;
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

fn validate_azure_provider(name: &str, provider: &Provider) -> Result<(), ConfigError> {
    let path = format!("providers.{name}");
    let deployment = provider
        .deployment
        .as_deref()
        .ok_or_else(|| ConfigError::InvalidValue {
            field_path: format!("{path}.deployment"),
            reason: "deployment is required for azure-openai providers".into(),
        })?;
    if !is_safe_url_component(deployment) {
        return Err(ConfigError::InvalidValue {
            field_path: format!("{path}.deployment"),
            reason: "must contain only ASCII letters, digits, hyphen, dot, underscore, or tilde"
                .into(),
        });
    }

    let api_version = provider
        .api_version
        .as_deref()
        .ok_or_else(|| ConfigError::InvalidValue {
            field_path: format!("{path}.api_version"),
            reason: "api_version is required for azure-openai providers".into(),
        })?;
    if !is_safe_url_component(api_version) {
        return Err(ConfigError::InvalidValue {
            field_path: format!("{path}.api_version"),
            reason: "must contain only ASCII letters, digits, hyphen, dot, underscore, or tilde"
                .into(),
        });
    }
    Ok(())
}

fn is_safe_url_component(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
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

/// A `routes:` provider reference must end up with a wire format that was
/// *stated*, not guessed. For unambiguous types the type states it; for
/// Vertex/Bedrock only a `models:` entry can, since the route surface has no
/// `dialect` field -- see the call site for what guessing costs.
fn check_route_ref_dialect(
    config: &SimpleConfig,
    reference: &ProviderModelRef,
    path: &str,
) -> Result<(), ConfigError> {
    // `check_provider_ref` already ran for this same path, so the name resolves.
    let Some(provider) = config.providers.get(&reference.provider) else {
        return Ok(());
    };
    let provider_type = provider.effective_type(&reference.provider);
    if !provider_type.dialect_is_ambiguous() {
        return Ok(());
    }
    if dialect_from_models(config, &reference.provider)?.is_some() {
        return Ok(());
    }
    Err(ConfigError::InvalidValue {
        field_path: path.to_string(),
        reason: format!(
            "`{}` providers serve more than one wire format under one type (e.g. Vertex \
             hosts Anthropic-, Google-, and OpenAI-shaped models), so the dialect cannot be \
             derived here, and a `routes:` provider reference has no `dialect` field to \
             carry it -- add a `models:` entry for `{}` using the object form \
             ({{ provider, model, dialect }}), which states it explicitly",
            provider_type.as_str(),
            reference.provider
        ),
    })
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
