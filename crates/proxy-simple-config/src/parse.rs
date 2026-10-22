//! Interpolate environment variables, parse strict YAML, then validate
//! semantic constraints such as route-to-provider references. Errors retain
//! field paths and unknown fields are always rejected.

use proxy_config::{ConfigError, ConfigFrontEnd, ConfigWarning};

use crate::lower::{classify_model_key, dialect_from_models, resolved_dialect};
use crate::model::{
    is_valid_provider_name, Listen, ListenerSpec, ModelDef, ModelProviderRef, ModelSelection,
    OAuth2JwtBearerDef, Provider, ProviderModelRef, ProviderType, SimpleConfig, SimpleDuration,
    RESERVED_KEYS,
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
///
/// References inside YAML comments are left alone, so a commented-out example
/// such as `# api_key: ${OPENAI_API_KEY}` does not demand the variable.
/// Interpolation stays textual (rather than walking parsed scalars) because
/// `{ api_key: ${KEY} }` is not valid YAML until the reference is replaced,
/// and because a substituted value keeps its YAML type (`port: ${PORT}`).
fn interpolate_env(
    text: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<String, ConfigError> {
    let comment = comment_mask(text);
    let mut out = String::with_capacity(text.len());
    let mut first_unset: Option<&str> = None;
    let mut offset = 0;
    while let Some(found) = text[offset..].find("${") {
        let pos = offset + found;
        if comment[pos] {
            out.push_str(&text[offset..pos + 2]);
            offset = pos + 2;
            continue;
        }
        if text[offset..pos].ends_with('$') {
            // `$${` -> literal `${`
            out.push_str(&text[offset..pos - 1]);
            out.push_str("${");
            offset = pos + 2;
            continue;
        }
        out.push_str(&text[offset..pos]);
        let after = &text[pos + 2..];
        let end = after.find('}').ok_or_else(|| {
            ConfigError::Parse("unterminated `${` environment reference".to_string())
        })?;
        let name = &after[..end];
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(ConfigError::Parse(format!(
                "`${{{name}}}` is not a valid environment variable reference"
            )));
        }
        match env(name) {
            Some(value) => out.push_str(&value),
            None if first_unset.is_none() => {
                first_unset = Some(name);
                out.push_str(UNSET_MARKER);
            }
            // Only the first unset variable is reported; keep the text
            // parseable so that one can be located.
            None => out.push_str("unset"),
        }
        offset = pos + 2 + end + 1;
    }
    out.push_str(&text[offset..]);
    match first_unset {
        None => Ok(out),
        Some(name) => {
            let reason =
                format!("environment variable `{name}` is not set (referenced as ${{{name}}})");
            Err(match locate_marker(&out) {
                Some(field_path) => ConfigError::InvalidValue { field_path, reason },
                None => ConfigError::Parse(reason),
            })
        }
    }
}

/// Stands in for the first unset variable so the YAML can be parsed to find
/// the field that referenced it. Valid in plain, quoted, and flow scalars.
const UNSET_MARKER: &str = "__llmproxy_unset_env__";

/// Dotted path of the scalar holding [`UNSET_MARKER`], in the same form as
/// deserialization errors (`providers.openai.api_key`, `routes[0].provider`).
/// `None` when the text does not parse or the marker sits in a mapping key.
fn locate_marker(text: &str) -> Option<String> {
    fn walk(value: &serde_yaml::Value, path: &str) -> Option<String> {
        match value {
            serde_yaml::Value::String(s) if s.contains(UNSET_MARKER) => Some(if path.is_empty() {
                "<root>".to_string()
            } else {
                path.to_string()
            }),
            serde_yaml::Value::Mapping(map) => map.iter().find_map(|(key, value)| {
                let key = key.as_str()?;
                let path = if path.is_empty() {
                    key.to_string()
                } else {
                    format!("{path}.{key}")
                };
                walk(value, &path)
            }),
            serde_yaml::Value::Sequence(items) => items
                .iter()
                .enumerate()
                .find_map(|(i, item)| walk(item, &format!("{path}[{i}]"))),
            serde_yaml::Value::Tagged(tagged) => walk(&tagged.value, path),
            _ => None,
        }
    }
    walk(&serde_yaml::from_str(text).ok()?, "")
}

/// Marks every byte of `text` that is inside a YAML comment.
///
/// This is a scan, not a parser, so its mistakes must fall on the loud side:
/// text wrongly taken as a value gets interpolated (an unset variable still
/// fails the load), while text wrongly taken as a comment would leave a
/// literal `${VAR}` in a value. Hence a quote opens a string after any
/// non-alphanumeric byte, and a block scalar runs while lines are indented
/// past the line that introduced it.
fn comment_mask(text: &str) -> Vec<bool> {
    enum State {
        Normal,
        Comment,
        Single,
        Double,
        /// Block scalar (`|` or `>`) introduced on a line with this indent.
        Block(usize),
    }
    let bytes = text.as_bytes();
    let mut mask = vec![false; bytes.len()];
    let mut state = State::Normal;
    let mut line_start = true;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if line_start {
            line_start = false;
            if let State::Block(parent) = state {
                let indent = bytes[i..].iter().take_while(|&&c| c == b' ').count();
                let rest = &bytes[i + indent..];
                let blank = rest.first().is_none_or(|&c| c == b'\n' || c == b'\r');
                if blank || indent > parent {
                    // Block content is literal text: skip the whole line.
                    let len = rest.iter().position(|&c| c == b'\n').unwrap_or(rest.len());
                    i += indent + len;
                    continue;
                }
                state = State::Normal;
            }
        }
        let prev = if i == 0 { b'\n' } else { bytes[i - 1] };
        match state {
            State::Comment => mask[i] = true,
            State::Single if b == b'\'' => {
                if bytes.get(i + 1) == Some(&b'\'') {
                    i += 1; // `''` is an escaped quote
                } else {
                    state = State::Normal;
                }
            }
            State::Double if b == b'\\' => i += 1,
            State::Double if b == b'"' => state = State::Normal,
            State::Single | State::Double | State::Block(_) => {}
            State::Normal => match b {
                b'#' if prev.is_ascii_whitespace() => {
                    state = State::Comment;
                    mask[i] = true;
                }
                b'\'' if !prev.is_ascii_alphanumeric() => state = State::Single,
                b'"' if !prev.is_ascii_alphanumeric() => state = State::Double,
                b'|' | b'>'
                    if prev.is_ascii_whitespace() && starts_block_scalar(&bytes[i + 1..]) =>
                {
                    let line = bytes[..i]
                        .iter()
                        .rposition(|&c| c == b'\n')
                        .map_or(0, |p| p + 1);
                    let indent = bytes[line..].iter().take_while(|&&c| c == b' ').count();
                    state = State::Block(indent);
                    // The header line may still end in a comment.
                    let header = &bytes[i + 1..];
                    let len = header
                        .iter()
                        .position(|&c| c == b'\n')
                        .unwrap_or(header.len());
                    if let Some(hash) = header[..len].iter().position(|&c| c == b'#') {
                        mask[i + 1 + hash..i + 1 + len].fill(true);
                    }
                    i += len;
                }
                _ => {}
            },
        }
        if bytes.get(i) == Some(&b'\n') {
            line_start = true;
            if let State::Comment = state {
                mask[i] = false;
                state = State::Normal;
            }
        }
        i += 1;
    }
    mask
}

/// Whether the bytes after a `|` or `>` complete a block scalar header:
/// optional chomping/indentation indicators, then end of line or a comment.
fn starts_block_scalar(after: &[u8]) -> bool {
    let rest = after
        .iter()
        .skip_while(|&&c| c == b'+' || c == b'-' || c.is_ascii_digit())
        .skip_while(|&&c| c == b' ' || c == b'\t')
        .copied()
        .next();
    matches!(rest, None | Some(b'\n' | b'\r' | b'#'))
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
        let provider_type = provider.effective_type(name);
        validate_provider_specific_fields(name, provider, provider_type)?;
        match provider_type {
            ProviderType::AzureOpenai => validate_azure_provider(name, provider)?,
            ProviderType::Vertex => validate_vertex_provider(name, provider)?,
            ProviderType::Bedrock => validate_bedrock_provider(name, provider)?,
            _ => validate_non_azure_provider(name, provider)?,
        }
        if provider.effective_base_url(name).is_none() {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{path}.base_url"),
                reason: format!(
                    "base_url is required for `{name}` (only providers named/typed \
                     openai, anthropic, or openrouter have an implied URL)"
                ),
            });
        }
    }

    if config.routes.is_empty() && config.models.is_empty() {
        return Err(ConfigError::InvalidValue {
            field_path: "routes".to_string(),
            reason: "at least one route or model is required".to_string(),
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
        // A catalogue key's `*` placement must be exact,
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
        check_model_weights(name, model, &path)?;
        check_session_affinity(config, model, &path)?;
        check_selection(model, &path)?;
    }

    // Validate model entries first so dialect lookup cannot mask a more
    // specific models error. Ambiguous provider types require an explicit
    // dialect: guessing can make usage parsing fail and bypass token charging
    // (AGENTS.md "Architecture Invariants", 1).
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
        if let Listen::Full(ListenerSpec {
            max_request_body_bytes: Some(0),
            ..
        }) = listen
        {
            // Envoy mode rejects an explicit 0 too: it would answer every
            // request that has a body with 413.
            return Err(ConfigError::InvalidValue {
                field_path: "listen.max_request_body_bytes".to_string(),
                reason: "must be greater than 0; 0 would reject every request body".to_string(),
            });
        }
        if let Listen::Full(ListenerSpec {
            max_connections: Some(0),
            ..
        }) = listen
        {
            // Envoy's DownstreamConnectionsConfig requires a positive limit.
            return Err(ConfigError::InvalidValue {
                field_path: "listen.max_connections".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }
        if let Listen::Full(spec) = listen {
            // The same bounds the HCM proto puts on the fields these lower to,
            // checked here so the error names the dialect path.
            if let Some(kb) = spec
                .max_request_headers_kb
                .filter(|kb| !(1..=8192).contains(kb))
            {
                return Err(ConfigError::InvalidValue {
                    field_path: "listen.max_request_headers_kb".to_string(),
                    reason: format!("must be in 1..=8192, got {kb}"),
                });
            }
            if spec.max_request_headers_count == Some(0) {
                return Err(ConfigError::InvalidValue {
                    field_path: "listen.max_request_headers_count".to_string(),
                    reason: "must be greater than 0".to_string(),
                });
            }
            if let Some(hops) = spec.trusted_hops.filter(|&h| u32::try_from(h).is_err()) {
                return Err(ConfigError::InvalidValue {
                    field_path: "listen.trusted_hops".to_string(),
                    reason: format!("must be in 0..={}, got {hops}", u32::MAX),
                });
            }
        }
    }
    if let Some(admin) = &config.admin {
        parse_host_port(admin, "admin")?;
    }
    validate_auto(config)?;
    validate_guardrails(config)?;
    validate_output_caps(config)?;
    Ok(())
}

/// A zero cap blocks every request. `auto:` cannot use this cap because it is
/// read from the requested model's route, not the resolved model's route.
fn validate_output_caps(config: &SimpleConfig) -> Result<(), ConfigError> {
    for (name, model) in &config.models {
        let Some(cap) = model.max_output_tokens else {
            continue;
        };
        let field_path = format!("models.{name}.max_output_tokens");
        if cap == 0 {
            return Err(ConfigError::InvalidValue {
                field_path,
                reason: "must be greater than 0".to_string(),
            });
        }
        if config.auto.is_some() {
            return Err(ConfigError::InvalidValue {
                field_path,
                reason: "is not supported together with the `auto` block: the cap is chosen \
                         before `auto` resolves to a model, so the resolved model's cap would \
                         not apply"
                    .to_string(),
            });
        }
    }
    Ok(())
}

/// `guardrails:` checks. Each failure the filter would report at its
/// `typed_config` path is reported here at the dialect path instead.
fn validate_guardrails(config: &SimpleConfig) -> Result<(), ConfigError> {
    let Some(guardrails) = &config.guardrails else {
        return Ok(());
    };
    let invalid = |field_path: String, reason: &str| ConfigError::InvalidValue {
        field_path,
        reason: reason.to_string(),
    };
    let Some(default) = &guardrails.default else {
        return Err(invalid(
            "guardrails.default".to_string(),
            "is required: a request with no tenant entry must still be checked",
        ));
    };
    if !guardrails.tenants.is_empty() && config.auth.is_none() {
        return Err(invalid(
            "guardrails.tenants".to_string(),
            "requires an `auth` block: without authentication no request has a tenant, so \
             these checks would never apply",
        ));
    }
    if guardrails.tenants.contains_key("") {
        return Err(invalid(
            "guardrails.tenants".to_string(),
            "a tenant must not be empty",
        ));
    }
    let checks = std::iter::once(("guardrails.default".to_string(), default)).chain(
        guardrails
            .tenants
            .iter()
            .map(|(tenant, check)| (format!("guardrails.tenants.{tenant}"), check)),
    );
    for (path, check) in checks {
        let Some(http) = &check.http else {
            return Err(invalid(
                path,
                "a backend is required; `http` is the only backend supported",
            ));
        };
        if check.failure_mode.is_none() {
            return Err(invalid(
                format!("{path}.failure_mode"),
                "is required: `closed` or `open`; there is no default",
            ));
        }
        // The filter parses the URL fully; this catches what it would reject
        // so the error names the dialect path.
        let url = http.url.as_deref().unwrap_or_default();
        let authority = url
            .strip_prefix("http://")
            .or_else(|| url.strip_prefix("https://"))
            .map(|rest| rest.split(['/', '?', '#']).next().unwrap_or_default());
        let valid = authority.is_some_and(|a| {
            !a.is_empty()
                && !a.starts_with(':')
                && !a.contains('@')
                && !a.contains(char::is_whitespace)
        });
        if !valid {
            return Err(invalid(
                format!("{path}.http.url"),
                "must be an absolute `http` or `https` URL with a host and no user information",
            ));
        }
        match http.timeout {
            None => {
                return Err(invalid(format!("{path}.http.timeout"), "is required"));
            }
            Some(SimpleDuration(timeout))
                if timeout.is_zero() || timeout.as_millis() > u128::from(u32::MAX) =>
            {
                return Err(invalid(
                    format!("{path}.http.timeout"),
                    "must be at least 1ms and fit in 32 bits of milliseconds",
                ));
            }
            Some(_) => {}
        }
        if !http.max_body_bytes.is_some_and(|max| max > 0) {
            return Err(invalid(
                format!("{path}.http.max_body_bytes"),
                "is required and must be greater than 0",
            ));
        }
    }
    Ok(())
}

/// The reserved model name `auto:` resolves.
const AUTO_MODEL: &str = "auto";

/// Every target must be served by a route or `models` entry. When `auto:` is
/// configured, the name `auto` is reserved because it could not be reached.
fn validate_auto(config: &SimpleConfig) -> Result<(), ConfigError> {
    let Some(auto) = &config.auto else {
        return Ok(());
    };
    let invalid =
        |field_path: String, reason: String| ConfigError::InvalidValue { field_path, reason };

    if auto.default.is_none() && auto.tenants.is_empty() {
        return Err(invalid(
            "auto".to_string(),
            "set `default`, `tenants`, or both; an empty block would refuse every `auto` request"
                .to_string(),
        ));
    }
    if !auto.tenants.is_empty() && config.auth.is_none() {
        return Err(invalid(
            "auto.tenants".to_string(),
            "requires an `auth` block: without authentication no request has a tenant, so \
             these rules would never apply"
                .to_string(),
        ));
    }
    if config.models.contains_key(AUTO_MODEL) {
        return Err(invalid(
            format!("models.{AUTO_MODEL}"),
            "`auto` is reserved while the `auto` block is set".to_string(),
        ));
    }
    if let Some(i) = config.routes.iter().position(|r| r.model == AUTO_MODEL) {
        return Err(invalid(
            format!("routes[{i}].model"),
            "`auto` is reserved while the `auto` block is set".to_string(),
        ));
    }

    if auto.tenants.contains_key("") {
        return Err(invalid(
            "auto.tenants".to_string(),
            "a tenant must not be empty".to_string(),
        ));
    }

    let targets = auto
        .default
        .iter()
        .map(|model| ("auto.default".to_string(), model))
        .chain(
            auto.tenants
                .iter()
                .map(|(tenant, model)| (format!("auto.tenants.{tenant}"), model)),
        );
    for (path, model) in targets {
        if model.is_empty() || model == AUTO_MODEL || model.contains('*') {
            return Err(invalid(
                path,
                "must be a concrete model name, not empty, `auto`, or a pattern".to_string(),
            ));
        }
        let served = config.models.keys().any(|key| glob_matches(key, model))
            || config.routes.iter().any(|r| glob_matches(&r.model, model));
        if !served {
            return Err(invalid(
                path,
                format!("no route or `models` entry serves `{model}`"),
            ));
        }
    }
    Ok(())
}

/// Matches `name` against a `routes[].model` or `models` key glob: `*`
/// matches any run of characters, the same grammar `lower::model_glob_matcher`
/// emits as a header matcher.
pub(crate) fn glob_matches(pattern: &str, name: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = name.strip_prefix(first) else {
        return false;
    };
    let parts: Vec<&str> = parts.collect();
    let Some((last, middle)) = parts.split_last() else {
        return rest.is_empty();
    };
    for part in middle {
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    rest.len() >= last.len() && rest.ends_with(last)
}

fn validate_provider_specific_fields(
    name: &str,
    provider: &Provider,
    provider_type: ProviderType,
) -> Result<(), ConfigError> {
    let path = format!("providers.{name}");
    let vertex_fields = [
        ("project", provider.project.is_some()),
        ("location", provider.location.is_some()),
        ("publisher", provider.publisher.is_some()),
        ("access_token", provider.access_token.is_some()),
        ("access_token_file", provider.access_token_file.is_some()),
        ("oauth2_jwt_bearer", provider.oauth2_jwt_bearer.is_some()),
    ];
    let bedrock_fields = [
        ("region", provider.region.is_some()),
        ("access_key_id", provider.access_key_id.is_some()),
        ("access_key_id_file", provider.access_key_id_file.is_some()),
        ("secret_access_key", provider.secret_access_key.is_some()),
        (
            "secret_access_key_file",
            provider.secret_access_key_file.is_some(),
        ),
        ("session_token", provider.session_token.is_some()),
        ("session_token_file", provider.session_token_file.is_some()),
    ];

    if provider_type != ProviderType::Vertex {
        if let Some((field, true)) = vertex_fields.iter().find(|(_, present)| *present) {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{path}.{field}"),
                reason: "is only valid for vertex providers".into(),
            });
        }
    }
    if provider_type != ProviderType::Bedrock {
        if let Some((field, true)) = bedrock_fields.iter().find(|(_, present)| *present) {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{path}.{field}"),
                reason: "is only valid for bedrock providers".into(),
            });
        }
    }
    if provider_type != ProviderType::AzureOpenai {
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
    if matches!(provider_type, ProviderType::Vertex | ProviderType::Bedrock)
        && (provider.api_key.is_some() || provider.api_key_file.is_some())
    {
        return Err(ConfigError::InvalidValue {
            field_path: format!("{path}.api_key"),
            reason: format!(
                "api_key/api_key_file are not valid for `{}` providers; use its native credential fields",
                provider_type.as_str()
            ),
        });
    }
    Ok(())
}

fn validate_vertex_provider(name: &str, provider: &Provider) -> Result<(), ConfigError> {
    let path = format!("providers.{name}");
    for (field, value) in [
        ("project", provider.project.as_deref()),
        ("location", provider.location.as_deref()),
        ("publisher", provider.publisher.as_deref()),
    ] {
        if value.is_none() {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{path}.{field}"),
                reason: format!("{field} is required for vertex providers"),
            });
        }
        if value == Some("") {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{path}.{field}"),
                reason: "must not be empty".into(),
            });
        }
    }
    if let Some(oauth2) = &provider.oauth2_jwt_bearer {
        if provider.access_token.is_some() || provider.access_token_file.is_some() {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{path}.oauth2_jwt_bearer"),
                reason: "set either oauth2_jwt_bearer or a configured access token \
                         (access_token, access_token_file), not both"
                    .into(),
            });
        }
        return validate_oauth2_jwt_bearer(&format!("{path}.oauth2_jwt_bearer"), oauth2);
    }
    validate_exactly_one_source(
        &path,
        "access_token",
        provider.access_token.as_deref(),
        "access_token_file",
        provider.access_token_file.as_deref(),
        "vertex OAuth access token (or oauth2_jwt_bearer)",
    )
}

/// Checks `oauth2_jwt_bearer` before lowering. The key file itself is read
/// and checked when the config is lowered, like every other credential file.
fn validate_oauth2_jwt_bearer(path: &str, def: &OAuth2JwtBearerDef) -> Result<(), ConfigError> {
    let invalid = |field: &str, reason: &str| ConfigError::InvalidValue {
        field_path: format!("{path}.{field}"),
        reason: reason.to_string(),
    };
    let tls = parse_token_url(&def.token_url, &format!("{path}.token_url"))?.tls;
    if def.ca_file.is_some() && !tls {
        return Err(invalid("ca_file", "is only valid for an https token_url"));
    }
    for (field, value) in [
        ("issuer", Some(def.issuer.as_str())),
        ("subject", def.subject.as_deref()),
        ("key_id", def.key_id.as_deref()),
        ("audience", def.audience.as_deref()),
        ("private_key_file", Some(def.private_key_file.as_str())),
        ("ca_file", def.ca_file.as_deref()),
    ] {
        if value == Some("") {
            return Err(invalid(field, "must not be empty"));
        }
    }
    if def.scopes.is_empty() {
        return Err(invalid("scopes", "must list at least one scope"));
    }
    for (i, scope) in def.scopes.iter().enumerate() {
        if scope.is_empty() || scope.chars().any(char::is_whitespace) {
            return Err(invalid(
                &format!("scopes[{i}]"),
                "must be a non-empty scope without spaces",
            ));
        }
    }
    for (field, value) in [
        ("assertion_lifetime", def.assertion_lifetime),
        ("refresh_before", def.refresh_before),
        ("timeout", def.timeout),
    ] {
        if let Some(SimpleDuration(duration)) = value {
            if duration.subsec_nanos() != 0
                || duration.as_secs() == 0
                || duration.as_secs() > 86_400
            {
                return Err(invalid(
                    field,
                    "must be a whole number of seconds from 1s to 24h",
                ));
            }
        }
    }
    Ok(())
}

/// A parsed `token_url`: plain `http` is accepted only to a loopback host,
/// because the request carries a signed assertion that anyone who reads it
/// can exchange for a token.
pub(crate) struct TokenUrl {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) tls: bool,
}

pub(crate) fn parse_token_url(url: &str, path: &str) -> Result<TokenUrl, ConfigError> {
    let invalid = |reason: String| ConfigError::InvalidValue {
        field_path: path.to_string(),
        reason,
    };
    let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(invalid(format!(
            "`{url}` must start with https:// (or http:// to a loopback host)"
        )));
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err(invalid(format!("`{url}` must name a host")));
    }
    let (host, port) = if authority.contains(':') || authority.starts_with('[') {
        parse_host_port(authority, path)?
    } else {
        (authority.to_string(), if tls { 443 } else { 80 })
    };
    let loopback = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if !tls && !loopback {
        return Err(invalid(format!(
            "`{url}` must use https; plain http is accepted only to a loopback host"
        )));
    }
    Ok(TokenUrl { host, port, tls })
}

fn validate_bedrock_provider(name: &str, provider: &Provider) -> Result<(), ConfigError> {
    let path = format!("providers.{name}");
    if provider.region.is_none() {
        return Err(ConfigError::InvalidValue {
            field_path: format!("{path}.region"),
            reason: "region is required for bedrock providers".into(),
        });
    }
    if provider.region.as_deref() == Some("") {
        return Err(ConfigError::InvalidValue {
            field_path: format!("{path}.region"),
            reason: "must not be empty".into(),
        });
    }
    validate_exactly_one_source(
        &path,
        "access_key_id",
        provider.access_key_id.as_deref(),
        "access_key_id_file",
        provider.access_key_id_file.as_deref(),
        "Bedrock access key ID",
    )?;
    validate_exactly_one_source(
        &path,
        "secret_access_key",
        provider.secret_access_key.as_deref(),
        "secret_access_key_file",
        provider.secret_access_key_file.as_deref(),
        "Bedrock secret access key",
    )?;
    if provider.session_token.is_some() && provider.session_token_file.is_some() {
        return Err(ConfigError::InvalidValue {
            field_path: format!("{path}.session_token"),
            reason: "set either session_token or session_token_file, not both".into(),
        });
    }
    for (field, value) in [
        ("session_token", provider.session_token.as_deref()),
        ("session_token_file", provider.session_token_file.as_deref()),
    ] {
        if value == Some("") {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{path}.{field}"),
                reason: "must not be empty".into(),
            });
        }
    }
    Ok(())
}

fn validate_exactly_one_source(
    path: &str,
    inline_field: &str,
    inline_value: Option<&str>,
    file_field: &str,
    file_value: Option<&str>,
    credential_name: &str,
) -> Result<(), ConfigError> {
    match (inline_value, file_value) {
        (Some(_), None) | (None, Some(_)) => {
            let (field, value) = if let Some(value) = inline_value {
                (inline_field, value)
            } else {
                (file_field, file_value.expect("matched Some"))
            };
            if value.is_empty() {
                Err(ConfigError::InvalidValue {
                    field_path: format!("{path}.{field}"),
                    reason: "must not be empty".into(),
                })
            } else {
                Ok(())
            }
        }
        (Some(_), Some(_)) => Err(ConfigError::InvalidValue {
            field_path: format!("{path}.{inline_field}"),
            reason: format!("set either {inline_field} or {file_field}, not both"),
        }),
        (None, None) => Err(ConfigError::InvalidValue {
            field_path: format!("{path}.{inline_field}"),
            reason: format!(
                "one {credential_name} source is required: {inline_field} or {file_field}"
            ),
        }),
    }
}

fn validate_non_azure_provider(name: &str, provider: &Provider) -> Result<(), ConfigError> {
    let path = format!("providers.{name}");
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

/// `models.<name>.session_affinity` (ADR-0016): only on a weighted alias,
/// which has a split to pin, and `identity` only with `auth`, which is what
/// fills the identity; without it no request could hash (AGENTS.md
/// invariant 1).
fn check_session_affinity(
    config: &SimpleConfig,
    model: &ModelDef,
    path: &str,
) -> Result<(), ConfigError> {
    let Some(affinity) = &model.session_affinity else {
        return Ok(());
    };
    let field_path = format!("{path}.session_affinity");
    if affinity.header.is_none() && affinity.identity.is_none() {
        return Err(ConfigError::InvalidValue {
            field_path,
            reason: "set `header`, `identity`, or both".to_string(),
        });
    }
    if model.providers.iter().all(|entry| entry.weight().is_none()) {
        return Err(ConfigError::InvalidValue {
            field_path,
            reason: "session affinity pins a session to one provider of a weighted split; \
                     set `weight` on every entry of `providers`"
                .to_string(),
        });
    }
    if let Some(header) = &affinity.header {
        // RFC 9110 token characters, as the schema's pattern.
        let token = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
        if header.is_empty() || !header.bytes().all(token) {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{field_path}.header"),
                reason: format!("`{header}` is not a valid HTTP header name"),
            });
        }
    }
    if affinity.identity.is_some() && config.auth.is_none() {
        return Err(ConfigError::InvalidValue {
            field_path: format!("{field_path}.identity"),
            reason: "an authenticated identity needs the `auth` block; without it no request \
                     carries one"
                .to_string(),
        });
    }
    Ok(())
}

/// `models.<name>.selection: latency` only on a weighted alias: without
/// weights there is no split for latency to bias (AGENTS.md invariant 1).
fn check_selection(model: &ModelDef, path: &str) -> Result<(), ConfigError> {
    if model.selection == ModelSelection::Latency
        && model.providers.iter().all(|entry| entry.weight().is_none())
    {
        return Err(ConfigError::InvalidValue {
            field_path: format!("{path}.selection"),
            reason: "latency selection biases a weighted split; set `weight` on every entry of \
                     `providers`"
                .to_string(),
        });
    }
    Ok(())
}

/// Largest `models.<name>.providers[i].weight`. Bounds the cumulative weight
/// of a list well inside `u32`, which Envoy's `WeightedCluster` sums into.
const MAX_MODEL_WEIGHT: u32 = 1_000_000;

/// `models.<name>.providers[i].weight`: on every entry or on none, within
/// bounds, not all zero, and no provider listed twice. Half-weighted lists are
/// refused rather than read as weight 0 or weight 1, because either guess
/// moves traffic the operator did not ask to move (AGENTS.md invariant 1).
fn check_model_weights(name: &str, model: &ModelDef, path: &str) -> Result<(), ConfigError> {
    if model.providers.iter().all(|entry| entry.weight().is_none()) {
        return Ok(());
    }
    let mut total: u64 = 0;
    for (i, entry) in model.providers.iter().enumerate() {
        let entry_path = format!("{path}.providers[{i}]");
        let Some(weight) = entry.weight() else {
            let reason = match entry {
                ModelProviderRef::Shorthand(_) => format!(
                    "`models.{name}` sets `weight` on another entry, so every entry needs one; \
                     the shorthand string form cannot carry `weight` -- use the object form \
                     ({{ provider, weight }})"
                ),
                ModelProviderRef::Full(_) => format!(
                    "`models.{name}` sets `weight` on another entry, so every entry needs one \
                     (use 0 for a fallback-only provider)"
                ),
            };
            return Err(ConfigError::InvalidValue {
                field_path: entry_path,
                reason,
            });
        };
        if weight > MAX_MODEL_WEIGHT {
            return Err(ConfigError::InvalidValue {
                field_path: format!("{entry_path}.weight"),
                reason: format!("must be at most {MAX_MODEL_WEIGHT}"),
            });
        }
        if let Some(first) = model.providers[..i]
            .iter()
            .position(|earlier| earlier.provider() == entry.provider())
        {
            return Err(ConfigError::InvalidValue {
                field_path: entry_path,
                reason: format!(
                    "provider `{}` is already providers[{first}]; a weighted list names each \
                     provider once",
                    entry.provider()
                ),
            });
        }
        total += u64::from(weight);
    }
    if total == 0 {
        return Err(ConfigError::InvalidValue {
            field_path: format!("{path}.providers"),
            reason: "every weight is 0, so no provider could be picked first; give at least one \
                     entry a weight above 0"
                .to_string(),
        });
    }
    Ok(())
}

/// Route references need an explicit dialect when provider type alone is
/// ambiguous; routes have no `dialect` field, so Vertex/Bedrock use `models:`.
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
