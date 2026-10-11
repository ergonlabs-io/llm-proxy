//! PGV (protoc-gen-validate) validation engine.
//!
//! Envoy's protos carry constraint annotations — `validate.rules` on fields
//! (e.g. `connect_timeout` must be `> 0s`, `port_value <= 65535`, `stat_prefix`
//! non-empty) and `validate.required` on oneofs. Envoy generates C++ validators
//! from them and rejects violating configs at load/xDS time. We interpret the
//! same annotations at runtime, reading them out of the embedded descriptor
//! pool — one engine covering every message type, no codegen step.
//!
//! Runs on every config entry point: bootstrap files after parsing, and
//! (later) every xDS resource before ACK — a failure here becomes a NACK.
//!
//! Supported rule subset (the ones Envoy actually uses on our surface):
//! `message.required`/`message.skip`, oneof `required`, `duration.{required,
//! gt,gte,lt,lte}`, numeric `{const,lt,lte,gt,gte,in,not_in}` for
//! (u)int32/64/double/float, `string.{const,min_len,max_len,min_bytes,
//! max_bytes,prefix,suffix,contains,in,not_in,pattern,well_known_regex}`,
//! `repeated.{min_items,max_items}`, `enum.defined_only`. Wrapper types
//! (`google.protobuf.UInt32Value` etc.) are unwrapped so scalar rules apply to
//! the wrapped value. Unsupported rule kinds are skipped, never mis-enforced —
//! meaning we can only be *more permissive* than Envoy, never less; the
//! diff rig is what shrinks that gap over time.

use std::sync::OnceLock;

use prost_reflect::{
    DynamicMessage, ExtensionDescriptor, FieldDescriptor, Kind, MessageDescriptor, ReflectMessage,
    Value,
};
use proxy_api::validate::{
    field_rules, string_rules, DurationRules, EnumRules, FieldRules, KnownRegex, RepeatedRules,
    StringRules,
};

use crate::error::ConfigError;

/// Validate a message (and, recursively, everything reachable from it,
/// including through `google.protobuf.Any`) against its PGV annotations.
/// Returns the first violation, with the full dotted field path.
pub fn validate_message(message: &DynamicMessage) -> Result<(), ConfigError> {
    walk_message(message, &mut PathBuf::default())
}

/// The three PGV extension descriptors, resolved once from the pool.
struct ValidateExts {
    /// `validate.rules` on `google.protobuf.FieldOptions`.
    rules: ExtensionDescriptor,
    /// `validate.required` on `google.protobuf.OneofOptions`.
    required: ExtensionDescriptor,
    /// `validate.disabled` on `google.protobuf.MessageOptions`.
    disabled: ExtensionDescriptor,
}

fn exts() -> &'static ValidateExts {
    static EXTS: OnceLock<ValidateExts> = OnceLock::new();
    EXTS.get_or_init(|| {
        let pool = proxy_api::descriptor_pool();
        let get = |name: &str| {
            pool.get_extension_by_name(name)
                .unwrap_or_else(|| panic!("`{name}` must be in the embedded descriptor pool"))
        };
        ValidateExts {
            rules: get("validate.rules"),
            required: get("validate.required"),
            disabled: get("validate.disabled"),
        }
    })
}

/// Dotted field path under construction (`static_resources.listeners[0]...`).
///
/// Rust note: we push/pop segments as the recursion descends/returns, reusing
/// one String instead of allocating a path per level.
#[derive(Default)]
struct PathBuf {
    buf: String,
}

impl PathBuf {
    fn push(&mut self, segment: &str) -> usize {
        let mark = self.buf.len();
        if !self.buf.is_empty() {
            self.buf.push('.');
        }
        self.buf.push_str(segment);
        mark
    }

    fn push_index(&mut self, index: usize) -> usize {
        let mark = self.buf.len();
        self.buf.push('[');
        self.buf.push_str(&index.to_string());
        self.buf.push(']');
        mark
    }

    fn pop(&mut self, mark: usize) {
        self.buf.truncate(mark);
    }

    fn violation(&self, rule: impl Into<String>) -> ConfigError {
        ConfigError::Validation {
            field_path: if self.buf.is_empty() {
                "<root>".to_string()
            } else {
                self.buf.clone()
            },
            rule: rule.into(),
        }
    }
}

fn walk_message(msg: &DynamicMessage, path: &mut PathBuf) -> Result<(), ConfigError> {
    let desc = msg.descriptor();
    if message_disabled(&desc) {
        return Ok(());
    }

    // Oneof `required`: exactly one member must be set.
    for oneof in desc.oneofs() {
        let opts = oneof.options();
        let required = opts
            .get_extension(&exts().required)
            .as_bool()
            .unwrap_or(false);
        if required && !oneof.fields().any(|f| msg.has_field(&f)) {
            let names = oneof
                .fields()
                .map(|f| f.name().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let mark = path.push(oneof.name());
            let err = path.violation(format!("exactly one of [{names}] is required"));
            path.pop(mark);
            return Err(err);
        }
    }

    for field in desc.fields() {
        let rules = field_rules(&field)?;
        let mark = path.push(field.name());
        let result = validate_field(msg, &field, rules.as_ref(), path);
        path.pop(mark);
        result?;
    }
    Ok(())
}

fn message_disabled(desc: &MessageDescriptor) -> bool {
    desc.options()
        .get_extension(&exts().disabled)
        .as_bool()
        .unwrap_or(false)
}

/// Decode the `validate.rules` extension on a field, if present.
fn field_rules(field: &FieldDescriptor) -> Result<Option<FieldRules>, ConfigError> {
    let opts = field.options();
    if !opts.has_extension(&exts().rules) {
        return Ok(None);
    }
    let value = opts.get_extension(&exts().rules);
    let msg = value
        .as_message()
        .ok_or_else(|| ConfigError::Parse("malformed validate.rules extension".into()))?;
    msg.transcode_to::<FieldRules>()
        .map(Some)
        .map_err(|e| ConfigError::Parse(format!("cannot decode validate.rules: {e}")))
}

fn validate_field(
    msg: &DynamicMessage,
    field: &FieldDescriptor,
    rules: Option<&FieldRules>,
    path: &mut PathBuf,
) -> Result<(), ConfigError> {
    if field.is_map() {
        // Map rules (min_pairs, ...) unimplemented; still recurse into
        // message-typed values so nested constraints are enforced.
        if let Some(Value::Map(map)) = msg
            .has_field(field)
            .then(|| msg.get_field(field))
            .as_deref()
        {
            for value in map.values() {
                if let Value::Message(inner) = value {
                    walk_message(inner, path)?;
                }
            }
        }
        return Ok(());
    }

    if field.is_list() {
        let value = msg.get_field(field);
        let items = value.as_list().unwrap_or(&[]);
        if let Some(FieldRules {
            r#type: Some(field_rules::Type::Repeated(rep)),
            ..
        }) = rules
        {
            apply_repeated_rules(items.len(), rep, path)?;
        }
        for (i, item) in items.iter().enumerate() {
            if let Value::Message(inner) = item {
                let mark = path.push_index(i);
                let result = recurse_into(inner, rules, path);
                path.pop(mark);
                result?;
            }
        }
        return Ok(());
    }

    match field.kind() {
        Kind::Message(inner_desc) => {
            if msg.has_field(field) {
                let value = msg.get_field(field);
                let inner = value
                    .as_message()
                    .expect("message-kind field holds a message");
                apply_message_typed_rules(inner, &inner_desc, rules, path)?;
                recurse_into(inner, rules, path)?;
            } else if let Some(rules) = rules {
                // Presence rules fire on ABSENT message fields — but rules on
                // a oneof MEMBER only apply when that member is the selected
                // case (PGV semantics); an unselected member is never checked.
                if field.containing_oneof().is_some() {
                    return Ok(());
                }
                let required = rules.message.as_ref().and_then(|m| m.required) == Some(true)
                    || matches!(
                        &rules.r#type,
                        Some(field_rules::Type::Duration(DurationRules {
                            required: Some(true),
                            ..
                        }))
                    );
                if required {
                    return Err(path.violation("value is required"));
                }
            }
            Ok(())
        }
        _ => {
            // PGV semantics: rules on a oneof member apply only when that
            // member is the one set; rules on plain proto3 scalars apply to
            // the (possibly default) value unconditionally — that is how
            // `string.min_len 1` makes a field effectively required.
            if field.containing_oneof().is_some() && !msg.has_field(field) {
                return Ok(());
            }
            if let Some(rules) = rules {
                apply_scalar_rules(&msg.get_field(field), rules, field, path)?;
            }
            Ok(())
        }
    }
}

/// Recurse into a set message-typed value: unpack `Any`, skip well-known leaf
/// types, honor `message.skip`.
fn recurse_into(
    inner: &DynamicMessage,
    rules: Option<&FieldRules>,
    path: &mut PathBuf,
) -> Result<(), ConfigError> {
    if let Some(FieldRules {
        message: Some(m), ..
    }) = rules
    {
        if m.skip == Some(true) {
            return Ok(());
        }
    }
    let full_name = inner.descriptor().full_name().to_string();
    if full_name == "google.protobuf.Any" {
        return walk_any(inner, path);
    }
    if full_name.starts_with("google.protobuf.") {
        // Duration/Timestamp/Struct/wrappers: leaves, no PGV rules inside.
        return Ok(());
    }
    walk_message(inner, path)
}

/// Unpack a `google.protobuf.Any` by type URL against the descriptor pool and
/// validate the inner message. The path continues through the Any field name,
/// matching how the loader reports paths inside `typed_config`.
fn walk_any(any: &DynamicMessage, path: &mut PathBuf) -> Result<(), ConfigError> {
    let desc = any.descriptor();
    let type_url_field = desc.get_field_by_name("type_url").expect("Any.type_url");
    let value_field = desc.get_field_by_name("value").expect("Any.value");

    let type_url = any
        .get_field(&type_url_field)
        .as_str()
        .unwrap_or("")
        .to_string();
    if type_url.is_empty() {
        return Ok(()); // empty Any — nothing to validate
    }
    let type_name = type_url.rsplit('/').next().unwrap_or(&type_url);
    let inner_desc = proxy_api::descriptor_pool()
        .get_message_by_name(type_name)
        .ok_or_else(|| ConfigError::UnknownTypeUrl {
            field_path: path.buf.clone(),
            type_url: type_url.clone(),
        })?;
    let bytes = any.get_field(&value_field);
    let bytes = bytes.as_bytes().map(|b| b.as_ref()).unwrap_or(&[]);
    let inner = DynamicMessage::decode(inner_desc, bytes)
        .map_err(|e| ConfigError::Parse(format!("cannot decode Any `{type_url}`: {e}")))?;
    walk_message(&inner, path)
}

/// Rules that target the VALUE of a message-typed field: durations and
/// well-known wrapper types (`google.protobuf.UInt32Value` etc.).
fn apply_message_typed_rules(
    inner: &DynamicMessage,
    inner_desc: &MessageDescriptor,
    rules: Option<&FieldRules>,
    path: &mut PathBuf,
) -> Result<(), ConfigError> {
    let Some(rules) = rules else { return Ok(()) };
    match (inner_desc.full_name(), &rules.r#type) {
        ("google.protobuf.Duration", Some(field_rules::Type::Duration(d))) => {
            let dur = inner
                .transcode_to::<prost_types::Duration>()
                .map_err(|e| ConfigError::Parse(format!("bad Duration: {e}")))?;
            apply_duration_rules(&dur, d, path)
        }
        // Wrappers: apply the scalar rule to the wrapped `value` field.
        (name, Some(_)) if name.starts_with("google.protobuf.") && name.ends_with("Value") => {
            let value_field = inner_desc
                .get_field_by_name("value")
                .expect("wrapper.value");
            apply_scalar_rules(&inner.get_field(&value_field), rules, &value_field, path)
        }
        _ => Ok(()),
    }
}

fn apply_repeated_rules(
    len: usize,
    rules: &RepeatedRules,
    path: &mut PathBuf,
) -> Result<(), ConfigError> {
    if rules.ignore_empty == Some(true) && len == 0 {
        return Ok(());
    }
    if let Some(min) = rules.min_items {
        if (len as u64) < min {
            return Err(path.violation(format!("value must contain at least {min} item(s)")));
        }
    }
    if let Some(max) = rules.max_items {
        if (len as u64) > max {
            return Err(path.violation(format!("value must contain no more than {max} item(s)")));
        }
    }
    Ok(())
}

fn apply_duration_rules(
    dur: &prost_types::Duration,
    rules: &DurationRules,
    path: &mut PathBuf,
) -> Result<(), ConfigError> {
    let nanos =
        |d: &prost_types::Duration| i128::from(d.seconds) * 1_000_000_000 + i128::from(d.nanos);
    let v = nanos(dur);
    let show = |d: &prost_types::Duration| format!("{}.{:09}s", d.seconds, d.nanos.unsigned_abs());
    if let Some(c) = &rules.r#const {
        if v != nanos(c) {
            return Err(path.violation(format!("value must equal {}", show(c))));
        }
    }
    if let Some(gt) = &rules.gt {
        if v <= nanos(gt) {
            return Err(path.violation(format!("value must be greater than {}", show(gt))));
        }
    }
    if let Some(gte) = &rules.gte {
        if v < nanos(gte) {
            return Err(path.violation(format!("value must be at least {}", show(gte))));
        }
    }
    if let Some(lt) = &rules.lt {
        if v >= nanos(lt) {
            return Err(path.violation(format!("value must be less than {}", show(lt))));
        }
    }
    if let Some(lte) = &rules.lte {
        if v > nanos(lte) {
            return Err(path.violation(format!("value must be at most {}", show(lte))));
        }
    }
    Ok(())
}

/// Numeric comparison rules, shared across the integer/float rule structs.
///
/// Rust note: a macro rather than a generic function because each PGV rule
/// struct (`UInt32Rules`, `Int64Rules`, ...) is a distinct type with the same
/// field names — a macro matches on shape, generics would need a trait per rule.
macro_rules! numeric_rules {
    ($val:expr, $rules:expr, $path:expr, $zero:literal) => {{
        let (v, r, path) = ($val, $rules, $path);
        // "Empty" for a numeric field is the proto3 default: zero.
        #[allow(clippy::float_cmp)]
        if r.ignore_empty == Some(true) && v == $zero {
            return Ok(());
        }
        if let Some(c) = r.r#const {
            if v != c {
                return Err(path.violation(format!("value must equal {c}")));
            }
        }
        if let Some(lt) = r.lt {
            if v >= lt {
                return Err(path.violation(format!("value must be less than {lt}")));
            }
        }
        if let Some(lte) = r.lte {
            if v > lte {
                return Err(path.violation(format!("value must be at most {lte}")));
            }
        }
        if let Some(gt) = r.gt {
            if v <= gt {
                return Err(path.violation(format!("value must be greater than {gt}")));
            }
        }
        if let Some(gte) = r.gte {
            if v < gte {
                return Err(path.violation(format!("value must be at least {gte}")));
            }
        }
        if !r.r#in.is_empty() && !r.r#in.contains(&v) {
            return Err(path.violation(format!("value must be one of {:?}", r.r#in)));
        }
        if r.not_in.contains(&v) {
            return Err(path.violation(format!("value must not be one of {:?}", r.not_in)));
        }
        Ok(())
    }};
}

fn apply_scalar_rules(
    value: &Value,
    rules: &FieldRules,
    field: &FieldDescriptor,
    path: &mut PathBuf,
) -> Result<(), ConfigError> {
    use field_rules::Type;
    match (&rules.r#type, value) {
        (Some(Type::String(r)), Value::String(s)) => apply_string_rules(s, r, path),
        (Some(Type::Uint32(r)), Value::U32(v)) => numeric_rules!(*v, r, path, 0),
        (Some(Type::Uint64(r)), Value::U64(v)) => numeric_rules!(*v, r, path, 0),
        (Some(Type::Int32(r)), Value::I32(v)) => numeric_rules!(*v, r, path, 0),
        (Some(Type::Int64(r)), Value::I64(v)) => numeric_rules!(*v, r, path, 0),
        (Some(Type::Double(r)), Value::F64(v)) => numeric_rules!(*v, r, path, 0.0),
        (Some(Type::Float(r)), Value::F32(v)) => numeric_rules!(*v, r, path, 0.0),
        (Some(Type::Enum(r)), Value::EnumNumber(n)) => {
            let Kind::Enum(enum_desc) = field.kind() else {
                return Ok(());
            };
            apply_enum_rules(*n, r, &enum_desc, path)
        }
        // Bool/bytes rules and mismatched shapes: not enforced (subset).
        _ => Ok(()),
    }
}

fn apply_enum_rules(
    number: i32,
    rules: &EnumRules,
    desc: &prost_reflect::EnumDescriptor,
    path: &mut PathBuf,
) -> Result<(), ConfigError> {
    if rules.defined_only == Some(true) && desc.get_value(number).is_none() {
        return Err(path.violation(format!(
            "value {number} is not a defined value of enum {}",
            desc.full_name()
        )));
    }
    if let Some(c) = rules.r#const {
        if number != c {
            return Err(path.violation(format!("value must equal {c}")));
        }
    }
    if !rules.r#in.is_empty() && !rules.r#in.contains(&number) {
        return Err(path.violation(format!("value must be one of {:?}", rules.r#in)));
    }
    if rules.not_in.contains(&number) {
        return Err(path.violation(format!("value must not be one of {:?}", rules.not_in)));
    }
    Ok(())
}

fn apply_string_rules(s: &str, r: &StringRules, path: &mut PathBuf) -> Result<(), ConfigError> {
    if r.ignore_empty == Some(true) && s.is_empty() {
        return Ok(());
    }
    let chars = s.chars().count() as u64;
    if let Some(c) = &r.r#const {
        if s != c {
            return Err(path.violation(format!("value must equal `{c}`")));
        }
    }
    if let Some(len) = r.len {
        if chars != len {
            return Err(path.violation(format!("value length must be exactly {len} characters")));
        }
    }
    if let Some(min) = r.min_len {
        if chars < min {
            return Err(path.violation(format!("value length must be at least {min} characters")));
        }
    }
    if let Some(max) = r.max_len {
        if chars > max {
            return Err(path.violation(format!("value length must be at most {max} characters")));
        }
    }
    if let Some(min) = r.min_bytes {
        if (s.len() as u64) < min {
            return Err(path.violation(format!("value length must be at least {min} bytes")));
        }
    }
    if let Some(max) = r.max_bytes {
        if (s.len() as u64) > max {
            return Err(path.violation(format!("value length must be at most {max} bytes")));
        }
    }
    if let Some(prefix) = &r.prefix {
        if !s.starts_with(prefix.as_str()) {
            return Err(path.violation(format!("value must start with `{prefix}`")));
        }
    }
    if let Some(suffix) = &r.suffix {
        if !s.ends_with(suffix.as_str()) {
            return Err(path.violation(format!("value must end with `{suffix}`")));
        }
    }
    if let Some(contains) = &r.contains {
        if !s.contains(contains.as_str()) {
            return Err(path.violation(format!("value must contain `{contains}`")));
        }
    }
    if let Some(not_contains) = &r.not_contains {
        if s.contains(not_contains.as_str()) {
            return Err(path.violation(format!("value must not contain `{not_contains}`")));
        }
    }
    if !r.r#in.is_empty() && !r.r#in.iter().any(|v| v == s) {
        return Err(path.violation(format!("value must be one of {:?}", r.r#in)));
    }
    if r.not_in.iter().any(|v| v == s) {
        return Err(path.violation(format!("value must not be one of {:?}", r.not_in)));
    }
    if let Some(pattern) = &r.pattern {
        let re = regex::Regex::new(pattern)
            .map_err(|e| ConfigError::Parse(format!("bad PGV pattern `{pattern}`: {e}")))?;
        if !re.is_match(s) {
            return Err(path.violation(format!("value must match pattern `{pattern}`")));
        }
    }
    if let Some(string_rules::WellKnown::WellKnownRegex(kind)) = r.well_known {
        let strict = r.strict.unwrap_or(true);
        apply_well_known_regex(s, kind, strict, path)?;
    }
    // Other well-known formats (email, hostname, uri, uuid, ip): part of the
    // unsupported subset — skipped, never mis-enforced.
    Ok(())
}

/// PGV `well_known_regex` for HTTP header names/values. Strict mode uses the
/// RFC 7230 token charset (plus a leading `:` for pseudo-headers); loose mode
/// only bans NUL/CR/LF.
fn apply_well_known_regex(
    s: &str,
    kind: i32,
    strict: bool,
    path: &mut PathBuf,
) -> Result<(), ConfigError> {
    let ok = match KnownRegex::try_from(kind) {
        Ok(KnownRegex::HttpHeaderName) => {
            let body = s.strip_prefix(':').unwrap_or(s);
            if strict {
                // RFC 7230 token (leading `:` allowed for pseudo-headers).
                !body.is_empty()
                    && body
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_|~`".contains(&b))
            } else {
                // PGV loose mode: empty allowed; only NUL/CR/LF banned.
                !body.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n')
            }
        }
        Ok(KnownRegex::HttpHeaderValue) => !s.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n'),
        _ => true,
    };
    if ok {
        Ok(())
    } else {
        Err(path.violation("value must be a valid HTTP header per RFC 7230"))
    }
}
