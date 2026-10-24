//! Detects serde_json's reserved `RawValue` key in a JSON document.
//!
//! The workspace enables serde_json's `raw_value` feature, and cargo turns a
//! feature on for every crate that links serde_json. With it, a
//! `serde_json::Value` reads an object whose first key is
//! [`SERDE_RAW_VALUE_KEY`] as the JSON text in that key's string value, not as
//! an object. So `{"model":{"$serde_json::private::RawValue":"\"gpt-4o\""}}`
//! is model `gpt-4o` to every `Value` decode in the proxy, and an object to
//! the provider. No API defines the key, so the filter manager refuses a
//! request body that has it anywhere, before any filter or the router decodes
//! the body (see `FilterManager::run`).

use std::cell::Cell;
use std::fmt;

use serde::de::{DeserializeSeed, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};

/// The key serde_json reserves for `RawValue`.
pub const SERDE_RAW_VALUE_KEY: &str = "$serde_json::private::RawValue";

/// Whether `body` is JSON with [`SERDE_RAW_VALUE_KEY`] as an object key, at
/// any depth and in any escaped spelling. A body that is not JSON has no key;
/// a key found before a syntax error still counts.
#[must_use]
pub fn contains_serde_raw_value_key(body: &[u8]) -> bool {
    // The key starts with `$`, which JSON can only spell as itself or as
    // `$`. Without either, there is nothing to walk for.
    if !body.contains(&b'$') && !body.windows(6).any(|w| w == b"\\u0024") {
        return false;
    }
    let found = Cell::new(false);
    let mut de = serde_json::Deserializer::from_slice(body);
    // The walk stops at the first match by failing on purpose; `found` says
    // which failure that was.
    let _ = Walk(&found).deserialize(&mut de);
    found.get()
}

/// Validates one JSON value without keeping it, checking every object key.
#[derive(Clone, Copy)]
struct Walk<'a>(&'a Cell<bool>);

impl<'de> DeserializeSeed<'de> for Walk<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<(), D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Walk<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(self)?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(reserved) = map.next_key_seed(IsReservedKey)? {
            if reserved {
                self.0.set(true);
                return Err(A::Error::custom("reserved key"));
            }
            map.next_value_seed(self)?;
        }
        Ok(())
    }
}

/// Compares a key with [`SERDE_RAW_VALUE_KEY`] as serde_json hands it over:
/// unescaped, and borrowed from the body when it has no escapes, so a key
/// costs no allocation.
struct IsReservedKey;

impl<'de> DeserializeSeed<'de> for IsReservedKey {
    type Value = bool;

    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<bool, D::Error> {
        de.deserialize_str(self)
    }
}

impl<'de> Visitor<'de> for IsReservedKey {
    type Value = bool;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object key")
    }

    fn visit_str<E>(self, key: &str) -> Result<bool, E> {
        Ok(key == SERDE_RAW_VALUE_KEY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_key_at_any_depth_and_spelling() {
        for body in [
            r#"{"$serde_json::private::RawValue":"{}"}"#,
            r#"{"model":{"$serde_json::private::RawValue":"\"gpt-4o\""}}"#,
            r#"{"messages":[{"role":"user"},{"$serde_json::private::RawValue":1}]}"#,
            r#"[[{"a":{"b":[{"$serde_json::private::RawValue":null}]}}]]"#,
            r#"{"\u0024serde_json::private::RawValue":"{}"}"#,
            r#"{"$serde_json::priv\u0061te::RawValue":"{}"}"#,
            // Found before the syntax error that follows it.
            r#"{"$serde_json::private::RawValue":"{}", oops"#,
        ] {
            assert!(contains_serde_raw_value_key(body.as_bytes()), "{body}");
        }
    }

    #[test]
    fn ignores_the_text_outside_a_key() {
        for body in [
            r#"{"model":"m","messages":[{"content":"$serde_json::private::RawValue"}]}"#,
            r#"{"$serde_json::private::RawValueX":1,"x$serde_json::private::RawValue":2}"#,
            r#"{"price":"$5","note":"\u0024 sign"}"#,
            r#"{"model":"m"}"#,
            "not json $serde_json::private::RawValue",
            "",
        ] {
            assert!(!contains_serde_raw_value_key(body.as_bytes()), "{body}");
        }
    }

    /// The reason for the check: with `raw_value` on, `Value` reads the
    /// object as something else. If serde_json stops doing that, this fails
    /// and the refusal can go.
    #[test]
    fn value_misreads_an_object_led_by_the_key() {
        let body = r#"{"model":{"$serde_json::private::RawValue":"\"gpt-4o\""}}"#;
        let value: serde_json::Value = serde_json::from_str(body).expect("valid JSON");
        assert_eq!(value["model"], "gpt-4o", "{value}");
    }
}
