//! Strict JSON-object decoding for admin request bodies.
//!
//! A `#[derive(Deserialize)]` struct also accepts a JSON array and reads its
//! elements as the fields in declaration order, so `["all"]` would parse as
//! `{"access": "all"}` and `["1.00", "daily"]` as a budget. `deny_unknown_fields`
//! cannot catch this: positional form has no field names. The admin API
//! documents objects only, and a policy the operator did not write in the
//! documented shape must be a 400 (AGENTS.md invariant 1), so request structs
//! decode through [`ObjectOnly`], which routes a struct to `deserialize_map`
//! and so rejects any other JSON type.

use serde::de::{DeserializeOwned, Deserializer, Visitor};
use serde::Deserialize;

/// [`serde_json::from_slice`] for a request struct `T`, refusing any top-level
/// value that is not a JSON object.
pub(super) fn from_slice<T: DeserializeOwned>(body: &[u8]) -> Result<T, serde_json::Error> {
    let mut de = serde_json::Deserializer::from_slice(body);
    let value = T::deserialize(ObjectOnly(&mut de))?;
    // Rust note: `from_slice` does this check itself; a hand-built
    // `Deserializer` must call `end` to refuse trailing bytes.
    de.end()?;
    Ok(value)
}

/// `deserialize_with` helper for an `Option<T>` struct field: `null` is
/// `None`, an object is `Some`, and an array is refused like at the top level.
pub(super) fn nullable_object<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Object<T>>::deserialize(de)?.map(|Object(value)| value))
}

struct Object<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        T::deserialize(ObjectOnly(de)).map(Object)
    }
}

/// Wraps a deserializer so a struct reads only from a map. Only `T::deserialize`
/// for a derived struct sees it, which calls `deserialize_struct`; every other
/// request falls back to `deserialize_any`, which is all a derived struct's own
/// visitor could need.
struct ObjectOnly<D>(D);

impl<'de, D: Deserializer<'de>> Deserializer<'de> for ObjectOnly<D> {
    type Error = D::Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.0.deserialize_any(visitor)
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.0.deserialize_map(visitor)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map enum identifier ignored_any
    }
}
