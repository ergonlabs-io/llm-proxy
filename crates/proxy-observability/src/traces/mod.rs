//! Best-effort trace export for analytics and fine-tuning (ADR-0008;
//! design in `internal-docs/trace-export-design.md`). Not billing: nothing
//! reads traces back to enforce or charge.

pub mod capture;
pub mod config;
pub mod gate;

/// Longest `tenant=<encoded id>` directory name a tenant may have to opt in.
/// Segment file names sit under it and must stay below `NAME_MAX` (255).
pub const MAX_TENANT_DIR_BYTES: usize = 200;

/// Percent-encodes an id for use as one path segment: bytes outside
/// `[A-Za-z0-9_-]` become `%XX`. `.` is encoded too, so neither `.` nor `..`
/// can appear, and distinct ids never collide after encoding.
pub fn encode_path_component(id: &str) -> String {
    let mut out = String::with_capacity(id.len());
    for b in id.bytes() {
        if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The directory name segments of `tenant` sit under.
pub fn tenant_dir(tenant: &str) -> String {
    format!("tenant={}", encode_path_component(tenant))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ids that could escape a directory, or collide with an encoded form,
    /// encode to distinct, inert segments.
    #[test]
    fn hostile_ids_encode_to_distinct_inert_segments() {
        assert_eq!(encode_path_component("acme-co_1"), "acme-co_1");
        assert_eq!(encode_path_component(".."), "%2E%2E");
        assert_eq!(encode_path_component("."), "%2E");
        assert_eq!(encode_path_component("a/b"), "a%2Fb");
        // A literal "%2F" must not encode to the same thing as "/".
        assert_eq!(encode_path_component("a%2Fb"), "a%252Fb");
        assert_eq!(encode_path_component("é"), "%C3%A9");
        assert_eq!(tenant_dir("t=1"), "tenant=t%3D1");
    }
}
