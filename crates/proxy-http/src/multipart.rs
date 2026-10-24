//! Bounded `multipart/form-data` request scanner (ADR-0010 decision 4).
//!
//! Transcription, translation and image edits upload a file, so their body is
//! a form, not JSON. The proxy still has to route on the `model` field,
//! authorize it, and prove the shape facts a spend budget admits on
//! (`response_format`), exactly as it does for a JSON body.
//!
//! The scanner reads text fields and skips file contents without copying
//! them. Request decoding is fully buffered (`filter_manager`), so it reads
//! the whole body, not a prefix: a field after a large file is found, and an
//! absent field is proven absent. What it keeps is bounded: one value of at
//! most [`MAX_FIELD_BYTES`] per field of interest. The work is one pass over
//! the body, whatever the client sends.
//!
//! It refuses to guess. A field the provider's form parser might read
//! differently from this one is [`Field::Unproven`]: a repeated field, a field
//! sent as a file, a field with a transfer encoding, or one too long to keep.
//! A body it cannot follow (no leading boundary, a missing delimiter, a
//! malformed part head) yields no facts at all. The bytes come from the
//! client, so nothing here panics on any input. This is a fuzz target
//! (`fuzz/fuzz_targets/multipart_scan.rs`).
//!
//! The router uses the same scan to check the routed model against the body
//! and to rewrite it for a provider model mapping, so the facts the proxy
//! metered on and the bytes the provider decodes agree.

use std::ops::Range;

/// Longest field value kept. A longer value of a field of interest is
/// [`Field::Unproven`]: a cut model name would route somewhere else.
pub const MAX_FIELD_BYTES: usize = 512;

/// Longest header block of one part. A longer one ends the scan with no
/// facts.
pub const MAX_HEADER_BYTES: usize = 8 * 1024;

/// Most parts read. A form with more ends the scan with no facts.
pub const MAX_PARTS: usize = 1024;

/// Longest boundary RFC 2046 allows.
const MAX_BOUNDARY_BYTES: usize = 70;

/// The value of one form field of interest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Field {
    /// The form has no such field.
    #[default]
    Absent,
    /// The field's text, sent once, as a plain text field.
    Value(String),
    /// The field is there, but its value is not known: see the module doc.
    Unproven,
}

impl Field {
    /// The value, when it is proven.
    pub fn value(&self) -> Option<&str> {
        match self {
            Field::Value(value) => Some(value),
            Field::Absent | Field::Unproven => None,
        }
    }
}

/// How a [`scan`] ended.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Outcome {
    /// The closing delimiter was found: every part was read.
    Complete,
    /// The body is not a form this scanner can follow. Every field is
    /// [`Field::Absent`] and proves nothing.
    #[default]
    Invalid,
}

/// The fields of interest of one form.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MultipartFacts {
    pub model: Field,
    /// Where the `model` value sits in the body, when it is a
    /// [`Field::Value`]. The router splices a mapped model here.
    pub model_range: Option<Range<usize>>,
    pub response_format: Field,
    pub size: Field,
    pub quality: Field,
    pub stream: Field,
    pub outcome: Outcome,
}

impl MultipartFacts {
    /// Every part was read and no field of interest is unproven, so an
    /// absent field is proven absent.
    pub fn complete(&self) -> bool {
        self.outcome == Outcome::Complete
            && [
                &self.model,
                &self.response_format,
                &self.size,
                &self.quality,
                &self.stream,
            ]
            .iter()
            .all(|field| **field != Field::Unproven)
    }
}

/// The boundary of a `multipart/form-data` content type, or `None` for any
/// other media type or a missing or malformed boundary.
pub fn form_data_boundary(content_type: &str) -> Option<String> {
    let mut parts = content_type.split(';');
    let media_type = parts.next()?.trim();
    if !media_type.eq_ignore_ascii_case("multipart/form-data") {
        return None;
    }
    let mut boundary = None;
    for param in parts {
        let Some((name, value)) = param.split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("boundary") {
            continue;
        }
        if boundary.is_some() {
            // Two boundaries: either one could be the delimiter.
            return None;
        }
        let value = value.trim();
        let value = match value.strip_prefix('"') {
            Some(quoted) => quoted.strip_suffix('"')?,
            // Unquoted, it must be a token (RFC 2045): parsers that stop at a
            // separator would otherwise read a different boundary.
            None if value.bytes().any(|c| b" ,=()<>@:\\/[]?{}".contains(&c)) => return None,
            None => value,
        };
        boundary = Some(value.to_string());
    }
    boundary.filter(|b| {
        !b.is_empty()
            && b.len() <= MAX_BOUNDARY_BYTES
            && !b.bytes().any(|c| c == b'"' || c.is_ascii_control())
    })
}

/// Which field of interest a part name is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Name {
    Model,
    ResponseFormat,
    Size,
    Quality,
    Stream,
}

fn field_name(name: &[u8]) -> Option<Name> {
    match name {
        b"model" => Some(Name::Model),
        b"response_format" => Some(Name::ResponseFormat),
        b"size" => Some(Name::Size),
        b"quality" => Some(Name::Quality),
        b"stream" => Some(Name::Stream),
        _ => None,
    }
}

impl MultipartFacts {
    fn slot(&mut self, name: Name) -> &mut Field {
        match name {
            Name::Model => &mut self.model,
            Name::ResponseFormat => &mut self.response_format,
            Name::Size => &mut self.size,
            Name::Quality => &mut self.quality,
            Name::Stream => &mut self.stream,
        }
    }
}

/// What a part's header block says about it.
struct PartHead {
    name: Vec<u8>,
    is_file: bool,
    /// A `Content-Transfer-Encoding` other than the identity ones.
    encoded: bool,
}

/// Scan a whole `multipart/form-data` body delimited by `boundary`.
pub fn scan(body: &[u8], boundary: &str) -> MultipartFacts {
    scan_inner(body, boundary.as_bytes()).unwrap_or_default()
}

/// `None` is [`Outcome::Invalid`].
fn scan_inner(body: &[u8], boundary: &[u8]) -> Option<MultipartFacts> {
    if boundary.is_empty() || boundary.len() > MAX_BOUNDARY_BYTES {
        return None;
    }
    // Every delimiter after the first is CRLF, `--`, the boundary. The first
    // may open the body without the CRLF. A preamble before it is refused:
    // form parsers disagree on it.
    let mut delimiter = b"\r\n--".to_vec();
    delimiter.extend_from_slice(boundary);
    let table = kmp_table(&delimiter);
    let mut at = delimiter.len() - 2;
    if !body.starts_with(&delimiter[2..]) {
        return None;
    }
    let mut facts = MultipartFacts::default();
    let mut parts = 0usize;
    loop {
        let rest = &body[at..];
        if rest.starts_with(b"--") {
            facts.outcome = Outcome::Complete;
            return Some(facts);
        }
        // Transport padding, then the line end that opens the part.
        let padding = rest
            .iter()
            .take_while(|b| matches!(b, b' ' | b'\t'))
            .count();
        if !rest[padding..].starts_with(b"\r\n") {
            return None;
        }
        at += padding + 2;
        parts += 1;
        if parts > MAX_PARTS {
            return None;
        }
        // The header block ends at an empty line; a part may have none.
        let (head, content_start) = if body[at..].starts_with(b"\r\n") {
            (&body[at..at], at + 2)
        } else {
            let window = &body[at..body.len().min(at + MAX_HEADER_BYTES + 4)];
            let end = find(window, b"\r\n\r\n", &kmp_table(b"\r\n\r\n"))?;
            (&body[at..at + end], at + end + 4)
        };
        let head = parse_head(head)?;
        let content_len = find(&body[content_start..], &delimiter, &table)?;
        let content = content_start..content_start + content_len;
        at = content.end + delimiter.len();
        let Some(name) = field_name(&head.name) else {
            continue;
        };
        let value = if *facts.slot(name) != Field::Absent
            || head.is_file
            || head.encoded
            || content.len() > MAX_FIELD_BYTES
        {
            Field::Unproven
        } else {
            match std::str::from_utf8(&body[content.clone()]) {
                Ok(text) => Field::Value(text.to_string()),
                Err(_) => Field::Unproven,
            }
        };
        if name == Name::Model {
            facts.model_range = matches!(value, Field::Value(_)).then_some(content);
        }
        *facts.slot(name) = value;
    }
}

/// Read one part's header block. `None` when it is malformed or has no
/// single `form-data` disposition with one plain `name`.
fn parse_head(head: &[u8]) -> Option<PartHead> {
    let mut disposition = None;
    let mut encoded = false;
    if head.is_empty() {
        return None;
    }
    for line in split_lines(head) {
        // A folded line continues the previous header; parsers disagree on
        // it, so it is refused.
        if line.first().is_some_and(|b| matches!(b, b' ' | b'\t')) {
            return None;
        }
        let colon = line.iter().position(|&b| b == b':')?;
        let (name, value) = (&line[..colon], trim(&line[colon + 1..]));
        if name.eq_ignore_ascii_case(b"content-disposition") {
            if disposition.is_some() {
                return None;
            }
            disposition = Some(value);
        } else if name.eq_ignore_ascii_case(b"content-transfer-encoding") {
            encoded |= !["7bit", "8bit", "binary"]
                .iter()
                .any(|identity| value.eq_ignore_ascii_case(identity.as_bytes()));
        }
    }
    let (name, is_file) = parse_disposition(disposition?)?;
    Some(PartHead {
        name,
        is_file,
        encoded,
    })
}

fn split_lines(head: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = Some(head);
    std::iter::from_fn(move || {
        let current = rest?;
        match current.windows(2).position(|w| w == b"\r\n") {
            Some(end) => {
                rest = Some(&current[end + 2..]);
                Some(&current[..end])
            }
            None => {
                rest = None;
                Some(current)
            }
        }
    })
}

fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t'))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !matches!(b, b' ' | b'\t'))
        .map_or(start, |i| i + 1);
    &bytes[start..end]
}

/// `form-data; name="model"; filename="a.mp3"`: the part name, and whether
/// the part is a file. `None` when the type is not `form-data`, the name is
/// missing or repeated, or it is given in the extended `name*` form.
fn parse_disposition(value: &[u8]) -> Option<(Vec<u8>, bool)> {
    let mut rest = value;
    let kind_end = rest.iter().position(|&b| b == b';').unwrap_or(rest.len());
    if !trim(&rest[..kind_end]).eq_ignore_ascii_case(b"form-data") {
        return None;
    }
    rest = &rest[kind_end..];
    let mut name = None;
    let mut is_file = false;
    while let Some(after) = rest.strip_prefix(b";") {
        let after = trim_start(after);
        let eq = after.iter().position(|&b| b == b'=')?;
        let param = trim(&after[..eq]);
        let (param_value, remainder) = parse_param_value(trim_start(&after[eq + 1..]))?;
        rest = trim_start(remainder);
        if param.eq_ignore_ascii_case(b"name") {
            if name.is_some() {
                return None;
            }
            name = Some(param_value);
        } else if param.eq_ignore_ascii_case(b"name*") {
            return None;
        } else if param.eq_ignore_ascii_case(b"filename")
            || param.eq_ignore_ascii_case(b"filename*")
        {
            is_file = true;
        }
    }
    if !rest.is_empty() {
        return None;
    }
    Some((name?, is_file))
}

fn trim_start(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t'))
        .unwrap_or(bytes.len());
    &bytes[start..]
}

/// A quoted string (with `\` quoting the next byte) or a token, and the
/// bytes after it.
fn parse_param_value(input: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    if let Some(quoted) = input.strip_prefix(b"\"") {
        let mut value = Vec::new();
        let mut i = 0;
        while i < quoted.len() {
            match quoted[i] {
                b'"' => return Some((value, &quoted[i + 1..])),
                b'\\' => {
                    value.push(*quoted.get(i + 1)?);
                    i += 2;
                }
                byte => {
                    value.push(byte);
                    i += 1;
                }
            }
        }
        return None;
    }
    let end = input
        .iter()
        .position(|&b| b == b';' || b == b' ' || b == b'\t')
        .unwrap_or(input.len());
    if end == 0 {
        return None;
    }
    Some((input[..end].to_vec(), &input[end..]))
}

/// Knuth-Morris-Pratt failure table, so a search is linear in the haystack
/// whatever bytes the client chose.
fn kmp_table(needle: &[u8]) -> Vec<usize> {
    let mut table = vec![0; needle.len()];
    let mut k = 0;
    for i in 1..needle.len() {
        while k > 0 && needle[i] != needle[k] {
            k = table[k - 1];
        }
        if needle[i] == needle[k] {
            k += 1;
        }
        table[i] = k;
    }
    table
}

/// The first position of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8], table: &[usize]) -> Option<usize> {
    let mut k = 0;
    for (i, &byte) in haystack.iter().enumerate() {
        while k > 0 && byte != needle[k] {
            k = table[k - 1];
        }
        if byte == needle[k] {
            k += 1;
            if k == needle.len() {
                return Some(i + 1 - k);
            }
        }
    }
    None
}

/// `body` with the bytes at `range` replaced by `value`. For the router's
/// model mapping, at a [`MultipartFacts::model_range`]; `None` when `value`
/// could end the part early.
pub fn replace_range(body: &[u8], range: Range<usize>, value: &str) -> Option<Vec<u8>> {
    if value.bytes().any(|b| b == b'\r' || b == b'\n') || range.end > body.len() {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() - range.len() + value.len());
    out.extend_from_slice(&body[..range.start]);
    out.extend_from_slice(value.as_bytes());
    out.extend_from_slice(&body[range.end..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const B: &str = "XyZ";

    /// A form with `fields` as text parts and one file part after them.
    fn form(fields: &[(&str, &str)], file: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        for (name, value) in fields {
            body.extend_from_slice(
                format!(
                    "--{B}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
                )
                .as_bytes(),
            );
        }
        body.extend_from_slice(
            format!(
                "--{B}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.mp3\"\r\n\
                 Content-Type: audio/mpeg\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(file);
        body.extend_from_slice(format!("\r\n--{B}--\r\n").as_bytes());
        body
    }

    #[test]
    fn reads_the_fields_of_interest_and_skips_the_file() {
        // The file holds text that looks like a delimiter without the CRLF,
        // and a field after it must still be found.
        let mut body = form(&[("model", "whisper-1")], b"--XyZ junk \r\n-XyZ\r\n");
        body.truncate(body.len() - format!("\r\n--{B}--\r\n").len());
        body.extend_from_slice(
            format!(
                "\r\n--{B}\r\ncontent-disposition: form-data; name=response_format\r\n\r\nverbose_json\r\n--{B}--"
            )
            .as_bytes(),
        );
        let facts = scan(&body, B);
        assert_eq!(facts.outcome, Outcome::Complete);
        assert_eq!(facts.model.value(), Some("whisper-1"));
        assert_eq!(facts.response_format.value(), Some("verbose_json"));
        assert_eq!(facts.size, Field::Absent);
        assert!(facts.complete());
        let range = facts.model_range.expect("model range");
        assert_eq!(&body[range], b"whisper-1");
    }

    #[test]
    fn a_large_file_before_the_model_is_skipped_not_held() {
        let file = vec![b'A'; 3 << 20];
        let mut body = format!(
            "--{B}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x.png\"\r\n\r\n"
        )
        .into_bytes();
        body.extend_from_slice(&file);
        body.extend_from_slice(
            format!("\r\n--{B}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\ngpt-image-1\r\n--{B}--\r\n")
                .as_bytes(),
        );
        let facts = scan(&body, B);
        assert_eq!(facts.model.value(), Some("gpt-image-1"));
        assert!(facts.complete());
    }

    #[test]
    fn ambiguous_fields_are_unproven_and_the_form_is_not_complete() {
        for (case, body) in [
            ("repeated", form(&[("model", "a"), ("model", "b")], b"")),
            (
                "sent as a file",
                format!(
                    "--{B}\r\nContent-Disposition: form-data; name=\"model\"; filename=\"m\"\r\n\r\na\r\n--{B}--"
                )
                .into_bytes(),
            ),
            (
                "transfer encoded",
                format!(
                    "--{B}\r\nContent-Disposition: form-data; name=\"model\"\r\nContent-Transfer-Encoding: base64\r\n\r\nYQ==\r\n--{B}--"
                )
                .into_bytes(),
            ),
            (
                "too long",
                form(&[("model", &"m".repeat(MAX_FIELD_BYTES + 1))], b""),
            ),
        ] {
            let facts = scan(&body, B);
            assert_eq!(facts.outcome, Outcome::Complete, "{case}");
            assert_eq!(facts.model, Field::Unproven, "{case}");
            assert_eq!(facts.model_range, None, "{case}");
            assert!(!facts.complete(), "{case}");
        }
    }

    #[test]
    fn a_body_it_cannot_follow_proves_nothing() {
        let good = form(&[("model", "m")], b"x");
        for (case, body) in [
            ("preamble", [b"hello\r\n".as_slice(), &good].concat()),
            ("truncated", good[..good.len() - 12].to_vec()),
            ("no disposition", format!("--{B}\r\nContent-Type: text/plain\r\n\r\nm\r\n--{B}--").into_bytes()),
            ("name*", format!("--{B}\r\nContent-Disposition: form-data; name*=UTF-8''model\r\n\r\nm\r\n--{B}--").into_bytes()),
            ("two names", format!("--{B}\r\nContent-Disposition: form-data; name=a; name=model\r\n\r\nm\r\n--{B}--").into_bytes()),
            ("folded header", format!("--{B}\r\nContent-Disposition: form-data;\r\n name=model\r\n\r\nm\r\n--{B}--").into_bytes()),
            ("bare LF", format!("--{B}\nContent-Disposition: form-data; name=model\n\nm\n--{B}--").into_bytes()),
            ("not form-data", format!("--{B}\r\nContent-Disposition: attachment; name=model\r\n\r\nm\r\n--{B}--").into_bytes()),
            ("empty", Vec::new()),
            // A delimiter followed by neither `--` nor a line end: parsers
            // disagree on whether it ends the part.
            ("near delimiter in content", form(&[("model", "m")], b"a\r\n--XyZz")),
        ] {
            let facts = scan(&body, B);
            assert_eq!(facts, MultipartFacts::default(), "{case}");
            assert!(!facts.complete(), "{case}");
        }
    }

    #[test]
    fn the_boundary_comes_from_a_form_data_content_type_only() {
        assert_eq!(
            form_data_boundary("multipart/form-data; boundary=abc").as_deref(),
            Some("abc")
        );
        assert_eq!(
            form_data_boundary("Multipart/Form-Data;charset=utf-8; BOUNDARY=\"a b\"").as_deref(),
            Some("a b")
        );
        for invalid in [
            "application/json",
            "multipart/mixed; boundary=abc",
            "multipart/form-data",
            "multipart/form-data; boundary=",
            "multipart/form-data; boundary=a; boundary=b",
            "multipart/form-data; boundary=\"unterminated",
            "multipart/form-data; boundary=b, boundary=c",
            "multipart/form-data; boundary=a b",
        ] {
            assert_eq!(form_data_boundary(invalid), None, "{invalid}");
        }
        let long = format!("multipart/form-data; boundary={}", "b".repeat(71));
        assert_eq!(form_data_boundary(&long), None);
    }

    #[test]
    fn a_mapped_model_is_spliced_in_place() {
        let body = form(&[("model", "alias"), ("prompt", "p")], b"img");
        let facts = scan(&body, B);
        let out = replace_range(&body, facts.model_range.unwrap(), "upstream-model-1").unwrap();
        let rescanned = scan(&out, B);
        assert_eq!(rescanned.model.value(), Some("upstream-model-1"));
        assert!(rescanned.complete());
        assert_eq!(replace_range(&body, 0..1, "a\r\nb"), None);
    }

    /// `form` adds a file part, so `parts` parts is `parts - 1` fields.
    fn form_of_parts(parts: usize) -> Vec<u8> {
        let mut fields: Vec<(String, String)> = (1..parts)
            .map(|i| (format!("f{i}"), "v".to_string()))
            .collect();
        fields[0] = ("model".to_string(), "m".to_string());
        let refs: Vec<(&str, &str)> = fields
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        form(&refs, b"")
    }

    #[test]
    fn a_form_with_too_many_parts_proves_nothing() {
        let at_cap = scan(&form_of_parts(MAX_PARTS), B);
        assert_eq!(at_cap.outcome, Outcome::Complete);
        assert_eq!(at_cap.model.value(), Some("m"));
        // One part over the cap refuses the whole form, the model included.
        assert_eq!(
            scan(&form_of_parts(MAX_PARTS + 1), B),
            MultipartFacts::default()
        );
    }
}
