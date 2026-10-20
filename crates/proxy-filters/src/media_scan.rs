//! Bounded structural scanners for media responses (ADR-0010 decision 4).
//!
//! An image response carries base64 images of several MB, far over the JSON
//! buffer the text endpoints use, and its `usage` object comes after them. So
//! these scanners never hold the body. They track object depth and string
//! state, skip string contents without keeping them, and keep only:
//!
//! - the top-level `usage` object, as raw text, up to [`MAX_USAGE_OBJECT_BYTES`];
//! - a few top-level string scalars (`size`, `quality`, `model`, `type`), each
//!   up to [`MAX_SCALAR_BYTES`];
//! - the count of elements of the top-level `data` array that closed.
//!
//! Memory is O(one usage object + a few short scalars), whatever the body size.
//! The bytes come from the provider, so nothing here panics on any input; a
//! shape it does not recognise yields no facts, never invented ones. This is a
//! fuzz target (`fuzz/fuzz_targets/media_scan.rs`).

/// Largest `usage` object kept. A bigger one is not read, so the response is
/// metered from its other meters only.
pub const MAX_USAGE_OBJECT_BYTES: usize = 16 * 1024;

/// Largest top-level string scalar kept. A longer value is dropped, not cut:
/// a truncated `size` would match the wrong price row.
pub const MAX_SCALAR_BYTES: usize = 128;

/// Largest top-level key compared against the keys of interest. A longer key
/// is none of them.
const MAX_KEY_BYTES: usize = 32;

/// What a [`MediaJsonScanner`] read from one JSON document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MediaFacts {
    /// The top-level `usage` object as raw JSON text, if it closed inside
    /// [`MAX_USAGE_OBJECT_BYTES`].
    pub usage: Option<String>,
    /// A top-level `usage` object was over [`MAX_USAGE_OBJECT_BYTES`].
    pub usage_oversized: bool,
    /// Elements of the top-level `data` array that closed. `None` when no
    /// top-level `data` array was seen.
    pub data_elements: Option<u64>,
    pub size: Option<String>,
    pub quality: Option<String>,
    pub model: Option<String>,
    /// The top-level `type`, which names a stream event.
    pub event_type: Option<String>,
    /// The top-level object closed: absent facts are proven absent.
    pub complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    Usage,
    Data,
    Size,
    Quality,
    Model,
    Type,
    Other,
}

fn classify_key(key: &[u8]) -> Key {
    match key {
        b"usage" => Key::Usage,
        b"data" => Key::Data,
        b"size" => Key::Size,
        b"quality" => Key::Quality,
        b"model" => Key::Model,
        b"type" => Key::Type,
        _ => Key::Other,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Before the top-level `{`.
    BeforeTop,
    /// In the top-level object, expecting a key or `}`.
    ExpectKey,
    /// In a top-level key.
    InKey,
    /// After a top-level key, expecting `:`.
    AfterKey,
    /// After `:`, expecting a value.
    BeforeValue,
    /// In a top-level string value.
    InString,
    /// In a top-level bare literal.
    InLiteral,
    /// In a nested value of the top-level object; `depth` counts open
    /// containers below the top level.
    Nested,
    /// After a top-level value, expecting `,` or `}`.
    AfterValue,
    /// The top-level object closed.
    Done,
    /// The input is not a JSON object this scanner can follow.
    Invalid,
}

/// Incremental scanner over one JSON document. Feed every chunk in order
/// with [`Self::push`]; chunks may split anywhere.
#[derive(Debug)]
pub struct MediaJsonScanner {
    state: State,
    escaped: bool,
    key: Vec<u8>,
    key_overflow: bool,
    current: Key,
    /// The string scalar being captured, when `current` is a scalar of interest.
    scalar: Vec<u8>,
    scalar_overflow: bool,
    /// Open containers below the top-level object, while `state == Nested`.
    depth: u32,
    nested_in_string: bool,
    /// The raw usage object being captured, when `current == Usage`.
    usage_buf: Vec<u8>,
    usage_overflow: bool,
    /// In a `data` array: an element literal or string is in progress at
    /// array depth.
    element_open: bool,
    data_count: u64,
    facts: MediaFacts,
}

impl Default for MediaJsonScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl MediaJsonScanner {
    pub fn new() -> Self {
        Self {
            state: State::BeforeTop,
            escaped: false,
            key: Vec::new(),
            key_overflow: false,
            current: Key::Other,
            scalar: Vec::new(),
            scalar_overflow: false,
            depth: 0,
            nested_in_string: false,
            usage_buf: Vec::new(),
            usage_overflow: false,
            element_open: false,
            data_count: 0,
            facts: MediaFacts::default(),
        }
    }

    /// The facts read so far. A cut document keeps what closed before the cut.
    pub fn facts(&self) -> &MediaFacts {
        &self.facts
    }

    /// The facts, consuming the scanner.
    pub fn finish(self) -> MediaFacts {
        self.facts
    }

    /// The scanner has decided: the object closed, or the input is not one.
    pub fn is_done(&self) -> bool {
        matches!(self.state, State::Done | State::Invalid)
    }

    pub fn push(&mut self, chunk: &[u8]) {
        for &byte in chunk {
            if self.is_done() {
                return;
            }
            self.feed(byte);
        }
    }

    fn feed(&mut self, byte: u8) {
        match self.state {
            State::BeforeTop => match byte {
                b'{' => self.state = State::ExpectKey,
                b if is_ws(b) => {}
                _ => self.state = State::Invalid,
            },
            State::ExpectKey => match byte {
                b'"' => {
                    self.key.clear();
                    self.key_overflow = false;
                    self.escaped = false;
                    self.state = State::InKey;
                }
                b'}' => self.close_top(),
                b if is_ws(b) => {}
                _ => self.state = State::Invalid,
            },
            State::InKey => {
                if self.escaped {
                    self.escaped = false;
                    self.push_key(byte);
                } else if byte == b'\\' {
                    self.escaped = true;
                    self.push_key(byte);
                } else if byte == b'"' {
                    self.current = self.decode_key();
                    self.state = State::AfterKey;
                } else {
                    self.push_key(byte);
                }
            }
            State::AfterKey => match byte {
                b':' => self.state = State::BeforeValue,
                b if is_ws(b) => {}
                _ => self.state = State::Invalid,
            },
            State::BeforeValue => self.begin_value(byte),
            State::InString => {
                if self.escaped {
                    self.escaped = false;
                    self.push_scalar(byte);
                } else if byte == b'\\' {
                    self.escaped = true;
                    self.push_scalar(byte);
                } else if byte == b'"' {
                    self.end_string();
                    self.state = State::AfterValue;
                } else {
                    self.push_scalar(byte);
                }
            }
            State::InLiteral => {
                if is_ws(byte) || matches!(byte, b',' | b'}') {
                    self.state = State::AfterValue;
                    self.feed(byte);
                } else if !matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'+' | b'.' | b'E') {
                    self.state = State::Invalid;
                }
            }
            State::Nested => self.nested(byte),
            State::AfterValue => match byte {
                b',' => self.state = State::ExpectKey,
                b'}' => self.close_top(),
                b if is_ws(b) => {}
                _ => self.state = State::Invalid,
            },
            State::Done | State::Invalid => {}
        }
    }

    fn begin_value(&mut self, byte: u8) {
        match byte {
            b if is_ws(b) => {}
            b'"' => {
                self.scalar.clear();
                self.scalar_overflow = false;
                self.escaped = false;
                self.state = State::InString;
            }
            b'{' | b'[' => {
                self.depth = 1;
                self.nested_in_string = false;
                self.escaped = false;
                self.usage_buf.clear();
                self.usage_overflow = false;
                if self.current == Key::Usage {
                    if byte == b'{' {
                        self.usage_buf.push(byte);
                    } else {
                        // Not an object: no usage.
                        self.current = Key::Other;
                        self.facts.usage = None;
                    }
                }
                if self.current == Key::Data {
                    if byte == b'[' {
                        // Last key wins: a repeated `data` restarts the count.
                        self.data_count = 0;
                        self.element_open = false;
                        self.facts.data_elements = Some(0);
                    } else {
                        self.current = Key::Other;
                        self.facts.data_elements = None;
                    }
                }
                self.clear_scalar_fact();
                self.state = State::Nested;
            }
            b't' | b'f' | b'n' | b'-' | b'0'..=b'9' => {
                self.clear_scalar_fact();
                match self.current {
                    Key::Usage => self.facts.usage = None,
                    Key::Data => self.facts.data_elements = None,
                    _ => {}
                }
                self.state = State::InLiteral;
            }
            _ => self.state = State::Invalid,
        }
    }

    fn nested(&mut self, byte: u8) {
        if self.current == Key::Usage && !self.usage_overflow {
            if self.usage_buf.len() >= MAX_USAGE_OBJECT_BYTES {
                self.usage_overflow = true;
                self.usage_buf = Vec::new();
            } else {
                self.usage_buf.push(byte);
            }
        }
        let in_data = self.current == Key::Data;
        if self.nested_in_string {
            if self.escaped {
                self.escaped = false;
            } else if byte == b'\\' {
                self.escaped = true;
            } else if byte == b'"' {
                self.nested_in_string = false;
                if in_data && self.depth == 1 && self.element_open {
                    // A string element of `data` closed.
                    self.element_open = false;
                    self.count_element();
                }
            }
            return;
        }
        if in_data
            && self.depth == 1
            && self.element_open
            && (is_ws(byte) || matches!(byte, b',' | b']'))
        {
            // A literal element of `data` ended.
            self.element_open = false;
            self.count_element();
        }
        match byte {
            b'"' => {
                self.nested_in_string = true;
                if in_data && self.depth == 1 {
                    self.element_open = true;
                }
            }
            b'{' | b'[' => self.depth = self.depth.saturating_add(1),
            b'}' | b']' => {
                self.depth = self.depth.saturating_sub(1);
                if in_data && self.depth == 1 {
                    // An object or array element of `data` closed.
                    self.count_element();
                }
                if self.depth == 0 {
                    self.end_nested();
                    self.state = State::AfterValue;
                }
            }
            b if is_ws(b) || b == b',' || b == b':' => {}
            _ => {
                if in_data && self.depth == 1 {
                    self.element_open = true;
                }
            }
        }
    }

    fn count_element(&mut self) {
        self.data_count = self.data_count.saturating_add(1);
        self.facts.data_elements = Some(self.data_count);
    }

    fn end_nested(&mut self) {
        if self.current == Key::Usage {
            self.facts.usage_oversized = self.usage_overflow;
            self.facts.usage = if self.usage_overflow {
                None
            } else {
                String::from_utf8(std::mem::take(&mut self.usage_buf)).ok()
            };
        }
    }

    fn push_key(&mut self, byte: u8) {
        if self.key.len() < MAX_KEY_BYTES {
            self.key.push(byte);
        } else {
            self.key_overflow = true;
        }
    }

    fn decode_key(&self) -> Key {
        if self.key_overflow {
            return Key::Other;
        }
        if self.key.contains(&b'\\') {
            // A key spelled with an escape names the same member to the
            // provider's decoder.
            return decode_json_string(&self.key)
                .map_or(Key::Other, |k| classify_key(k.as_bytes()));
        }
        classify_key(&self.key)
    }

    fn wants_scalar(&self) -> bool {
        matches!(
            self.current,
            Key::Size | Key::Quality | Key::Model | Key::Type
        )
    }

    fn push_scalar(&mut self, byte: u8) {
        if !self.wants_scalar() || self.scalar_overflow {
            return;
        }
        if self.scalar.len() < MAX_SCALAR_BYTES {
            self.scalar.push(byte);
        } else {
            self.scalar_overflow = true;
        }
    }

    fn end_string(&mut self) {
        let value = if self.scalar_overflow {
            None
        } else {
            decode_json_string(&self.scalar)
        };
        match self.current {
            Key::Size => self.facts.size = value,
            Key::Quality => self.facts.quality = value,
            Key::Model => self.facts.model = value,
            Key::Type => self.facts.event_type = value,
            Key::Usage => self.facts.usage = None,
            Key::Data => self.facts.data_elements = None,
            Key::Other => {}
        }
    }

    /// A non-string value for a scalar key replaces an earlier string one
    /// (last key wins), so that fact is no longer known.
    fn clear_scalar_fact(&mut self) {
        match self.current {
            Key::Size => self.facts.size = None,
            Key::Quality => self.facts.quality = None,
            Key::Model => self.facts.model = None,
            Key::Type => self.facts.event_type = None,
            _ => {}
        }
    }

    fn close_top(&mut self) {
        self.facts.complete = true;
        self.state = State::Done;
    }
}

fn is_ws(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

fn decode_json_string(raw: &[u8]) -> Option<String> {
    let mut quoted = Vec::with_capacity(raw.len() + 2);
    quoted.push(b'"');
    quoted.extend_from_slice(raw);
    quoted.push(b'"');
    serde_json::from_slice(&quoted).ok()
}

/// What a [`MediaSseScanner`] read from an image stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MediaStreamFacts {
    /// `*.completed` events that closed.
    pub completed: u64,
    /// The `usage` of the last completed event that carried one.
    pub usage: Option<String>,
    pub usage_oversized: bool,
    /// From the last completed event that carried them.
    pub size: Option<String>,
    pub quality: Option<String>,
    pub model: Option<String>,
}

/// Bounded scanner over an image SSE stream. Each `data:` line is one JSON
/// event, and a completed image event holds the whole base64 image, so lines
/// are fed through a [`MediaJsonScanner`] as they arrive and never held.
///
/// The `images` meter counts `*.completed` events. Partial-image events are
/// not images: their surcharge is in the reported output tokens (ADR-0010
/// decision 4).
#[derive(Debug, Default)]
pub struct MediaSseScanner {
    /// Bytes of the current line's field name, up to `data:`.
    prefix: Vec<u8>,
    /// The current line is a `data:` line being fed to `frame`.
    frame: Option<MediaJsonScanner>,
    /// The current line is not a data line; skip to its end.
    skipping: bool,
    facts: MediaStreamFacts,
}

impl MediaSseScanner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn facts(&self) -> &MediaStreamFacts {
        &self.facts
    }

    pub fn push(&mut self, chunk: &[u8]) {
        let mut rest = chunk;
        while !rest.is_empty() {
            let line_end = rest.iter().position(|&b| b == b'\n');
            let (part, ends_line) = match line_end {
                Some(i) => (&rest[..i], true),
                None => (rest, false),
            };
            self.feed_part(part);
            if ends_line {
                self.end_line();
                rest = &rest[line_end.unwrap_or_default() + 1..];
            } else {
                rest = &[];
            }
        }
    }

    fn feed_part(&mut self, mut part: &[u8]) {
        if self.skipping {
            return;
        }
        if self.frame.is_none() {
            const DATA: &[u8] = b"data:";
            while !part.is_empty() && self.prefix.len() < DATA.len() {
                self.prefix.push(part[0]);
                part = &part[1..];
                if !DATA.starts_with(&self.prefix) {
                    self.skipping = true;
                    return;
                }
            }
            if self.prefix.len() < DATA.len() {
                return;
            }
            self.frame = Some(MediaJsonScanner::new());
        }
        if let Some(frame) = self.frame.as_mut() {
            // The optional space after `data:` is whitespace to the scanner.
            frame.push(part);
        }
    }

    fn end_line(&mut self) {
        if let Some(frame) = self.frame.take() {
            let facts = frame.finish();
            if facts.complete
                && facts
                    .event_type
                    .as_deref()
                    .is_some_and(|t| t.ends_with(".completed"))
            {
                self.facts.completed = self.facts.completed.saturating_add(1);
                if facts.usage.is_some() || facts.usage_oversized {
                    self.facts.usage = facts.usage;
                    self.facts.usage_oversized = facts.usage_oversized;
                }
                if facts.size.is_some() {
                    self.facts.size = facts.size;
                }
                if facts.quality.is_some() {
                    self.facts.quality = facts.quality;
                }
                if facts.model.is_some() {
                    self.facts.model = facts.model;
                }
            }
        }
        self.prefix.clear();
        self.skipping = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_chunks(body: &[u8], chunk: usize) -> MediaFacts {
        let mut scanner = MediaJsonScanner::new();
        for part in body.chunks(chunk.max(1)) {
            scanner.push(part);
        }
        scanner.finish()
    }

    fn image_body(images: usize, b64_len: usize) -> String {
        let b64 = "A".repeat(b64_len);
        let data: Vec<String> = (0..images)
            .map(|_| format!(r#"{{"b64_json":"{b64}","revised_prompt":"a \"cat\" {{x}}"}}"#))
            .collect();
        format!(
            r#"{{"created":1,"data":[{}],"size":"1024x1024","quality":"high","usage":{{"input_tokens":50,"input_tokens_details":{{"text_tokens":40,"image_tokens":10}},"output_tokens":4160,"total_tokens":4210}}}}"#,
            data.join(",")
        )
    }

    #[test]
    fn reads_usage_scalars_and_counts_images_past_a_multi_megabyte_body() {
        let body = image_body(2, 3 << 20);
        // Byte-at-a-time for a small body, and odd chunks for the large one,
        // so every split point inside strings and escapes is exercised.
        for chunk in [7, 4096] {
            let facts = scan_chunks(body.as_bytes(), chunk);
            assert!(facts.complete);
            assert_eq!(facts.data_elements, Some(2));
            assert_eq!(facts.size.as_deref(), Some("1024x1024"));
            assert_eq!(facts.quality.as_deref(), Some("high"));
            let usage: serde_json::Value =
                serde_json::from_str(facts.usage.as_deref().expect("usage")).expect("json");
            assert_eq!(usage["output_tokens"], 4160);
            assert_eq!(usage["input_tokens_details"]["image_tokens"], 10);
        }
        let small = image_body(3, 5);
        assert_eq!(scan_chunks(small.as_bytes(), 1).data_elements, Some(3));
    }

    #[test]
    fn a_cut_body_keeps_only_the_images_that_closed() {
        let body = image_body(3, 1000);
        // Cut inside the third element's base64.
        let cut = body.find("AAAA").unwrap() + 2 * 1060 + 500;
        let facts = scan_chunks(&body.as_bytes()[..cut], 64);
        assert!(!facts.complete);
        assert_eq!(facts.data_elements, Some(2));
        assert_eq!(facts.usage, None, "usage comes after the cut");
    }

    #[test]
    fn nested_keys_are_not_top_level_facts() {
        let body = br#"{"data":[{"size":"9x9","usage":{"input_tokens":1}}],"meta":{"quality":"low","data":[1,2,3]}}"#;
        let facts = scan_chunks(body, 3);
        assert_eq!(facts.data_elements, Some(1));
        assert_eq!(facts.size, None);
        assert_eq!(facts.quality, None);
        assert_eq!(facts.usage, None);
    }

    #[test]
    fn last_key_wins_and_wrong_types_clear_a_fact() {
        let facts = scan_chunks(br#"{"size":"a","size":1,"data":[{},{}],"data":[{}]}"#, 2);
        assert_eq!(facts.size, None);
        assert_eq!(facts.data_elements, Some(1));
        let facts = scan_chunks(br#"{"usage":{"input_tokens":1},"usage":"none"}"#, 5);
        assert_eq!(facts.usage, None);
        let facts = scan_chunks(br#"{"data":{"b64_json":"x"}}"#, 5);
        assert_eq!(facts.data_elements, None);
    }

    #[test]
    fn an_escaped_key_names_the_same_member() {
        let facts = scan_chunks(br#"{"size":"512x512","data":["a","b",null]}"#, 1);
        assert_eq!(facts.size.as_deref(), Some("512x512"));
        assert_eq!(facts.data_elements, Some(3));
    }

    #[test]
    fn oversized_values_are_dropped_not_cut() {
        let long = "x".repeat(MAX_SCALAR_BYTES + 1);
        let body = format!(r#"{{"size":"{long}"}}"#);
        assert_eq!(scan_chunks(body.as_bytes(), 9).size, None);
        let big = format!(
            r#"{{"usage":{{"pad":"{}","input_tokens":1}}}}"#,
            "y".repeat(MAX_USAGE_OBJECT_BYTES)
        );
        let facts = scan_chunks(big.as_bytes(), 1000);
        assert_eq!(facts.usage, None);
        assert!(facts.usage_oversized);
    }

    #[test]
    fn non_objects_yield_nothing() {
        for body in [&b"[1,2]"[..], b"not json", b"", b"\"str\"", b"{]"] {
            let facts = scan_chunks(body, 1);
            assert_eq!(facts.data_elements, None, "{body:?}");
            assert!(!facts.complete, "{body:?}");
        }
    }

    #[test]
    fn sse_counts_completed_events_and_takes_the_last_usage() {
        let b64 = "B".repeat(2 << 20);
        let stream = format!(
            "event: image_generation.partial_image\n\
             data: {{\"type\":\"image_generation.partial_image\",\"b64_json\":\"{b64}\"}}\n\n\
             event: image_generation.completed\r\n\
             data: {{\"type\":\"image_generation.completed\",\"b64_json\":\"{b64}\",\"size\":\"1024x1536\",\"quality\":\"medium\",\"usage\":{{\"input_tokens\":7,\"output_tokens\":100}}}}\r\n\r\n"
        );
        for chunk in [5, 65536] {
            let mut scanner = MediaSseScanner::new();
            for part in stream.as_bytes().chunks(chunk) {
                scanner.push(part);
            }
            let facts = scanner.facts();
            assert_eq!(facts.completed, 1);
            assert_eq!(facts.size.as_deref(), Some("1024x1536"));
            assert_eq!(facts.quality.as_deref(), Some("medium"));
            let usage: serde_json::Value =
                serde_json::from_str(facts.usage.as_deref().unwrap()).unwrap();
            assert_eq!(usage["output_tokens"], 100);
        }
    }

    #[test]
    fn sse_cut_inside_a_completed_event_counts_nothing_for_it() {
        let stream = "data: {\"type\":\"image_generation.completed\",\"b64_json\":\"AAAA";
        let mut scanner = MediaSseScanner::new();
        scanner.push(stream.as_bytes());
        assert_eq!(scanner.facts().completed, 0);
        assert_eq!(scanner.facts().usage, None);
    }
}
