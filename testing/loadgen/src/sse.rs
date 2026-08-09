//! Server-Sent-Events framing, shared by every dialect the driver speaks.
//!
//! The one bug this module exists to prevent: assuming a single TCP read (or
//! a single HTTP/1.1 chunk / HTTP/2 DATA frame) hands you a whole SSE
//! "frame" (an `event:`/`data:` block terminated by a blank line). Under
//! load that assumption breaks constantly -- a frame's bytes can arrive
//! split across arbitrarily many reads. `SseParser` buffers everything it
//! has been given and only ever looks for a frame boundary in the
//! accumulated buffer, so a split frame just means `push` returns nothing
//! until the rest of it shows up.

/// One parsed SSE frame: an optional named `event:` and the (possibly
/// multi-line, but here joined with `\n`) `data:` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseFrame {
    pub event: Option<String>,
    pub data: String,
}

/// Incremental SSE frame parser. Feed it raw bytes as they arrive off the
/// wire (in any chunking); it hands back every frame that becomes complete.
///
/// Rust note: this holds a growing `Vec<u8>` rather than a `String` so a
/// frame boundary search never has to worry about a multi-byte UTF-8
/// sequence being split across two `push` calls -- we only decode a frame's
/// bytes to UTF-8 once we know the whole frame (up to its blank-line
/// terminator) is present.
#[derive(Debug, Default)]
pub struct SseParser {
    buf: Vec<u8>,
}

impl SseParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed newly received bytes in and drain every complete frame the
    /// buffer now contains. A single call can return 0, 1, or many frames
    /// (one read can complete several small frames at once).
    pub fn push(&mut self, bytes: &[u8]) -> Vec<SseFrame> {
        self.buf.extend_from_slice(bytes);
        let mut frames = Vec::new();
        while let Some(boundary) = find_blank_line(&self.buf) {
            // `boundary` is the index of the start of the blank-line
            // terminator; `rest_at` is where the next frame's bytes begin.
            let (raw_frame, rest_at) = boundary;
            let frame_bytes = self.buf[..raw_frame].to_vec();
            // Rust note: `drain` removes the consumed prefix (frame +
            // terminator) in place, leaving any partial next frame in `buf`
            // for the next `push` call.
            self.buf.drain(..rest_at);
            if let Some(frame) = parse_frame_bytes(&frame_bytes) {
                frames.push(frame);
            }
        }
        frames
    }
}

/// Find the first blank-line frame terminator (`"\n\n"` or `"\r\n\r\n"`) in
/// `buf`, returning `(frame_end, consumed_end)`: bytes before `frame_end` are
/// the frame body, and everything up to `consumed_end` (the terminator
/// itself) should be dropped from the buffer.
fn find_blank_line(buf: &[u8]) -> Option<(usize, usize)> {
    // Scan for "\n\n" first since it is the common case (our mock upstreams
    // emit bare `\n`); fall back to treating a lone "\r\n\r\n" the same way
    // so a real provider using CRLF line endings still parses.
    for i in 0..buf.len() {
        if buf[i] == b'\n' {
            if buf.get(i + 1) == Some(&b'\n') {
                return Some((i, i + 2));
            }
            if buf[..i].last() == Some(&b'\r')
                && buf.get(i + 1) == Some(&b'\r')
                && buf.get(i + 2) == Some(&b'\n')
            {
                // "...\r\n\r\n": the first '\n' is at i, preceded by '\r' at
                // i-1; frame body ends before that '\r'.
                return Some((i - 1, i + 3));
            }
        }
    }
    None
}

/// Parse one already-delimited frame's raw bytes into event/data lines.
/// Blank frames (e.g. a stray terminator with nothing before it, or a
/// comment-only frame -- a line starting with `:`) yield `None`.
fn parse_frame_bytes(frame_bytes: &[u8]) -> Option<SseFrame> {
    let text = String::from_utf8_lossy(frame_bytes);
    let mut event = None;
    let mut data_lines: Vec<&str> = Vec::new();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        if let Some(value) = line.strip_prefix("event:") {
            event = Some(value.trim_start().to_string());
        } else if let Some(value) = line.strip_prefix("data:") {
            data_lines.push(value.strip_prefix(' ').unwrap_or(value));
        }
        // Other SSE fields (`id:`, `retry:`) aren't produced by any dialect
        // we speak; ignored rather than erroring since this is a client
        // parsing someone else's wire format, not our own config surface.
    }
    if event.is_none() && data_lines.is_empty() {
        return None;
    }
    Some(SseFrame {
        event,
        data: data_lines.join("\n"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_data_only_frame() {
        let mut parser = SseParser::new();
        let frames = parser.push(b"data: hello\n\n");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].event, None);
        assert_eq!(frames[0].data, "hello");
    }

    #[test]
    fn parses_named_event_frame() {
        let mut parser = SseParser::new();
        let frames = parser.push(b"event: message_start\ndata: {\"a\":1}\n\n");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].event.as_deref(), Some("message_start"));
        assert_eq!(frames[0].data, "{\"a\":1}");
    }

    #[test]
    fn frame_split_across_multiple_pushes() {
        // The classic bug: a frame's bytes arrive in several TCP reads.
        let mut parser = SseParser::new();
        assert!(parser.push(b"event: content_block_delta\nda").is_empty());
        assert!(parser.push(b"ta: {\"delta\":{\"text\":\"hi\"").is_empty());
        let frames = parser.push(b"}}\n\n");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].event.as_deref(), Some("content_block_delta"));
        assert_eq!(frames[0].data, "{\"delta\":{\"text\":\"hi\"}}");
    }

    #[test]
    fn split_exactly_at_the_blank_line_terminator() {
        let mut parser = SseParser::new();
        assert!(parser.push(b"data: x\n").is_empty());
        let frames = parser.push(b"\n");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data, "x");
    }

    #[test]
    fn multiple_frames_in_one_push() {
        let mut parser = SseParser::new();
        let frames = parser.push(b"data: a\n\ndata: b\n\n");
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].data, "a");
        assert_eq!(frames[1].data, "b");
    }

    #[test]
    fn multi_line_data_is_joined_with_newline() {
        let mut parser = SseParser::new();
        let frames = parser.push(b"data: line1\ndata: line2\n\n");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data, "line1\nline2");
    }

    #[test]
    fn crlf_terminated_frame_parses() {
        let mut parser = SseParser::new();
        let frames = parser.push(b"data: hello\r\n\r\n");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data, "hello");
    }

    #[test]
    fn done_terminator_is_a_plain_data_frame() {
        let mut parser = SseParser::new();
        let frames = parser.push(b"data: [DONE]\n\n");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data, "[DONE]");
    }
}
