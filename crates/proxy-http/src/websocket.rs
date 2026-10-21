//! RFC 6455 framing, as much of it as an observer of a WebSocket tunnel
//! needs: where each frame starts and ends, its opcode and flags, and its
//! unmasked payload. The tunnel uses it to place a Close frame between two
//! frames on drain; the usage filter uses it to read realtime event frames.
//! It never re-frames or rewrites the bytes it reads.

/// RFC 6455 section 5.2 opcodes this crate acts on.
pub mod opcode {
    pub const CONTINUATION: u8 = 0x0;
    pub const TEXT: u8 = 0x1;
    pub const BINARY: u8 = 0x2;
    pub const CLOSE: u8 = 0x8;
}

/// RFC 6455 section 7.4.1: "going away", the code a server sends when it is
/// shutting down.
pub const CLOSE_GOING_AWAY: u16 = 1001;

/// One unmasked server-to-client Close frame with `code` and a short reason.
/// Control frames carry at most 125 payload bytes (section 5.5), so the
/// reason is truncated to fit.
pub fn close_frame(code: u16, reason: &str) -> Vec<u8> {
    let reason = &reason.as_bytes()[..reason.len().min(123)];
    let mut frame = Vec::with_capacity(4 + reason.len());
    frame.push(0x80 | opcode::CLOSE);
    // Rust note: `reason.len()` is at most 123 here, so the `as u8` cannot
    // truncate.
    frame.push((2 + reason.len()) as u8);
    frame.extend_from_slice(&code.to_be_bytes());
    frame.extend_from_slice(reason);
    frame
}

/// A frame's header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub fin: bool,
    /// RSV1, which `permessage-deflate` sets on a compressed message's first
    /// frame (RFC 7692 section 6).
    pub rsv1: bool,
    pub opcode: u8,
    pub payload_len: u64,
}

/// One piece of a frame's payload, unmasked, delivered as the bytes arrive.
/// A frame with an empty payload is delivered once, with `last` set.
pub struct Piece<'a> {
    pub header: FrameHeader,
    pub payload: &'a [u8],
    /// This piece ends the frame.
    pub last: bool,
}

/// The longest header: 2 bytes, an 8-byte extended length, a 4-byte mask.
const MAX_HEADER: usize = 14;

/// Incremental frame decoder for one direction of a WebSocket connection.
/// Feed it the bytes in order, in chunks of any size.
#[derive(Default)]
pub struct FrameDecoder {
    header: [u8; MAX_HEADER],
    header_len: usize,
    current: Option<Current>,
}

#[derive(Clone, Copy)]
struct Current {
    header: FrameHeader,
    mask: Option<[u8; 4]>,
    /// Payload bytes of this frame already delivered.
    offset: u64,
}

impl FrameDecoder {
    /// Between two frames: no header byte or payload byte of a frame is
    /// pending.
    pub fn at_boundary(&self) -> bool {
        self.header_len == 0 && self.current.is_none()
    }

    /// Consume all of `data`, calling `sink` with each payload piece.
    pub fn feed(&mut self, data: &[u8], sink: &mut dyn FnMut(Piece<'_>)) {
        let mut rest = data;
        while !rest.is_empty() {
            let used = self.step(rest, sink);
            rest = &rest[used..];
        }
    }

    /// Consume `data` only up to the end of the frame in progress, and
    /// return how many bytes that took: 0 when already [`Self::at_boundary`],
    /// `data.len()` when the frame goes on past `data`.
    pub fn finish_frame(&mut self, data: &[u8]) -> usize {
        let mut used = 0;
        while used < data.len() && !self.at_boundary() {
            used += self.step(&data[used..], &mut |_| {});
        }
        used
    }

    /// Advance by at most one header or one payload piece; return the bytes
    /// used (always at least one, since `data` is non-empty).
    fn step(&mut self, data: &[u8], sink: &mut dyn FnMut(Piece<'_>)) -> usize {
        let Some(mut current) = self.current else {
            return self.read_header(data, sink);
        };
        let remaining = current.header.payload_len - current.offset;
        // Rust note: `min` against a `usize` length first, so the cast back
        // from `u64` can never truncate.
        let take = (data.len() as u64).min(remaining) as usize;
        let last = take as u64 == remaining;
        let chunk = &data[..take];
        match current.mask {
            None => sink(Piece {
                header: current.header,
                payload: chunk,
                last,
            }),
            Some(mask) => {
                let unmasked: Vec<u8> = chunk
                    .iter()
                    .enumerate()
                    .map(|(i, b)| b ^ mask[((current.offset + i as u64) % 4) as usize])
                    .collect();
                sink(Piece {
                    header: current.header,
                    payload: &unmasked,
                    last,
                });
            }
        }
        current.offset += take as u64;
        self.current = (!last).then_some(current);
        take
    }

    fn read_header(&mut self, data: &[u8], sink: &mut dyn FnMut(Piece<'_>)) -> usize {
        let mut used = 0;
        loop {
            let need = header_len(&self.header[..self.header_len]);
            if self.header_len == need {
                break;
            }
            if used == data.len() {
                return used;
            }
            self.header[self.header_len] = data[used];
            self.header_len += 1;
            used += 1;
        }
        let h = &self.header[..self.header_len];
        let short = u64::from(h[1] & 0x7f);
        let (payload_len, mask_at) = match short {
            126 => (u64::from(u16::from_be_bytes([h[2], h[3]])), 4),
            127 => (
                u64::from_be_bytes([h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9]]),
                10,
            ),
            n => (n, 2),
        };
        let mask = (h[1] & 0x80 != 0)
            .then(|| [h[mask_at], h[mask_at + 1], h[mask_at + 2], h[mask_at + 3]]);
        let header = FrameHeader {
            fin: h[0] & 0x80 != 0,
            rsv1: h[0] & 0x40 != 0,
            opcode: h[0] & 0x0f,
            payload_len,
        };
        self.header_len = 0;
        if payload_len == 0 {
            sink(Piece {
                header,
                payload: &[],
                last: true,
            });
        } else {
            self.current = Some(Current {
                header,
                mask,
                offset: 0,
            });
        }
        used.max(1)
    }
}

/// How long the header that starts with `partial` is, once enough of it is
/// known to say; until then, one byte more than `partial`.
fn header_len(partial: &[u8]) -> usize {
    if partial.len() < 2 {
        return partial.len() + 1;
    }
    let mask = if partial[1] & 0x80 != 0 { 4 } else { 0 };
    let extended = match partial[1] & 0x7f {
        126 => 2,
        127 => 8,
        _ => 0,
    };
    2 + extended + mask
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(fin: bool, op: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut out = vec![if fin { 0x80 } else { 0 } | op];
        let mask_bit = if mask.is_some() { 0x80 } else { 0 };
        match payload.len() {
            n if n < 126 => out.push(mask_bit | n as u8),
            n if n <= 0xffff => {
                out.push(mask_bit | 126);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                out.push(mask_bit | 127);
                out.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        match mask {
            None => out.extend_from_slice(payload),
            Some(m) => {
                out.extend_from_slice(&m);
                out.extend(payload.iter().enumerate().map(|(i, b)| b ^ m[i % 4]));
            }
        }
        out
    }

    /// Feed `wire` one byte at a time and in one piece; both must yield the
    /// same frames, since TCP may split a frame anywhere.
    fn decode(wire: &[u8]) -> Vec<(FrameHeader, Vec<u8>)> {
        let mut whole = Vec::new();
        for chunking in [1usize, wire.len().max(1)] {
            let mut decoder = FrameDecoder::default();
            let mut frames: Vec<(FrameHeader, Vec<u8>)> = Vec::new();
            let mut open: Vec<u8> = Vec::new();
            for chunk in wire.chunks(chunking) {
                decoder.feed(chunk, &mut |piece| {
                    open.extend_from_slice(piece.payload);
                    if piece.last {
                        frames.push((piece.header, std::mem::take(&mut open)));
                    }
                });
            }
            assert!(decoder.at_boundary());
            if chunking == 1 {
                whole = frames;
            } else {
                assert_eq!(frames, whole, "chunking must not change the frames");
            }
        }
        whole
    }

    #[test]
    fn decodes_short_extended_masked_and_empty_frames_split_anywhere() {
        let big = vec![b'x'; 70_000];
        let mid = vec![b'y'; 300];
        let mut wire = frame(true, opcode::TEXT, b"hello", None);
        wire.extend(frame(false, opcode::TEXT, &mid, None));
        wire.extend(frame(true, opcode::CONTINUATION, &big, None));
        wire.extend(frame(true, opcode::TEXT, b"masked", Some([1, 2, 3, 4])));
        wire.extend(frame(true, opcode::BINARY, b"", None));
        let frames = decode(&wire);
        let summary: Vec<(bool, u8, Vec<u8>)> = frames
            .into_iter()
            .map(|(h, p)| (h.fin, h.opcode, p))
            .collect();
        assert_eq!(
            summary,
            vec![
                (true, opcode::TEXT, b"hello".to_vec()),
                (false, opcode::TEXT, mid),
                (true, opcode::CONTINUATION, big),
                (true, opcode::TEXT, b"masked".to_vec()),
                (true, opcode::BINARY, Vec::new()),
            ]
        );
    }

    #[test]
    fn finish_frame_stops_exactly_at_the_end_of_the_frame_in_progress() {
        let mut wire = frame(true, opcode::TEXT, b"abcdef", None);
        let first_len = wire.len();
        wire.extend(frame(true, opcode::TEXT, b"next", None));
        let mut decoder = FrameDecoder::default();
        assert_eq!(decoder.finish_frame(&wire), 0, "already between frames");
        decoder.feed(&wire[..3], &mut |_| {});
        assert!(!decoder.at_boundary());
        let used = decoder.finish_frame(&wire[3..]);
        assert_eq!(3 + used, first_len);
        assert!(decoder.at_boundary());
    }

    #[test]
    fn close_frame_is_an_unmasked_final_close_with_the_code_first() {
        let wire = close_frame(CLOSE_GOING_AWAY, "draining");
        let frames = decode(&wire);
        assert_eq!(frames.len(), 1);
        let (header, payload) = &frames[0];
        assert!(header.fin);
        assert_eq!(header.opcode, opcode::CLOSE);
        assert_eq!(&payload[..2], &1001u16.to_be_bytes());
        assert_eq!(&payload[2..], b"draining");
        assert!(close_frame(1001, &"r".repeat(400)).len() <= 2 + 125);
    }
}
