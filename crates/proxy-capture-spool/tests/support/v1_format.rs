//! Version 1 wire format. All lengths are checked before allocation.

use super::{EncryptionKey, Error, Result, SpoolConfig};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
};

pub(crate) const HEADER_BYTES: usize = 288;
pub(crate) const FRAME_OVERHEAD: usize = 41; // length, kind, sequence, nonce, AEAD tag
pub(crate) const FOOTER_PAYLOAD: usize = 48; // count, last sequence, SHA-256
pub(crate) const FOOTER_BYTES: usize = FRAME_OVERHEAD + FOOTER_PAYLOAD;
pub(crate) const DESCRIPTOR_BYTES: usize = 56; // first, last, length, SHA-256
pub(crate) const STATE_FIXED: usize = 32; // next, durable, acknowledged, count
const VERSION: u32 = 1;
const SEGMENT_MAGIC: &[u8; 8] = b"LMSPOOL1";
const STATE_MAGIC: &[u8; 8] = b"LMSTATE1";
const ID_BYTES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Descriptor {
    pub first: u64,
    pub last: u64,
    pub bytes: u64,
    pub hash: [u8; 32],
}

#[derive(Clone, Debug)]
pub(crate) struct State {
    pub next: u64,
    pub durable: u64,
    pub acknowledged: u64,
    pub segments: Vec<Descriptor>,
}

impl State {
    pub fn empty() -> Self {
        Self {
            next: 1,
            durable: 0,
            acknowledged: 0,
            segments: Vec::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(STATE_FIXED + DESCRIPTOR_BYTES * self.segments.len());
        for n in [
            self.next,
            self.durable,
            self.acknowledged,
            self.segments.len() as u64,
        ] {
            out.extend_from_slice(&n.to_le_bytes());
        }
        for segment in &self.segments {
            for n in [segment.first, segment.last, segment.bytes] {
                out.extend_from_slice(&n.to_le_bytes());
            }
            out.extend_from_slice(&segment.hash);
        }
        out
    }

    pub fn decode(bytes: &[u8], config: &SpoolConfig) -> Result<Self> {
        if bytes.len() < STATE_FIXED {
            return Err(Error::Corrupt);
        }
        let count = number(&bytes[24..32]);
        if count > config.max_segments as u64
            || bytes.len() != STATE_FIXED + count as usize * DESCRIPTOR_BYTES
        {
            return Err(Error::Corrupt);
        }
        let mut state = Self {
            next: number(&bytes[..8]),
            durable: number(&bytes[8..16]),
            acknowledged: number(&bytes[16..24]),
            segments: Vec::with_capacity(count as usize),
        };
        if state.next == 0 || state.durable >= state.next || state.acknowledged > state.durable {
            return Err(Error::Corrupt);
        }
        let mut previous = 0;
        for bytes in bytes[STATE_FIXED..].chunks_exact(DESCRIPTOR_BYTES) {
            let descriptor = Descriptor {
                first: number(&bytes[..8]),
                last: number(&bytes[8..16]),
                bytes: number(&bytes[16..24]),
                hash: bytes[24..56].try_into().unwrap(),
            };
            if descriptor.first == 0
                || descriptor.first <= previous
                || descriptor.last < descriptor.first
                || descriptor.last > state.durable
                || descriptor.last <= state.acknowledged
                || descriptor.bytes < (HEADER_BYTES + FRAME_OVERHEAD + FOOTER_BYTES) as u64
                || descriptor.bytes > config.max_segment_bytes
            {
                return Err(Error::Corrupt);
            }
            previous = descriptor.last;
            state.segments.push(descriptor);
        }
        if state.durable > state.acknowledged
            && state.segments.last().map(|s| s.last) != Some(state.durable)
        {
            return Err(Error::Corrupt);
        }
        Ok(state)
    }
}

pub(crate) fn number(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}

pub(crate) fn header(
    config: &SpoolConfig,
    key: &EncryptionKey,
    first: u64,
    state: bool,
) -> [u8; HEADER_BYTES] {
    let mut out = [0; HEADER_BYTES];
    out[..8].copy_from_slice(if state { STATE_MAGIC } else { SEGMENT_MAGIC });
    out[8..12].copy_from_slice(&VERSION.to_le_bytes());
    out[12..20].copy_from_slice(&first.to_le_bytes());
    out[20..22].copy_from_slice(&(config.node_id.len() as u16).to_le_bytes());
    out[22..24].copy_from_slice(&(key.id.len() as u16).to_le_bytes());
    out[24..24 + config.node_id.len()].copy_from_slice(config.node_id.as_bytes());
    out[152..152 + key.id.len()].copy_from_slice(key.id.as_bytes());
    out
}

pub(crate) fn read_header(
    reader: &mut impl Read,
    config: &SpoolConfig,
    state: bool,
) -> Result<([u8; HEADER_BYTES], String, u64)> {
    let mut bytes = [0; HEADER_BYTES];
    read_exact(reader, &mut bytes)?;
    if &bytes[..8] != if state { STATE_MAGIC } else { SEGMENT_MAGIC } {
        return Err(Error::Corrupt);
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    if version != VERSION {
        return Err(Error::UnknownVersion(version));
    }
    let node_len = u16::from_le_bytes(bytes[20..22].try_into().unwrap()) as usize;
    let key_len = u16::from_le_bytes(bytes[22..24].try_into().unwrap()) as usize;
    if node_len == 0
        || node_len > ID_BYTES
        || key_len == 0
        || key_len > ID_BYTES
        || bytes[24..24 + node_len] != *config.node_id.as_bytes()
        || bytes[24 + node_len..152].iter().any(|b| *b != 0)
        || bytes[152 + key_len..].iter().any(|b| *b != 0)
    {
        return Err(Error::Corrupt);
    }
    let id = std::str::from_utf8(&bytes[152..152 + key_len])
        .map_err(|_| Error::Corrupt)?
        .to_owned();
    let first = number(&bytes[12..20]);
    Ok((bytes, id, first))
}

pub(crate) fn encrypt(
    header: &[u8],
    key: &EncryptionKey,
    kind: u8,
    sequence: u64,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce = [0; 12];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| Error::Crypto)?;
    let length =
        u32::try_from(payload.len() + FRAME_OVERHEAD - 4).map_err(|_| Error::RecordTooLarge)?;
    let mut prefix = Vec::with_capacity(25);
    prefix.extend_from_slice(&length.to_le_bytes());
    prefix.push(kind);
    prefix.extend_from_slice(&sequence.to_le_bytes());
    prefix.extend_from_slice(&nonce);
    let mut aad = Vec::with_capacity(header.len() + prefix.len());
    aad.extend_from_slice(header);
    aad.extend_from_slice(&prefix);
    let mut ciphertext = payload.to_owned();
    key.key
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(&aad),
            &mut ciphertext,
        )
        .map_err(|_| Error::Crypto)?;
    prefix.extend_from_slice(&ciphertext);
    Ok(prefix)
}

pub(crate) struct Frame {
    pub kind: u8,
    pub sequence: u64,
    pub plaintext: Vec<u8>,
    pub encoded: Vec<u8>,
}

pub(crate) fn read_frame(
    reader: &mut impl Read,
    header: &[u8],
    key: &EncryptionKey,
    max_payload: usize,
    remaining: u64,
) -> Result<Frame> {
    let mut prefix = [0; 25];
    if remaining < FRAME_OVERHEAD as u64 {
        return Err(Error::Corrupt);
    }
    read_exact(reader, &mut prefix[..4])?;
    let length = u32::from_le_bytes(prefix[..4].try_into().unwrap()) as u64;
    let total = length + 4;
    if total < FRAME_OVERHEAD as u64
        || total > remaining
        || total > (max_payload + FRAME_OVERHEAD) as u64
    {
        return Err(Error::Corrupt);
    }
    read_exact(reader, &mut prefix[4..])?;
    let mut ciphertext = vec![0; total as usize - prefix.len()];
    read_exact(reader, &mut ciphertext)?;
    let mut encoded = prefix.to_vec();
    encoded.extend_from_slice(&ciphertext);
    let mut aad = header.to_vec();
    aad.extend_from_slice(&prefix);
    let plaintext = key
        .key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(prefix[13..25].try_into().unwrap()),
            aead::Aad::from(&aad),
            &mut ciphertext,
        )
        .map_err(|_| Error::Corrupt)?
        .to_owned();
    Ok(Frame {
        kind: prefix[4],
        sequence: number(&prefix[5..13]),
        plaintext,
        encoded,
    })
}

pub(crate) fn read_exact(reader: &mut impl Read, bytes: &mut [u8]) -> Result<()> {
    reader.read_exact(bytes).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::Corrupt
        } else {
            Error::Io(error)
        }
    })
}

pub(crate) fn find_key<'a>(
    keys: &'a BTreeMap<String, EncryptionKey>,
    id: &str,
) -> Result<&'a EncryptionKey> {
    keys.get(id).ok_or(Error::MissingKey)
}

pub(crate) fn write_state(
    writer: &mut impl Write,
    config: &SpoolConfig,
    key: &EncryptionKey,
    state: &State,
) -> Result<()> {
    let header = header(config, key, 0, true);
    let frame = encrypt(&header, key, 3, 0, &state.encode())?;
    writer.write_all(&header)?;
    writer.write_all(&frame)?;
    Ok(())
}
