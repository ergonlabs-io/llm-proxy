//! Application envelopes, independent of redb's page format.
use crate::{EncryptionKey, Error, Result};
use ring::{
    aead, digest,
    rand::{SecureRandom, SystemRandom},
};
use std::collections::BTreeMap;

pub(crate) const VERSION: u32 = 3;
const MAGIC: &[u8; 8] = b"LMREDB03";
const PREFIX_BYTES: usize = 14;
pub(crate) const MAX_ENVELOPE_OVERHEAD: usize = PREFIX_BYTES + 128 + 12 + 16;
pub(crate) const MAX_STATE_BYTES: usize = 8 + 4 + 2 + 128 + 32 + 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct State {
    pub next: u64,
    pub durable: u64,
    pub acknowledged: u64,
    pub count: u64,
    pub digest: [u8; 32],
}
impl State {
    pub fn empty() -> Self {
        Self {
            next: 1,
            durable: 0,
            acknowledged: 0,
            count: 0,
            digest: inventory_hash()
                .finish()
                .as_ref()
                .try_into()
                .expect("SHA-256 digest is 32 bytes"),
        }
    }
    pub fn encode(&self, node: &str) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MAX_STATE_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&(node.len() as u16).to_le_bytes());
        bytes.extend_from_slice(node.as_bytes());
        for n in [self.next, self.durable, self.acknowledged, self.count] {
            bytes.extend_from_slice(&n.to_le_bytes());
        }
        bytes.extend_from_slice(&self.digest);
        bytes
    }
    pub fn decode(bytes: &[u8], node: &str) -> Result<Self> {
        if bytes.len() < 14 || &bytes[..8] != MAGIC {
            return Err(Error::Corrupt);
        }
        let version = u32::from_le_bytes(bytes[8..12].try_into().expect("4-byte range"));
        if version != VERSION {
            return Err(Error::UnknownVersion(version));
        }
        let length = u16::from_le_bytes(bytes[12..14].try_into().expect("2-byte range")) as usize;
        if length == 0 || length > 128 || bytes.len() != 14 + length + 64 {
            return Err(Error::Corrupt);
        }
        if &bytes[14..14 + length] != node.as_bytes() {
            return Err(Error::Corrupt);
        }
        let rest = &bytes[14 + length..];
        let number =
            |start| u64::from_le_bytes(rest[start..start + 8].try_into().expect("8-byte range"));
        let state = Self {
            next: number(0),
            durable: number(8),
            acknowledged: number(16),
            count: number(24),
            digest: rest[32..]
                .try_into()
                .expect("length check leaves 64 - 32 = 32 digest bytes"),
        };
        if state.next == 0
            || state.durable >= state.next
            || state.acknowledged > state.durable
            || state.count > state.durable - state.acknowledged
            || (state.count == 0) != (state.durable == state.acknowledged)
        {
            return Err(Error::Corrupt);
        }
        Ok(state)
    }
}

pub(crate) fn inventory_hash() -> digest::Context {
    let mut hash = digest::Context::new(&digest::SHA256);
    hash.update(b"llmproxy-capture-redb-v3-inventory");
    hash
}
pub(crate) fn hash_record(hash: &mut digest::Context, sequence: u64, envelope: &[u8]) {
    hash.update(&sequence.to_le_bytes());
    hash.update(&(envelope.len() as u64).to_le_bytes());
    hash.update(envelope);
}
fn aad(node: &str, kind: u8, sequence: u64, prefix: &[u8]) -> Vec<u8> {
    let mut bytes = b"llmproxy-capture-redb-v3-envelope".to_vec();
    bytes.extend_from_slice(&(node.len() as u16).to_le_bytes());
    bytes.extend_from_slice(node.as_bytes());
    bytes.push(kind);
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(prefix);
    bytes
}
pub(crate) fn encrypt(
    key: &EncryptionKey,
    node: &str,
    kind: u8,
    sequence: u64,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce = [0; 12];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| Error::Crypto)?;
    let mut bytes = Vec::with_capacity(MAX_ENVELOPE_OVERHEAD + payload.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.extend_from_slice(&(key.id.len() as u16).to_le_bytes());
    bytes.extend_from_slice(key.id.as_bytes());
    bytes.extend_from_slice(&nonce);
    let associated = aad(node, kind, sequence, &bytes);
    let mut ciphertext = payload.to_vec();
    key.key
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(associated),
            &mut ciphertext,
        )
        .map_err(|_| Error::Crypto)?;
    bytes.extend_from_slice(&ciphertext);
    Ok(bytes)
}

pub(crate) fn key_id(envelope: &[u8], bound: usize) -> Result<&str> {
    if envelope.len() < PREFIX_BYTES + 1 + 12 + 16
        || envelope.len()
            > bound
                .checked_add(MAX_ENVELOPE_OVERHEAD)
                .ok_or(Error::Corrupt)?
        || &envelope[..8] != MAGIC
    {
        return Err(Error::Corrupt);
    }
    let version = u32::from_le_bytes(envelope[8..12].try_into().expect("4-byte range"));
    if version != VERSION {
        return Err(Error::UnknownVersion(version));
    }
    let length = u16::from_le_bytes(envelope[12..14].try_into().expect("2-byte range")) as usize;
    let overhead = PREFIX_BYTES + length + 12 + 16;
    if length == 0 || length > 128 || envelope.len() < overhead || envelope.len() - overhead > bound
    {
        return Err(Error::Corrupt);
    }
    std::str::from_utf8(&envelope[PREFIX_BYTES..PREFIX_BYTES + length]).map_err(|_| Error::Corrupt)
}

pub(crate) fn decrypt(
    keys: &BTreeMap<String, EncryptionKey>,
    node: &str,
    kind: u8,
    sequence: u64,
    envelope: &[u8],
    bound: usize,
) -> Result<Vec<u8>> {
    let id = key_id(envelope, bound)?;
    let key = keys.get(id).ok_or(Error::MissingKey)?;
    let nonce_start = PREFIX_BYTES + id.len();
    let prefix_end = nonce_start + 12;
    let nonce = envelope[nonce_start..prefix_end]
        .try_into()
        .expect("12-byte range");
    let mut bytes = envelope[prefix_end..].to_vec();
    let length = key
        .key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad(node, kind, sequence, &envelope[..prefix_end])),
            &mut bytes,
        )
        .map_err(|_| Error::Corrupt)?
        .len();
    bytes.truncate(length);
    Ok(bytes)
}
