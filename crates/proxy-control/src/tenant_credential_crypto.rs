//! At-rest protection for per-tenant provider credentials.
//!
//! The control store persists each tenant's provider API keys so a restart can
//! dial providers without re-provisioning. That makes the store a credential
//! store, and a copied database must not disclose provider keys. Each secret is
//! therefore sealed with AES-256-GCM under a key-encryption key (KEK) that
//! lives outside the store, so the store only ever holds ciphertext.
//!
//! The additional authenticated data (AAD) binds every ciphertext to its
//! tenant, provider, and KEK id. A row copied into another tenant's row (or
//! re-labelled to another provider or key id) fails to decrypt instead of
//! silently handing the wrong tenant's credential to the wrong provider. The
//! u32 length prefixes in [`associated_data`] additionally pin field
//! boundaries, so `("a|b", "c")` and `("a", "b|c")` cannot collide.
//!
//! [`fingerprint`] and [`last4`] exist so callers can index, log, and display
//! credentials by a stable identifier: the fingerprint is a domain-separated
//! HMAC under a key derived from the auth `hmac_secret`, never that secret
//! itself, and `last4` is what a UI shows a
//! human. Neither ever requires the plaintext to leave [`TenantSecret`].

use ring::{
    aead, hmac,
    rand::{SecureRandom, SystemRandom},
};
use std::{fmt, path::Path};
use zeroize::Zeroizing;

const AAD_LABEL: &[u8] = b"llmproxy-tenant-credential:v1";
const FINGERPRINT_LABEL: &[u8] = b"llmproxy-tenant-credential-fingerprint:v1";
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;

/// The plaintext type is shared with the router, which lives below this crate
/// (ADR-0007 decision 3), so it is defined in `proxy-http` and re-exported here.
pub use proxy_credentials::TenantSecret;

/// Errors from KEK loading and key-ring construction.
///
/// No variant ever renders key bytes; the id in [`KekError::DuplicateId`] is
/// stored in plaintext in every sealed row anyway.
#[derive(Debug, thiserror::Error)]
pub enum KekError {
    #[error("credential key id must not be empty")]
    EmptyId,
    #[error("credential key file must be a regular file")]
    NotARegularFile,
    #[error("credential key file must not be group- or world-accessible")]
    InsecurePermissions,
    #[error("credential key file must contain exactly {KEY_BYTES} bytes")]
    BadKeyLength,
    #[error("credential key id {0:?} appears more than once in the key ring")]
    DuplicateId(String),
    #[error("credential key file I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors from [`seal`] and [`open`]. None ever renders key or plaintext
/// material: `Decrypt` in particular says nothing about which byte or why.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("cryptographic randomness source failed")]
    Randomness,
    #[error("no key in the ring has id {0:?}")]
    UnknownKeyId(String),
    #[error("credential decryption failed")]
    Decrypt,
    #[error("credential encryption failed")]
    Seal,
}

/// A key-encryption key: AES-256-GCM key material plus its (non-secret) id,
/// which is what a [`SealedCredential`] names so [`open`] can pick a key.
///
/// The bytes are held in [`Zeroizing`] and wiped on drop; `Debug` renders only
/// the id. `load` refuses key files that are not private regular files or that
/// are not exactly 32 bytes, so a world-readable or truncated key file fails
/// closed rather than weakening every credential it seals.
pub struct CredentialKek {
    id: String,
    key: Zeroizing<[u8; KEY_BYTES]>,
}

impl CredentialKek {
    pub fn load(id: &str, path: &Path) -> Result<Self, KekError> {
        use std::io::Read;
        if id.is_empty() {
            return Err(KekError::EmptyId);
        }
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_file() {
            return Err(KekError::NotARegularFile);
        }
        // Any group or other permission bit means another principal could
        // have read or replaced the key material.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(KekError::InsecurePermissions);
            }
        }
        // Every buffer that holds key bytes is zeroized, including on the
        // wrong-length path, and the bytes are copied straight into the
        // zeroizing array rather than through a stack temporary.
        let mut bytes = Zeroizing::new(Vec::with_capacity(KEY_BYTES + 1));
        std::fs::File::open(path)?
            .take((KEY_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() != KEY_BYTES {
            return Err(KekError::BadKeyLength);
        }
        let mut key = Zeroizing::new([0u8; KEY_BYTES]);
        key.copy_from_slice(&bytes);
        Ok(Self {
            id: id.to_string(),
            key,
        })
    }

    pub fn from_bytes(id: &str, key_bytes: [u8; KEY_BYTES]) -> Result<Self, KekError> {
        if id.is_empty() {
            return Err(KekError::EmptyId);
        }
        Ok(Self {
            id: id.to_string(),
            key: Zeroizing::new(key_bytes),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }
}

impl fmt::Debug for CredentialKek {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialKek")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// The set of KEKs a process seals and opens with: exactly one `current` key
/// that every new seal uses, plus retired `previous` keys kept only so
/// already-sealed rows still open. Ids must be unique so [`open`]'s lookup by
/// id is unambiguous -- a duplicate id would silently pick one key over the
/// other and fail decrypts that should succeed.
pub struct KeyRing {
    current: CredentialKek,
    previous: Vec<CredentialKek>,
}

impl KeyRing {
    pub fn new(current: CredentialKek, previous: Vec<CredentialKek>) -> Result<Self, KekError> {
        let mut seen = vec![current.id.as_str()];
        for key in &previous {
            if seen.contains(&key.id.as_str()) {
                return Err(KekError::DuplicateId(key.id.clone()));
            }
            seen.push(key.id.as_str());
        }
        Ok(Self { current, previous })
    }

    /// A SHA-256 over every key's id and bytes, in ring order. A config
    /// reload compares it with the running ring's, because the ring is fixed
    /// at startup and a rotated key file at an unchanged path must still be
    /// seen as a change. One-way, so holding it keeps no second copy of the
    /// keys.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut context = ring::digest::Context::new(&ring::digest::SHA256);
        for key in std::iter::once(&self.current).chain(&self.previous) {
            context.update(&(key.id.len() as u64).to_be_bytes());
            context.update(key.id.as_bytes());
            context.update(key.key.as_slice());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(context.finish().as_ref());
        out
    }

    fn lookup(&self, id: &str) -> Option<&CredentialKek> {
        if self.current.id == id {
            Some(&self.current)
        } else {
            self.previous.iter().find(|key| key.id == id)
        }
    }
}

impl fmt::Debug for KeyRing {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyRing")
            .field("current", &self.current)
            .field("previous_count", &self.previous.len())
            .finish_non_exhaustive()
    }
}

/// A sealed credential as the control store persists it: the non-secret key id
/// (so a reader knows which KEK can open it), the nonce, and the AES-256-GCM
/// ciphertext including its tag. Safe to `Serialize`: none of these fields is
/// secret material.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SealedCredential {
    pub key_id: String,
    pub nonce: [u8; NONCE_BYTES],
    pub ciphertext: Vec<u8>,
}

/// Seals `secret` under `ring`'s `current` key with a fresh random nonce.
///
/// Always encrypts with `current` (never a retired key) so rotation moves new
/// rows onto the new key the moment the ring is swapped.
pub fn seal(
    ring: &KeyRing,
    tenant: &str,
    provider: &str,
    secret: &TenantSecret,
) -> Result<SealedCredential, CryptoError> {
    let key = &ring.current;
    let mut nonce = [0; NONCE_BYTES];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| CryptoError::Randomness)?;
    let aad = associated_data(tenant, provider, &key.id);
    let less_safe = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, &*key.key).map_err(|_| CryptoError::Seal)?,
    );
    // Sized for the tag up front so sealing never reallocates and frees a
    // buffer that still holds plaintext; zeroized on every exit path.
    let plaintext = secret.expose().as_bytes();
    let mut buffer = Zeroizing::new(Vec::with_capacity(
        plaintext.len() + aead::AES_256_GCM.tag_len(),
    ));
    buffer.extend_from_slice(plaintext);
    less_safe
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad),
            &mut *buffer,
        )
        .map_err(|_| CryptoError::Seal)?;
    Ok(SealedCredential {
        key_id: key.id.clone(),
        nonce,
        ciphertext: buffer.to_vec(),
    })
}

/// Opens `sealed` with whichever ring key (current or previous) matches
/// `sealed.key_id`.
///
/// [`CryptoError::UnknownKeyId`] means the ring has since dropped the key the
/// row was sealed under; [`CryptoError::Decrypt`] covers both a wrong AEAD key
/// and any tenant/provider/key-id mismatch, deliberately indistinguishable so
/// the error says nothing about why.
pub fn open(
    ring: &KeyRing,
    tenant: &str,
    provider: &str,
    sealed: &SealedCredential,
) -> Result<TenantSecret, CryptoError> {
    let key = ring
        .lookup(&sealed.key_id)
        .ok_or_else(|| CryptoError::UnknownKeyId(sealed.key_id.clone()))?;
    let aad = associated_data(tenant, provider, &sealed.key_id);
    let less_safe = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, &*key.key).map_err(|_| CryptoError::Decrypt)?,
    );
    // Holds plaintext after `open_in_place`, so it is zeroized on drop.
    let mut bytes = Zeroizing::new(sealed.ciphertext.clone());
    let plaintext_len = less_safe
        .open_in_place(
            aead::Nonce::assume_unique_for_key(sealed.nonce),
            aead::Aad::from(aad),
            &mut bytes,
        )
        .map_err(|_| CryptoError::Decrypt)?
        .len();
    // A tag match means this came from `seal`, which only ever seals UTF-8, so
    // this cannot fail; mapped to `Decrypt` rather than a variant that could
    // never be observed. `from_utf8` borrows, so no error value carries the
    // plaintext out of the zeroizing buffer.
    let text = std::str::from_utf8(&bytes[..plaintext_len]).map_err(|_| CryptoError::Decrypt)?;
    Ok(TenantSecret::new(text.to_owned()))
}

/// A domain-separated, non-reversible identifier for a secret, for indexing
/// and equality checks on stored credentials.
///
/// The HMAC master key first derives a sub-key over a fixed label, then that
/// sub-key HMACs the plaintext. This is domain separation: the auth
/// `hmac_secret` also digests virtual keys, and using it directly here would
/// reuse one key for two purposes, so a value computed for one could be
/// presented as the other. Output is the first 16 lowercase hex characters.
pub fn fingerprint(hmac_secret: &[u8], secret: &TenantSecret) -> String {
    let sub_key = hmac::Key::new(hmac::HMAC_SHA256, hmac_secret);
    let derived = hmac::sign(&sub_key, FINGERPRINT_LABEL);
    let fingerprint_key = hmac::Key::new(hmac::HMAC_SHA256, derived.as_ref());
    let tag = hmac::sign(&fingerprint_key, secret.expose().as_bytes());
    hex_lower(&tag.as_ref()[..8])
}

/// The last 4 Unicode scalar values of the secret (fewer if shorter) -- what a
/// UI shows a human to tell two credentials apart. Operates on chars, not
/// bytes, so it never splits a multibyte character.
pub fn last4(secret: &TenantSecret) -> String {
    let text = secret.expose();
    match text.char_indices().rev().nth(3) {
        Some((start, _)) => text[start..].to_string(),
        None => text.to_string(),
    }
}

/// The AAD binding a ciphertext to its row: a fixed label, then tenant,
/// provider, and key id, each prefixed with a u32 big-endian length. The
/// length prefixes pin field boundaries so `("a|b", "c")` and `("a", "b|c")`
/// cannot produce the same AAD.
fn associated_data(tenant: &str, provider: &str, key_id: &str) -> Vec<u8> {
    let mut bytes = AAD_LABEL.to_vec();
    for field in [tenant, provider, key_id] {
        bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
        bytes.extend_from_slice(field.as_bytes());
    }
    bytes
}

/// Lowercase hex encoder. Hand-rolled because the `hex` crate is not otherwise
/// in this workspace's tree, and a nibble table is smaller than a new
/// dependency.
fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Distinctive so a Debug/Display regression renders something the
    /// assertions can actually see.
    const PLAINTEXT: &str = "sk-or-v1-SENTINEL";
    /// ASCII on purpose: any hex or verbatim rendering of the key bytes
    /// contains these substrings.
    const KEY_A: [u8; KEY_BYTES] = *b"0123456789abcdef0123456789abcdef";
    const KEY_B: [u8; KEY_BYTES] = *b"fedcba9876543210fedcba9876543210";

    fn kek(id: &str, bytes: [u8; KEY_BYTES]) -> CredentialKek {
        CredentialKek::from_bytes(id, bytes).unwrap()
    }

    fn ring(current_id: &str, current: [u8; KEY_BYTES]) -> KeyRing {
        KeyRing::new(kek(current_id, current), vec![]).unwrap()
    }

    fn secret() -> TenantSecret {
        TenantSecret::new(PLAINTEXT.to_string())
    }

    #[test]
    fn fingerprint_changes_with_a_key_or_its_id() {
        let base = ring("k1", KEY_A).fingerprint();
        assert_eq!(base, ring("k1", KEY_A).fingerprint());
        assert_ne!(base, ring("k1", KEY_B).fingerprint());
        assert_ne!(base, ring("k2", KEY_A).fingerprint());
        let with_previous = KeyRing::new(kek("k1", KEY_A), vec![kek("k0", KEY_B)]).unwrap();
        assert_ne!(base, with_previous.fingerprint());
    }

    #[test]
    fn seal_open_round_trip() {
        let ring = ring("k1", KEY_A);
        let sealed = seal(&ring, "t1", "anthropic", &secret()).unwrap();
        assert_eq!(sealed.key_id, "k1");
        // Ciphertext is exactly plaintext plus the 16-byte GCM tag, and does
        // not carry the plaintext anywhere inside it.
        assert_eq!(sealed.ciphertext.len(), PLAINTEXT.len() + 16);
        assert!(!sealed
            .ciphertext
            .windows(PLAINTEXT.len())
            .any(|w| w == PLAINTEXT.as_bytes()));
        let opened = open(&ring, "t1", "anthropic", &sealed).unwrap();
        assert_eq!(opened.expose(), PLAINTEXT);
    }

    #[test]
    fn open_fails_for_a_different_tenant() {
        let ring = ring("k1", KEY_A);
        let sealed = seal(&ring, "t1", "anthropic", &secret()).unwrap();
        assert!(matches!(
            open(&ring, "t2", "anthropic", &sealed),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn open_fails_for_a_different_provider() {
        let ring = ring("k1", KEY_A);
        let sealed = seal(&ring, "t1", "anthropic", &secret()).unwrap();
        assert!(matches!(
            open(&ring, "t1", "openai", &sealed),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn aad_length_prefixes_pin_field_boundaries() {
        // Without length prefixes, ("a|b", "c") and ("a", "b|c") would build
        // the same AAD and cross-open.
        let ring = ring("k1", KEY_A);
        let sealed = seal(&ring, "a|b", "c", &secret()).unwrap();
        assert!(matches!(
            open(&ring, "a", "b|c", &sealed),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let ring = ring("k1", KEY_A);
        let mut sealed = seal(&ring, "t1", "anthropic", &secret()).unwrap();
        sealed.ciphertext[0] ^= 0x01;
        assert!(matches!(
            open(&ring, "t1", "anthropic", &sealed),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn tampered_key_id_to_another_known_key_fails() {
        let ring = KeyRing::new(kek("k1", KEY_A), vec![kek("k2", KEY_B)]).unwrap();
        let mut sealed = seal(&ring, "t1", "anthropic", &secret()).unwrap();
        sealed.key_id = "k2".to_string();
        // `key_id` is in the AAD, and `k2` is a real ring key, so only the
        // binding -- not key availability -- rejects this.
        assert!(matches!(
            open(&ring, "t1", "anthropic", &sealed),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn unknown_key_id_reports_unknown_key_id() {
        let ring = ring("k1", KEY_A);
        let mut sealed = seal(&ring, "t1", "anthropic", &secret()).unwrap();
        sealed.key_id = "k-gone".to_string();
        assert!(matches!(
            open(&ring, "t1", "anthropic", &sealed),
            Err(CryptoError::UnknownKeyId(id)) if id == "k-gone"
        ));
    }

    #[test]
    fn rotation_opens_old_rows_and_reseals_under_the_new_key() {
        let ring_a = ring("k1", KEY_A);
        let sealed = seal(&ring_a, "t1", "anthropic", &secret()).unwrap();
        assert_eq!(sealed.key_id, "k1");

        let ring_b = KeyRing::new(kek("k2", KEY_B), vec![kek("k1", KEY_A)]).unwrap();
        let opened = open(&ring_b, "t1", "anthropic", &sealed).unwrap();
        assert_eq!(opened.expose(), PLAINTEXT);

        let resealed = seal(&ring_b, "t1", "anthropic", &secret()).unwrap();
        assert_eq!(resealed.key_id, "k2");
        assert_ne!(resealed.nonce, sealed.nonce);
    }

    #[test]
    fn two_seals_of_the_same_secret_use_fresh_nonce_and_ciphertext() {
        let ring = ring("k1", KEY_A);
        let first = seal(&ring, "t1", "anthropic", &secret()).unwrap();
        let second = seal(&ring, "t1", "anthropic", &secret()).unwrap();
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
        assert_eq!(
            open(&ring, "t1", "anthropic", &first).unwrap().expose(),
            PLAINTEXT
        );
        assert_eq!(
            open(&ring, "t1", "anthropic", &second).unwrap().expose(),
            PLAINTEXT
        );
    }

    #[test]
    fn debug_and_display_never_render_secret_material() {
        let secret = secret();
        assert_eq!(format!("{secret:?}"), "<redacted>");
        assert_eq!(format!("{secret}"), "<redacted>");

        let kek_a = kek("k1", KEY_A);
        let kek_debug = format!("{kek_a:?}");
        assert!(kek_debug.contains("k1"));
        assert!(!kek_debug.contains(PLAINTEXT));
        assert!(!kek_debug.contains("0123456789abcdef"));

        let ring = KeyRing::new(kek_a, vec![kek("k2", KEY_B)]).unwrap();
        let ring_debug = format!("{ring:?}");
        assert!(ring_debug.contains("k1"));
        assert!(!ring_debug.contains(PLAINTEXT));
        assert!(!ring_debug.contains("0123456789abcdef"));
        assert!(!ring_debug.contains("fedcba9876543210"));
    }

    /// A fresh directory under the system temp dir. This crate keeps
    /// `tempfile` out of its dev-dependencies; the name is unique per process
    /// and call so parallel tests never share a file.
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "llmproxy-kek-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_key_file(dir: &Path, name: &str, bytes: &[u8], mode: u32) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
        path
    }

    #[test]
    fn kek_load_accepts_a_private_32_byte_file() {
        let dir = temp_dir("t");
        let path = write_key_file(&dir, "kek", &KEY_A, 0o600);
        assert_eq!(CredentialKek::load("k1", &path).unwrap().id(), "k1");
    }

    #[cfg(unix)]
    #[test]
    fn kek_load_rejects_group_or_other_bits() {
        let dir = temp_dir("t");
        let path = write_key_file(&dir, "kek", &KEY_A, 0o644);
        assert!(matches!(
            CredentialKek::load("k1", &path),
            Err(KekError::InsecurePermissions)
        ));
    }

    #[test]
    fn kek_load_rejects_wrong_lengths() {
        let dir = temp_dir("t");
        for (name, len) in [("short", KEY_BYTES - 1), ("long", KEY_BYTES + 1)] {
            let key_bytes = vec![b'x'; len];
            let path = write_key_file(&dir, name, &key_bytes, 0o600);
            assert!(matches!(
                CredentialKek::load("k1", &path),
                Err(KekError::BadKeyLength)
            ));
        }
    }

    #[test]
    fn kek_rejects_an_empty_id() {
        let dir = temp_dir("t");
        let path = write_key_file(&dir, "kek", &KEY_A, 0o600);
        assert!(matches!(
            CredentialKek::from_bytes("", KEY_A),
            Err(KekError::EmptyId)
        ));
        assert!(matches!(
            CredentialKek::load("", &path),
            Err(KekError::EmptyId)
        ));
    }

    #[test]
    fn key_ring_rejects_duplicate_ids() {
        assert!(matches!(
            KeyRing::new(kek("k1", KEY_A), vec![kek("k1", KEY_B)]),
            Err(KekError::DuplicateId(id)) if id == "k1"
        ));
        assert!(matches!(
            KeyRing::new(kek("k-new", KEY_A), vec![kek("k-old", KEY_A), kek("k-old", KEY_B)]),
            Err(KekError::DuplicateId(id)) if id == "k-old"
        ));
    }

    #[test]
    fn fingerprint_is_deterministic_16_lowercase_hex_chars() {
        let first = fingerprint(b"master", &secret());
        let second = fingerprint(b"master", &secret());
        assert_eq!(first, second);
        assert_eq!(first.len(), 16);
        assert!(first
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
    }

    #[test]
    fn fingerprint_differs_for_different_hmac_secrets() {
        assert_ne!(
            fingerprint(b"master-a", &secret()),
            fingerprint(b"master-b", &secret())
        );
    }

    #[test]
    fn fingerprint_is_not_a_plain_hmac_of_the_plaintext() {
        let master = b"fingerprint-master";
        let plain_key = hmac::Key::new(hmac::HMAC_SHA256, master);
        let plain = hmac::sign(&plain_key, PLAINTEXT.as_bytes());
        assert_ne!(
            fingerprint(master, &secret()),
            hex_lower(&plain.as_ref()[..8])
        );
    }

    #[test]
    fn last4_uses_chars_not_bytes() {
        assert_eq!(last4(&TenantSecret::new("ab".to_string())), "ab");
        assert_eq!(last4(&secret()), "INEL");
        // Multibyte: 5 chars, last 4 must be whole characters.
        assert_eq!(last4(&TenantSecret::new("ключ🙂".to_string())), "люч🙂");
    }
}
