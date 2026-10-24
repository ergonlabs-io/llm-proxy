//! `--mode keygen` -- generates a virtual key and the digest that goes in an
//! `auth.keys[]` (or `typed_config.virtual_keys[]`) entry, so an operator no
//! longer has to invent a key by hand and reach for `openssl` to digest it.
//!
//! The generated digest uses the same HMAC-SHA256 function as authentication,
//! so generated credentials match the verifier's normalization and encoding.

use std::path::PathBuf;

use ring::rand::SystemRandom;

use proxy_control::auth::{digest_hex, generate_plaintext_key, HmacSecret};

/// Env var carrying the HMAC secret, mirroring the dialect's `hmac_secret:
/// ${VAR}` idiom (`schema/llmproxy-v1.schema.json`'s `Auth.hmac_secret`).
const SECRET_ENV_VAR: &str = "LLMPROXY_AUTH_SECRET";

/// Resolves the operator's HMAC secret: `--hmac-secret-file` first, then
/// `$LLMPROXY_AUTH_SECRET`, erroring clearly if neither is usable.
///
/// File contents use the same normalization as the verifier, so a trailing
/// newline cannot make the printed digest unusable. The environment value is
/// not trimmed, matching inline configuration.
fn resolve_secret(hmac_secret_file: Option<&PathBuf>) -> Result<Vec<u8>, String> {
    if let Some(path) = hmac_secret_file {
        let raw = std::fs::read(path)
            .map_err(|e| format!("--hmac-secret-file {}: {e}", path.display()))?;
        let bytes = proxy_control::auth::secret_bytes_from_file(&raw).to_vec();
        if bytes.is_empty() {
            return Err(format!(
                "--hmac-secret-file {}: file is empty or contains only whitespace (an empty \
                 secret would make every digest effectively unkeyed)",
                path.display()
            ));
        }
        return Ok(bytes);
    }

    match std::env::var(SECRET_ENV_VAR) {
        Ok(value) if !value.is_empty() => Ok(value.into_bytes()),
        Ok(_) => Err(format!(
            "${SECRET_ENV_VAR} is set but empty (an empty secret would make every digest \
             effectively unkeyed)"
        )),
        Err(_) => Err(format!(
            "no HMAC secret: pass --hmac-secret-file <PATH>, or set ${SECRET_ENV_VAR}"
        )),
    }
}

/// Runs `--mode keygen`: resolves the secret, generates a key, and prints it
/// once as a paste-ready config fragment.
///
/// The plaintext key is written once to stdout for the operator to copy; it
/// must never enter tracing or stderr logs.
pub fn run(tenant: &str, key_id: &str, hmac_secret_file: Option<&PathBuf>) -> Result<(), String> {
    let secret_bytes = resolve_secret(hmac_secret_file)?;
    let secret = HmacSecret::new(&secret_bytes);

    let rng = SystemRandom::new();
    let plaintext_key = generate_plaintext_key(&rng);
    let digest = digest_hex(&secret, &plaintext_key);

    println!(
        "Key (shown once -- store it now; it cannot be recovered from the config):\n\n  \
         {plaintext_key}\n\nAdd to your llmproxy.yaml:\n\n  auth:\n    keys:\n      - id: \
         {key_id}\n        tenant: {tenant}\n        digest: {digest}\n"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Rust note: `std::env::set_var`/`remove_var` mutate PROCESS-GLOBAL state,
    // and `cargo test` runs `#[test]` fns on separate threads by default.
    // Both tests below touch `SECRET_ENV_VAR` (one sets it, the other asserts
    // it is absent), so without this lock they race: the "neither source is
    // set" test could observe the other test's `env-secret` mid-flight and
    // "pass" a resolution that should have errored -- or fail, depending on
    // thread timing. An edge here must not make CI a coin flip (rule of thumb:
    // a flaky test is a broken test).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Held for the whole body of each env-touching test. `into_inner` on
    /// poisoning so one test's panic does not cascade "dead" locks into the
    /// others -- the `()` payload guards nothing but ordering.
    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn resolve_secret_prefers_file_over_env_var() {
        let _env_guard = lock_env();
        // Written to leave the var exactly as it found it (removed) even on an
        // early `expect` panic -- the CLI integration tests under `tests/`
        // spawn a fresh process each time, so they never inherit whatever
        // this in-process test leaves behind either way.
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "llm-proxy-keygen-unit-test-secret-{}.txt",
            std::process::id()
        ));
        std::fs::write(&path, "file-secret").expect("write temp secret file");

        std::env::set_var(SECRET_ENV_VAR, "env-secret");
        let resolved = resolve_secret(Some(&path));
        std::env::remove_var(SECRET_ENV_VAR);
        let _ = std::fs::remove_file(&path);

        assert_eq!(
            resolved.expect("file secret should resolve"),
            b"file-secret"
        );
    }

    #[test]
    fn resolve_secret_errors_clearly_when_neither_source_is_set() {
        let _env_guard = lock_env();
        std::env::remove_var(SECRET_ENV_VAR);
        let err = resolve_secret(None).expect_err("no secret configured must be an error");
        assert!(err.contains(SECRET_ENV_VAR));
    }
}
