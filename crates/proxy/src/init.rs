//! `llm-proxy init` starter installation.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::Path;

use proxy_filters::auth::{digest_hex, generate_plaintext_key, HmacSecret};
use ring::rand::{SecureRandom as _, SystemRandom};

const CONFIG_FILE: &str = "llmproxy.yaml";
const SECRET_FILE: &str = "auth-secret";
const DEFAULT_TENANT: &str = "default";
const DEFAULT_KEY_ID: &str = "default-admin";

pub fn run(directory: &Path) -> Result<(), String> {
    let config_path = directory.join(CONFIG_FILE);
    let secret_path = directory.join(SECRET_FILE);

    refuse_existing(&config_path)?;
    refuse_existing(&secret_path)?;
    fs::create_dir_all(directory)
        .map_err(|e| format!("cannot create {}: {e}", directory.display()))?;

    let rng = SystemRandom::new();
    let mut secret_bytes = [0_u8; 32];
    rng.fill(&mut secret_bytes)
        .map_err(|_| "failed to generate the authentication secret".to_string())?;
    let secret_text = secret_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let plaintext_key = generate_plaintext_key(&rng);
    let digest = digest_hex(&HmacSecret::new(secret_text.as_bytes()), &plaintext_key);

    write_new_secret(&secret_path, secret_text.as_bytes())?;
    if let Err(err) = write_new(&config_path, starter_config(&digest).as_bytes()) {
        let _ = fs::remove_file(&secret_path);
        return Err(err);
    }

    println!(
        "Initialized {}\n\n  config: {}\n  authentication secret: {}\n  tenant: {}\n  key id: {}\n\nKey (shown once -- store it now; it cannot be recovered):\n\n  {}\n\nRun:\n\n  cd {}\n  llm-proxy --config {}",
        directory.display(),
        config_path.display(),
        secret_path.display(),
        DEFAULT_TENANT,
        DEFAULT_KEY_ID,
        plaintext_key,
        directory.display(),
        CONFIG_FILE,
    );
    Ok(())
}

fn refuse_existing(path: &Path) -> Result<(), String> {
    if path.exists() {
        return Err(format!(
            "refusing to overwrite existing file {}; move it or choose another directory",
            path.display()
        ));
    }
    Ok(())
}

fn write_new(path: &Path, contents: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    file.write_all(contents)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

#[cfg(unix)]
fn write_new_secret(path: &Path, contents: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    file.write_all(contents)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn write_new_secret(path: &Path, contents: &[u8]) -> Result<(), String> {
    write_new(path, contents)
}

fn starter_config(digest: &str) -> String {
    format!(
        r#"# llm-proxy starter configuration
version: 0

listen: 0.0.0.0:8080
admin: 127.0.0.1:9901

# Every generated account starts in the reserved `default` tenant. Add more
# keys with: llm-proxy --mode keygen --tenant default --hmac-secret-file ./auth-secret
auth:
  hmac_secret_file: ./auth-secret
  keys:
    - id: {DEFAULT_KEY_ID}
      tenant: {DEFAULT_TENANT}
      digest: {digest}

providers:
  # Local default; install Ollama and pull a model before sending requests.
  ollama:
    type: openai-compatible
    base_url: http://127.0.0.1:11434

  # OpenAI
  # openai:
  #   api_key: replace-with-OPENAI_API_KEY

  # Anthropic
  # anthropic:
  #   api_key: replace-with-ANTHROPIC_API_KEY

  # OpenRouter (OpenAI-compatible)
  # openrouter:
  #   type: openai-compatible
  #   base_url: https://openrouter.ai
  #   api_key: replace-with-OPENROUTER_API_KEY

  # SpaceX AI / xAI (OpenAI-compatible)
  # spacexai:
  #   type: openai-compatible
  #   base_url: https://api.x.ai
  #   api_key: replace-with-XAI_API_KEY

routes:
  - model: "*"
    provider: ollama

observability:
  access_logs:
    output: stdout
    format: json
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starter_config_parses_as_dialect_config() {
        let text = starter_config(&"a".repeat(64));
        proxy_simple_config::parse_simple_config(&text).expect("starter must parse");
    }

    #[test]
    fn starter_lists_requested_provider_examples() {
        let text = starter_config(&"a".repeat(64));
        for provider in ["openai", "anthropic", "openrouter", "spacexai", "ollama"] {
            assert!(
                text.contains(provider),
                "missing provider example {provider}"
            );
        }
    }
}
