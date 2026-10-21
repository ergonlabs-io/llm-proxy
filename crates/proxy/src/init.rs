//! `llm-proxy init` starter installation.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::Path;

use proxy_control::auth::{digest_hex, generate_plaintext_key, HmacSecret};
use ring::rand::{SecureRandom as _, SystemRandom};

const CONFIG_FILE: &str = "llmproxy.yaml";
const SECRET_FILE: &str = "auth-secret";
/// Read by the operator into `LLMPROXY_ADMIN_TOKEN`. The token stays out of the config, so a config dump or a
/// checked-in config never carries it.
const ADMIN_TOKEN_FILE: &str = "admin-token";
/// The starter config's `admin` address, printed as the admin UI's address.
const ADMIN_ADDRESS: &str = "127.0.0.1:53422";
const DEFAULT_TENANT: &str = "default";
const DEFAULT_KEY_ID: &str = "default-admin";

pub fn run(directory: &Path) -> Result<(), String> {
    let config_path = directory.join(CONFIG_FILE);
    let secret_path = directory.join(SECRET_FILE);
    let admin_token_path = directory.join(ADMIN_TOKEN_FILE);

    refuse_existing(&config_path)?;
    refuse_existing(&secret_path)?;
    refuse_existing(&admin_token_path)?;
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
    let mut admin_token_bytes = [0_u8; 32];
    rng.fill(&mut admin_token_bytes)
        .map_err(|_| "failed to generate the admin token".to_string())?;
    let admin_token = admin_token_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let digest = digest_hex(&HmacSecret::new(secret_text.as_bytes()), &plaintext_key);

    write_new_secret(&secret_path, secret_text.as_bytes())?;
    if let Err(err) = write_new_secret(&admin_token_path, admin_token.as_bytes()) {
        let _ = fs::remove_file(&secret_path);
        return Err(err);
    }
    if let Err(err) = write_new(&config_path, starter_config(&digest).as_bytes()) {
        let _ = fs::remove_file(&secret_path);
        let _ = fs::remove_file(&admin_token_path);
        return Err(err);
    }

    println!(
        "Initialized {}\n\n  config: {}\n  authentication secret: {}\n  admin token: {}\n  tenant: {}\n  key id: {}\n\nKey (shown once -- store it now; it cannot be recovered):\n\n  {}\n\nRun:\n\n  cd {}\n  {}\n\n{}",
        directory.display(),
        config_path.display(),
        secret_path.display(),
        admin_token_path.display(),
        DEFAULT_TENANT,
        DEFAULT_KEY_ID,
        plaintext_key,
        directory.display(),
        run_command(),
        admin_ui_hint(),
    );
    Ok(())
}

/// The command `init` prints. The admin token comes from its file, so the admin UI can make changes from the first
/// start, and never appears on the command line as a literal.
fn run_command() -> String {
    format!("LLMPROXY_ADMIN_TOKEN=\"$(cat {ADMIN_TOKEN_FILE})\" llm-proxy --config {CONFIG_FILE}")
}

fn admin_ui_hint() -> String {
    format!(
        "Admin UI: http://{ADMIN_ADDRESS}/ui/\n  Paste the token from {ADMIN_TOKEN_FILE} to manage keys, tenants, budgets and pricing.\n  The UI needs LLMPROXY_ADMIN_UI_DIR set to the admin-ui-dist directory of the release archive."
    )
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

listen: 0.0.0.0:53421
admin: {ADMIN_ADDRESS}

# Every generated account starts in the reserved `default` tenant. Add more
# keys with: llm-proxy --mode keygen --tenant default --hmac-secret-file ./auth-secret
auth:
  hmac_secret_file: ./auth-secret
  keys:
    - id: {DEFAULT_KEY_ID}
      tenant: {DEFAULT_TENANT}
      digest: {digest}
  # Lets every tenant without a stored model policy use every model, so the
  # key above works at once. The proxy warns about it at startup. Before you
  # issue keys to other people, grant models per tenant with
  # PUT /tenants/{{id}}/policy and remove this block.
  enforce:
    tenants_without_policy: allow

providers:
  # Local default; install Ollama and pull a model before sending requests.
  ollama:
    type: openai-compatible
    base_url: http://127.0.0.1:11434

  # OpenAI
  # openai:
  #   api_key: ${{OPENAI_API_KEY}}

  # Anthropic
  # anthropic:
  #   api_key: ${{ANTHROPIC_API_KEY}}

  # OpenRouter (all OpenRouter model IDs)
  # openrouter:
  #   type: openrouter
  #   api_key: ${{OPENROUTER_API_KEY}}

  # SpaceX AI / xAI (OpenAI-compatible)
  # spacexai:
  #   type: openai-compatible
  #   base_url: https://api.x.ai
  #   api_key: ${{XAI_API_KEY}}

# To serve every model from another provider, uncomment it above, export the
# environment variable its api_key names, and name the provider here.
routes:
  - model: "*"
    provider: ollama

observability:
  access_logs:
    output: ./llmproxy-access.log
    format: json
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_writes_an_admin_token_file_and_refuses_to_overwrite_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        run(dir.path()).expect("init succeeds in an empty directory");
        let token =
            fs::read_to_string(dir.path().join(ADMIN_TOKEN_FILE)).expect("admin token file");
        assert_eq!(token.len(), 64, "32 random bytes, hex-encoded");
        assert!(token.bytes().all(|b| b.is_ascii_hexdigit()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(dir.path().join(ADMIN_TOKEN_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the admin token is a credential");
        }
        let config = fs::read_to_string(dir.path().join(CONFIG_FILE)).unwrap();
        assert!(
            !config.contains(&token),
            "the token must stay out of the config"
        );

        fs::remove_file(dir.path().join(CONFIG_FILE)).unwrap();
        fs::remove_file(dir.path().join(SECRET_FILE)).unwrap();
        let err = run(dir.path()).expect_err("an existing admin token file is never overwritten");
        assert!(err.contains(ADMIN_TOKEN_FILE), "{err}");
    }

    #[test]
    fn printed_admin_ui_address_is_the_starter_admin_address() {
        let text = starter_config(&"a".repeat(64));
        assert!(text.contains(&format!("admin: {ADMIN_ADDRESS}")));
        assert!(admin_ui_hint().contains(&format!("http://{ADMIN_ADDRESS}/ui/")));
        assert!(
            run_command().contains(&format!("\"$(cat {ADMIN_TOKEN_FILE})\"")),
            "the token is read from its file, never inlined: {}",
            run_command()
        );
    }

    #[test]
    fn starter_config_parses_as_dialect_config() {
        let text = starter_config(&"a".repeat(64));
        // A fresh install has none of the commented-out providers' variables
        // set; their `${VAR}` placeholders must not fail the load.
        assert!(text.contains("#   api_key: ${OPENAI_API_KEY}"));
        proxy_simple_config::parse_simple_config_with_env(&text, &|_| None)
            .expect("starter must parse with no environment");
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

    #[test]
    fn starter_allows_tenants_without_policy_so_the_printed_key_works() {
        let text = starter_config(&"a".repeat(64));
        let config = proxy_simple_config::parse_simple_config(&text).expect("starter must parse");
        let auth = config.auth.expect("starter configures auth");
        assert_eq!(
            auth.enforce.tenants_without_policy,
            Some(proxy_simple_config::model::TenantsWithoutPolicy::Allow)
        );
    }

    #[test]
    fn starter_writes_access_logs_to_a_file() {
        let text = starter_config(&"a".repeat(64));
        assert!(text.contains("output: ./llmproxy-access.log"));
        assert!(!text.contains("output: stdout"));
    }
}
