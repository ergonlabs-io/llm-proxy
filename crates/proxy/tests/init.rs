use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");

fn unique_dir(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "llm-proxy-init-{label}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ))
}

#[test]
fn init_creates_a_valid_install_without_overwriting_it() {
    let dir = unique_dir("valid");
    let first = Command::new(BIN)
        .args(["init", dir.to_str().unwrap()])
        .output()
        .expect("run init");
    assert!(
        first.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(dir.join("llmproxy.yaml").is_file());
    assert!(dir.join("auth-secret").is_file());
    assert!(std::fs::read_to_string(dir.join("llmproxy.yaml"))
        .unwrap()
        .contains("output: ./llmproxy-access.log"));
    assert!(String::from_utf8_lossy(&first.stdout).contains("tenant: default"));

    let validate = Command::new(BIN)
        .current_dir(&dir)
        .args(["--config", "llmproxy.yaml", "--mode", "validate"])
        .output()
        .expect("validate generated config");
    assert!(
        validate.status.success(),
        "generated config invalid: {}",
        String::from_utf8_lossy(&validate.stderr)
    );

    let config_before = std::fs::read(dir.join("llmproxy.yaml")).unwrap();
    let second = Command::new(BIN)
        .args(["init", dir.to_str().unwrap()])
        .output()
        .expect("run init twice");
    assert!(!second.status.success());
    assert_eq!(
        config_before,
        std::fs::read(dir.join("llmproxy.yaml")).unwrap()
    );

    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn init_makes_the_authentication_secret_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = unique_dir("permissions");
    let status = Command::new(BIN)
        .args(["init", dir.to_str().unwrap()])
        .status()
        .expect("run init");
    assert!(status.success());
    let mode = std::fs::metadata(dir.join("auth-secret"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    std::fs::remove_dir_all(dir).unwrap();
}
