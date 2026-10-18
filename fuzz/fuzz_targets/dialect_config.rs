//! The dialect loader (`proxy-simple-config` `parse.rs` and `lower.rs`):
//! `${VAR}` interpolation with its YAML comment mask, strict YAML parsing,
//! semantic validation, and lowering to an Envoy bootstrap.
//!
//! An operator writes this file, but it also arrives through config reload,
//! and a panic here takes the process down rather than failing the load.
//!
//! Input: the config text. Every `${VAR}` resolves to a fixed value except
//! names starting with `UNSET`, which exercise the unset-variable path.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let env = |name: &str| (!name.starts_with("UNSET")).then(|| "fuzz-value".to_string());
    let Ok(config) = proxy_simple_config::parse_simple_config_with_env(text, &env) else {
        return;
    };
    let _ = proxy_simple_config::lower(&config);
    let _ = proxy_simple_config::to_envoy_yaml(&config);
});
