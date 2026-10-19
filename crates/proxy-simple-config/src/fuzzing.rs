//! Entry points for the cargo-fuzz targets in `fuzz/`. Not a public API: the
//! module exists only with the `fuzzing` feature (and under `test`), and each
//! function forwards to a private helper unchanged, so the fuzzer exercises
//! the code production runs.

/// The `routes[].model` and `models` key glob the validator uses
/// (`parse::glob_matches`).
pub fn glob_matches(pattern: &str, name: &str) -> bool {
    crate::parse::glob_matches(pattern, name)
}

/// Whether `name` is a legal `models:` catalogue key
/// (`lower::classify_model_key`).
pub fn is_valid_model_key(name: &str) -> bool {
    crate::lower::classify_model_key(name).is_ok()
}
