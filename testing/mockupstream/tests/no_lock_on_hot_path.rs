//! Structural sanity check for the crate doc's rule ("no `Mutex` on
//! the request path"), which the scale-test profile extension must not
//! quietly break by giving profile lookup or RNG state a shared, lockable
//! home.
//!
//! This can't be a runtime test -- nothing here would reliably contend a
//! lock even if one existed. Instead it inspects the source of the three
//! hot-path modules directly (via `include_str!`, so it fails the moment
//! any of them starts constructing a `Mutex`/`RwLock`, not just when a test
//! happens to exercise the unlucky interleaving) and asserts none of them
//! ever names a lock type as a *value* (`Mutex<`/`RwLock<`) -- as opposed to
//! merely *mentioning* one in a doc comment explaining why there isn't one,
//! which several already do (`stats.rs`, `handler.rs`'s "Rust note").

const HANDLER_SRC: &str = include_str!("../src/handler.rs");
const FRAMES_SRC: &str = include_str!("../src/frames.rs");
const PROFILES_SRC: &str = include_str!("../src/profiles.rs");

/// A line constructs/names a lock type as a value, not just mentions it in
/// prose -- `Mutex<`/`RwLock<` is how both a type annotation (`Mutex<T>`)
/// and a constructor (`Mutex::new`, which is written `Mutex::<T>::new` only
/// when turbofished, but far more commonly just `Mutex::new` -- so this also
/// checks the bare `Mutex::`/`RwLock::` prefix) would appear; a doc comment
/// merely naming "Mutex" in backticks (no `<` or `::` immediately after)
/// does not.
fn constructs_a_lock(src: &str) -> bool {
    src.lines().any(|line| {
        let trimmed = line.trim_start();
        // Skip doc/regular comments -- every current mention of "Mutex" in
        // this crate's hot-path modules is prose explaining its absence.
        if trimmed.starts_with("//") {
            return false;
        }
        line.contains("Mutex<")
            || line.contains("Mutex::")
            || line.contains("RwLock<")
            || line.contains("RwLock::")
    })
}

#[test]
fn handler_never_constructs_a_lock() {
    assert!(
        !constructs_a_lock(HANDLER_SRC),
        "handler.rs must not hold a Mutex/RwLock on the request path"
    );
}

#[test]
fn frames_never_constructs_a_lock() {
    assert!(
        !constructs_a_lock(FRAMES_SRC),
        "frames.rs must not hold a Mutex/RwLock while building/streaming a response"
    );
}

#[test]
fn profiles_never_constructs_a_lock() {
    assert!(
        !constructs_a_lock(PROFILES_SRC),
        "profiles.rs must not hold a Mutex/RwLock across a profile lookup"
    );
}
