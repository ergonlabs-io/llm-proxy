//! `controlplane` is a library crate consumed by integration tests;
//! this binary has nothing to run on
//! its own.

fn main() {
    println!(
        "controlplane is a library for the scriptable xDS test harness; it has no binary behavior."
    );
}
