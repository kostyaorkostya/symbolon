//! Binary entry point.
//!
//! In a later session this will dispatch between running the daemon
//! and the `gcb <provider> <subcommand>` CLI surface (see
//! `docs/OPERATIONS.md`). For now it just prints the package version
//! and exits 0 so the binary builds cleanly.

fn main() {
    println!("gcb {}", env!("CARGO_PKG_VERSION"));
}
