//! Async filesystem loaders for `config.toml` and `clients.json`.
//!
//! Lives outside `crate::config` so the parser knows nothing about
//! the filesystem. Reads go through `compio::fs::read`.

use std::io;
use std::path::Path;

use crate::config::{ClientsFile, Config};

/// Load and parse `config.toml`. Parse errors are wrapped via
/// `io::Error::other` so the unified return type lets `?` flow at
/// callers. The error doesn't carry the path — caller has it and
/// stamps it on its log line.
pub async fn load_config(path: &Path) -> io::Result<Config> {
    let text = read_utf8(path).await?;
    Config::parse(&text).map_err(io::Error::other)
}

/// Load and parse `clients.json`. Same wrapping convention as
/// `load_config`.
pub async fn load_clients_file(path: &Path) -> io::Result<ClientsFile> {
    let text = read_utf8(path).await?;
    ClientsFile::parse(&text).map_err(io::Error::other)
}

async fn read_utf8(path: &Path) -> io::Result<String> {
    let bytes = compio::fs::read(path).await?;
    String::from_utf8(bytes).map_err(io::Error::other)
}
