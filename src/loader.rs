//! Async filesystem loaders for `config.toml` and `clients.json`.
//!
//! Lives outside `crate::config` so the parser knows nothing about
//! the filesystem. Reads go through `compio::fs::read`.

use std::path::Path;

use crate::config::{self, ClientsFile, Config, ConfigError};

/// Load and parse `config.toml`.
pub async fn load_config(path: &Path) -> Result<Config, ConfigError> {
    let text = read_utf8(path).await?;
    config::parse_config(&text, path)
}

/// Load and parse `clients.json`.
pub(crate) async fn load_clients_file(path: &Path) -> Result<ClientsFile, ConfigError> {
    let text = read_utf8(path).await?;
    config::parse_clients_file(&text, path)
}

async fn read_utf8(path: &Path) -> Result<String, ConfigError> {
    let bytes = compio::fs::read(path)
        .await
        .map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    String::from_utf8(bytes).map_err(|e| ConfigError::Utf8 {
        path: path.to_path_buf(),
        source: e.utf8_error(),
    })
}
