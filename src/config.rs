//! Parsing and in-memory representation of `/etc/gcb/config.toml` and
//! `/etc/gcb/clients.json`.
//!
//! Single responsibility: turn the on-disk schemas documented in
//! `docs/PROTOCOLS.md` into typed Rust values, and reject unknown
//! fields. All deserializers carry `#[serde(deny_unknown_fields)]`.

// Transitional: the `load_*` entry points and the `Io`/`Toml` error
// variants have no in-crate caller yet — `daemon` and `admin` are
// still stubs. Remove this allow when those modules land and start
// calling `load_config` / `load_clients_file`.
#![allow(dead_code)]

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Top-level parsed `config.toml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub(crate) listen: ListenConfig,
    pub(crate) admin: AdminConfig,
    pub(crate) clients: ClientsConfig,
    pub(crate) stunnel: StunnelConfig,
    pub(crate) logging: LoggingConfig,
    pub(crate) provider: Providers,
}

/// `[listen]` section.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListenConfig {
    /// Unix-domain socket the daemon listens on; stunnel forwards here.
    pub(crate) socket: PathBuf,
}

/// `[admin]` section.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdminConfig {
    /// Unix-domain socket the CLI talks to for operator commands.
    pub(crate) socket_path: PathBuf,
}

/// `[clients]` section.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientsConfig {
    /// Path to the JSON file holding enrolled clients.
    pub(crate) file: PathBuf,
}

/// `[stunnel]` section.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StunnelConfig {
    /// Path to stunnel's PSK secrets file. The daemon rewrites this
    /// via the admin socket on enroll/revoke and then SIGHUPs stunnel.
    pub(crate) psk_file: PathBuf,
}

/// `[logging]` section.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoggingConfig {
    /// Minimum log level the subscriber emits.
    pub(crate) level: LogLevel,
}

/// Log level as it appears in `config.toml`. Mirrors the levels
/// listed in `docs/PROTOCOLS.md`. Kept local (not `tracing::Level`)
/// because `tracing::Level` does not implement `serde::Deserialize`.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// `[provider.*]` parent table.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Providers {
    /// `[provider.github]` block; absent means no GitHub provider
    /// configured. The daemon errors at startup if no provider is
    /// configured at all.
    pub(crate) github: Option<ProviderGithub>,
}

/// `[provider.github]` section.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderGithub {
    /// Host string matched byte-exact against the `host=` field in
    /// git-credential requests (AGENTS.md invariant #11).
    pub host: String,
    /// API base URL, e.g. `https://api.github.com`. Kept as a plain
    /// string at this layer; URL parsing is the provider module's
    /// responsibility.
    pub api_base: String,
    pub app_id: u64,
    pub installation_id: u64,
    /// PEM-encoded App private key; loaded once at startup.
    pub private_key_path: PathBuf,
}

/// Top-level parsed `clients.json`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientsFile {
    /// Schema version. Only `1` is supported today.
    pub(crate) version: u32,
    pub(crate) clients: Vec<ClientEntry>,
}

/// One enrolled client.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientEntry {
    pub(crate) name: String,
    pub(crate) ip: IpAddr,
    pub(crate) providers: Vec<String>,
    /// RFC 3339 UTC timestamp. Kept as a `String`; consumers parse
    /// on use via `time::OffsetDateTime` if/when they need a typed
    /// value. The daemon is the sole writer and writes a known
    /// format. Retyping this field is a separate task.
    pub(crate) enrolled_at: String,
    pub(crate) note: Option<String>,
}

/// Errors returned by the config-loading entry points.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
    /// Reading the file from disk failed.
    #[error("failed to read {}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// TOML deserialization failed.
    #[error("failed to parse {}", path.display())]
    Toml {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    /// JSON deserialization failed.
    #[error("failed to parse {}", path.display())]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    /// `clients.json` has a schema version we don't know how to read.
    #[error("clients file version unsupported: got {0}, expected 1")]
    UnsupportedClientsVersion(u32),
}

/// Load and parse `config.toml`.
pub(crate) fn load_config(path: &Path) -> Result<Config, ConfigError> {
    let text = fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    toml::from_str(&text).map_err(|source| ConfigError::Toml {
        path: path.to_path_buf(),
        source,
    })
}

/// Load and parse `clients.json`.
pub(crate) fn load_clients_file(path: &Path) -> Result<ClientsFile, ConfigError> {
    let text = fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    parse_clients_file(&text, path)
}

/// Parse a `clients.json` body. Split from `load_clients_file` so the
/// version-check branch is reachable from unit tests without touching
/// the filesystem.
fn parse_clients_file(text: &str, path: &Path) -> Result<ClientsFile, ConfigError> {
    let parsed: ClientsFile = serde_json::from_str(text).map_err(|source| ConfigError::Json {
        path: path.to_path_buf(),
        source,
    })?;
    if parsed.version != 1 {
        return Err(ConfigError::UnsupportedClientsVersion(parsed.version));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN_GOOD_CONFIG: &str = r#"
[listen]
socket = "/run/gcb/daemon.sock"

[admin]
socket_path = "/run/gcb/admin.sock"

[clients]
file = "/etc/gcb/clients.json"

[stunnel]
psk_file = "/etc/stunnel/gcb.psk"

[logging]
level = "info"

[provider.github]
host = "github.com"
api_base = "https://api.github.com"
app_id = 123456
installation_id = 789012
private_key_path = "/etc/gcb/github-app.pem"
"#;

    #[test]
    fn config_known_good_round_trips() {
        let cfg: Config = toml::from_str(KNOWN_GOOD_CONFIG).unwrap();
        assert_eq!(cfg.listen.socket, PathBuf::from("/run/gcb/daemon.sock"));
        assert_eq!(cfg.admin.socket_path, PathBuf::from("/run/gcb/admin.sock"));
        assert_eq!(cfg.clients.file, PathBuf::from("/etc/gcb/clients.json"));
        assert_eq!(cfg.stunnel.psk_file, PathBuf::from("/etc/stunnel/gcb.psk"));
        assert_eq!(cfg.logging.level, LogLevel::Info);
        let gh = cfg.provider.github.expect("github provider present");
        assert_eq!(gh.host, "github.com");
        assert_eq!(gh.api_base, "https://api.github.com");
        assert_eq!(gh.app_id, 123_456);
        assert_eq!(gh.installation_id, 789_012);
        assert_eq!(
            gh.private_key_path,
            PathBuf::from("/etc/gcb/github-app.pem")
        );
    }

    #[test]
    fn config_rejects_unknown_top_level_key() {
        let src = format!("rogue = true\n{KNOWN_GOOD_CONFIG}");
        let err = toml::from_str::<Config>(&src).unwrap_err();
        assert!(
            err.to_string().contains("rogue") || err.to_string().contains("unknown"),
            "error did not mention unknown field: {err}"
        );
    }

    #[test]
    fn config_rejects_unknown_field_in_listen() {
        let src = KNOWN_GOOD_CONFIG.replace(
            "[listen]\nsocket = \"/run/gcb/daemon.sock\"",
            "[listen]\nsocket = \"/run/gcb/daemon.sock\"\nport = 1234",
        );
        assert!(toml::from_str::<Config>(&src).is_err());
    }

    #[test]
    fn config_rejects_unknown_field_in_provider_github() {
        let src = format!("{KNOWN_GOOD_CONFIG}rogue_field = \"x\"\n");
        assert!(toml::from_str::<Config>(&src).is_err());
    }

    #[test]
    fn config_rejects_missing_installation_id() {
        let src = KNOWN_GOOD_CONFIG.replace("installation_id = 789012\n", "");
        assert!(toml::from_str::<Config>(&src).is_err());
    }

    #[test]
    fn log_level_warn_accepted() {
        let cfg: LoggingConfig = toml::from_str(r#"level = "warn""#).unwrap();
        assert_eq!(cfg.level, LogLevel::Warn);
    }

    #[test]
    fn log_level_fatal_rejected() {
        assert!(toml::from_str::<LoggingConfig>(r#"level = "fatal""#).is_err());
    }

    #[test]
    fn clients_empty_array_parses() {
        let parsed: ClientsFile = serde_json::from_str(r#"{"version":1,"clients":[]}"#).unwrap();
        assert_eq!(parsed.version, 1);
        assert!(parsed.clients.is_empty());
    }

    #[test]
    fn clients_one_entry_parses() {
        let json = r#"{
  "version": 1,
  "clients": [
    {
      "name": "dev-vm-1",
      "ip": "192.168.122.10",
      "providers": ["github"],
      "enrolled_at": "2026-05-26T12:34:56Z",
      "note": null
    }
  ]
}"#;
        let parsed: ClientsFile = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.clients.len(), 1);
        let c = &parsed.clients[0];
        assert_eq!(c.name, "dev-vm-1");
        assert_eq!(c.ip, "192.168.122.10".parse::<IpAddr>().unwrap());
        assert_eq!(c.providers, vec!["github".to_string()]);
        assert_eq!(c.enrolled_at, "2026-05-26T12:34:56Z");
        assert!(c.note.is_none());
    }

    #[test]
    fn clients_unknown_field_on_entry_rejected() {
        let json = r#"{
  "version": 1,
  "clients": [
    {
      "name": "x",
      "ip": "10.0.0.1",
      "providers": [],
      "enrolled_at": "2026-01-01T00:00:00Z",
      "note": null,
      "extra": "nope"
    }
  ]
}"#;
        assert!(serde_json::from_str::<ClientsFile>(json).is_err());
    }

    #[test]
    fn clients_version_two_returns_unsupported() {
        let json = r#"{"version":2,"clients":[]}"#;
        let err = parse_clients_file(json, Path::new("/test/clients.json")).unwrap_err();
        assert!(
            matches!(err, ConfigError::UnsupportedClientsVersion(2)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn clients_malformed_ip_returns_json_error() {
        let json = r#"{
  "version": 1,
  "clients": [
    {
      "name": "x",
      "ip": "not-an-ip",
      "providers": [],
      "enrolled_at": "2026-01-01T00:00:00Z",
      "note": null
    }
  ]
}"#;
        let err = parse_clients_file(json, Path::new("/test/clients.json")).unwrap_err();
        assert!(matches!(err, ConfigError::Json { .. }), "unexpected: {err}");
    }
}
