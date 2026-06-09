//! Parsing and in-memory representation of `config.toml` and
//! `clients.json`.
//!
//! Single responsibility: turn the on-disk schemas documented in
//! `docs/PROTOCOLS.md` into typed Rust values, and reject unknown
//! fields. No filesystem access — that lives in `crate::loader`.
//! All deserializers carry `#[serde(deny_unknown_fields)]`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Top-level parsed `config.toml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: ListenConfig,
    pub admin: AdminConfig,
    pub clients: ClientsConfig,
    pub logging: LoggingConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    pub provider: Providers,
}

/// `[runtime]` section. Optional knobs that don't fit elsewhere.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    /// Optional pidfile path. When set, the daemon writes its PID
    /// here once it's ready to serve (for OpenRC's
    /// `command_background=yes` + `pidfile=...` convention). Under
    /// systemd, leave unset and use `Type=notify` — sd_notify
    /// READY=1 covers readiness without a pidfile.
    ///
    /// The parent directory of this path is added to the sandbox
    /// write-allowlist automatically.
    #[serde(default)]
    pub pidfile: Option<PathBuf>,
}

/// `[listen]` section.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenConfig {
    /// TCP address the daemon binds for inbound client connections.
    /// Default deployment: `0.0.0.0:9418`. Symbolon terminates Noise NNpsk0
    /// in-process; no stunnel layer.
    pub bind: SocketAddr,
    /// Path to the symbolon-owned PSK store (`identity:hex_psk` per line).
    /// Read at startup and re-read on SIGHUP. Atomically rewritten by
    /// enroll/revoke.
    pub psk_file: PathBuf,
}

/// `[admin]` section.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// Unix-domain socket the CLI talks to for operator commands.
    pub socket_path: PathBuf,
}

/// `[clients]` section.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientsConfig {
    /// Path to the JSON file holding enrolled clients.
    pub file: PathBuf,
}

/// `[logging]` section.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Minimum log level the subscriber emits.
    pub level: LogLevel,
}

/// Log level as it appears in `config.toml`. Mirrors the levels
/// listed in `docs/PROTOCOLS.md`. Kept local (not `tracing::Level`)
/// because `tracing::Level` does not implement `serde::Deserialize`.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// `[security]` section. Absent in `config.toml` means `Default` —
/// `sandbox = "best_effort"`, no extra read dirs.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    #[serde(default)]
    pub sandbox: SandboxMode,
    /// Extra read-only dirs to grant landlock access on. RHEL/Fedora
    /// hosts typically need `"/etc/pki/tls/certs"` for OpenSSL CA
    /// roots.
    #[serde(default)]
    pub extra_read_dirs: Vec<PathBuf>,
    /// `mlockall` policy at startup. See `MlockMode` for semantics.
    /// Belt-and-suspenders on top of the primary defence (disable
    /// swap on the broker host — see docs/INSTALL.md).
    #[serde(default)]
    pub mlock: MlockMode,
}

/// Sandbox enforcement policy, controlling Landlock at ABI 6.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SandboxMode {
    /// Refuse to start if the kernel can't enforce the full ABI.
    Required,
    /// Apply whatever the kernel supports; log degradation.
    #[default]
    BestEffort,
    /// Skip sandboxing entirely. Not recommended; useful in tests.
    Off,
}

/// `mlockall` policy at daemon startup. We call
/// `mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)` so the App
/// private key and in-flight tokens never reach swap. Needs
/// `LimitMEMLOCK=infinity` in the systemd unit (or
/// CAP_IPC_LOCK) — see docs/INSTALL.md.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MlockMode {
    /// Call mlockall; exit 1 if it fails.
    Required,
    /// Call mlockall; on failure log `evt=mlock status=skipped`
    /// and continue. Zero-config friendly default.
    #[default]
    BestEffort,
    /// Don't call mlockall. For containers/CI where the syscall
    /// would noisily fail and the operator doesn't want it.
    Off,
}

/// `[provider.*]` parent table.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Providers {
    /// `[provider.github]` block; absent means no GitHub provider
    /// configured. The daemon errors at startup if no provider is
    /// configured at all.
    pub github: Option<ProviderGithub>,
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
    /// GitHub App Client ID (the `Iv1.`/`Iv23l...` string visible on
    /// the App's settings page). Used as the JWT `iss` claim; this
    /// is the documented preferred form per GitHub's "Generating a
    /// JSON web token (JWT) for a GitHub App" guide.
    pub client_id: String,
    pub installation_id: u64,
    /// PEM-encoded App private key; loaded once at startup.
    pub private_key_path: PathBuf,
    /// Startup self-check timeout (e.g. `"5s"`). Required — no
    /// default; the operator picks based on their network's p99
    /// latency to api.github.com.
    #[serde(with = "humantime_serde")]
    pub selfcheck_timeout: std::time::Duration,
    /// Per-request timeout for resolve / mint HTTPS calls
    /// (e.g. `"10s"`). Defaults to 10s if omitted.
    #[serde(with = "humantime_serde", default = "default_request_timeout")]
    pub request_timeout: std::time::Duration,
    /// HTTP `User-Agent` sent to the provider API. GitHub rejects
    /// requests without one (403). Default `"symbolon"` — no version
    /// number is appended, since leaking the patch level narrows
    /// the CVE list applicable to this binary. Operators can
    /// override to e.g. their org name.
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
}

fn default_request_timeout() -> std::time::Duration {
    std::time::Duration::from_secs(10)
}

fn default_user_agent() -> String {
    "symbolon".to_string()
}

/// Top-level parsed `clients.json`. Serialize side is used by
/// `admin::handle_enroll` / `handle_revoke` when rewriting the
/// file; the round-trip uses the same struct on both ends so the
/// schema can only drift in one place.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientsFile {
    /// Schema version. Only `2` is supported today. v1 carried an
    /// `ip` field per client (used when stunnel fronted the daemon
    /// and identity came from the source IP); v2 drops it — identity
    /// now derives from the Noise handshake's PSK selection.
    pub version: u32,
    pub clients: Vec<ClientEntry>,
}

/// One enrolled client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientEntry {
    pub name: String,
    pub providers: Vec<String>,
    /// RFC 3339 UTC timestamp. Kept as a `String`; consumers parse
    /// on use via `time::OffsetDateTime` if/when they need a typed
    /// value. The daemon is the sole writer and writes a known
    /// format. Retyping this field is a separate task.
    pub enrolled_at: String,
    pub note: Option<String>,
}

/// Errors returned by config parsing.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Reading the file from disk failed.
    #[error("failed to read {}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// File bytes were not valid UTF-8.
    #[error("file contents are not valid UTF-8: {}", path.display())]
    Utf8 {
        path: PathBuf,
        #[source]
        source: std::str::Utf8Error,
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
    #[error(
        "clients file version unsupported: got {0}, expected 2 (re-enroll all clients to upgrade from v1)"
    )]
    UnsupportedClientsVersion(u32),
}

/// Parse `config.toml` from a UTF-8 string.
pub fn parse_config(text: &str, path: &Path) -> Result<Config, ConfigError> {
    toml::from_str(text).map_err(|source| ConfigError::Toml {
        path: path.to_path_buf(),
        source,
    })
}

/// Parse `clients.json` from a UTF-8 string. Validates schema version.
pub fn parse_clients_file(text: &str, path: &Path) -> Result<ClientsFile, ConfigError> {
    let parsed: ClientsFile = serde_json::from_str(text).map_err(|source| ConfigError::Json {
        path: path.to_path_buf(),
        source,
    })?;
    if parsed.version != 2 {
        return Err(ConfigError::UnsupportedClientsVersion(parsed.version));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN_GOOD_CONFIG: &str = r#"
[listen]
bind = "0.0.0.0:9418"
psk_file = "/var/lib/symbolon/psks"

[admin]
socket_path = "/run/symbolon/admin.sock"

[clients]
file = "/var/lib/symbolon/clients.json"

[logging]
level = "info"

[provider.github]
host = "github.com"
api_base = "https://api.github.com"
client_id = "Iv23liABCDEFGHIJklmn"
installation_id = 789012
private_key_path = "/etc/symbolon/github-app.pem"
selfcheck_timeout = "5s"
"#;

    #[test]
    fn config_known_good_round_trips() {
        let cfg: Config = toml::from_str(KNOWN_GOOD_CONFIG).unwrap();
        assert_eq!(cfg.listen.bind, "0.0.0.0:9418".parse().unwrap());
        assert_eq!(cfg.listen.psk_file, PathBuf::from("/var/lib/symbolon/psks"));
        assert_eq!(
            cfg.admin.socket_path,
            PathBuf::from("/run/symbolon/admin.sock")
        );
        assert_eq!(
            cfg.clients.file,
            PathBuf::from("/var/lib/symbolon/clients.json")
        );
        assert_eq!(cfg.logging.level, LogLevel::Info);
        let gh = cfg.provider.github.expect("github provider present");
        assert_eq!(gh.host, "github.com");
        assert_eq!(gh.api_base, "https://api.github.com");
        assert_eq!(gh.client_id, "Iv23liABCDEFGHIJklmn");
        assert_eq!(gh.installation_id, 789_012);
        assert_eq!(
            gh.private_key_path,
            PathBuf::from("/etc/symbolon/github-app.pem")
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
            "[listen]\nbind = \"0.0.0.0:9418\"",
            "[listen]\nbind = \"0.0.0.0:9418\"\nport = 1234",
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
    fn config_rejects_missing_client_id() {
        let src = KNOWN_GOOD_CONFIG.replace("client_id = \"Iv23liABCDEFGHIJklmn\"\n", "");
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
    fn security_section_absent_defaults_to_best_effort() {
        let cfg: Config = toml::from_str(KNOWN_GOOD_CONFIG).unwrap();
        assert_eq!(cfg.security.sandbox, SandboxMode::BestEffort);
        assert!(cfg.security.extra_read_dirs.is_empty());
    }

    #[test]
    fn security_required_parses() {
        let src = format!("{KNOWN_GOOD_CONFIG}\n[security]\nsandbox = \"required\"\n");
        let cfg: Config = toml::from_str(&src).unwrap();
        assert_eq!(cfg.security.sandbox, SandboxMode::Required);
    }

    #[test]
    fn security_off_parses() {
        let src = format!("{KNOWN_GOOD_CONFIG}\n[security]\nsandbox = \"off\"\n");
        let cfg: Config = toml::from_str(&src).unwrap();
        assert_eq!(cfg.security.sandbox, SandboxMode::Off);
    }

    #[test]
    fn security_best_effort_parses_explicitly() {
        let src = format!("{KNOWN_GOOD_CONFIG}\n[security]\nsandbox = \"best_effort\"\n");
        let cfg: Config = toml::from_str(&src).unwrap();
        assert_eq!(cfg.security.sandbox, SandboxMode::BestEffort);
    }

    #[test]
    fn security_invalid_value_rejected() {
        let src = format!("{KNOWN_GOOD_CONFIG}\n[security]\nsandbox = \"strict\"\n");
        assert!(toml::from_str::<Config>(&src).is_err());
    }

    #[test]
    fn security_extra_read_dirs_parses() {
        let src = format!(
            "{KNOWN_GOOD_CONFIG}\n[security]\nsandbox = \"best_effort\"\nextra_read_dirs = [\"/etc/pki/tls/certs\"]\n"
        );
        let cfg: Config = toml::from_str(&src).unwrap();
        assert_eq!(
            cfg.security.extra_read_dirs,
            vec![PathBuf::from("/etc/pki/tls/certs")]
        );
    }

    #[test]
    fn security_unknown_field_rejected() {
        let src = format!("{KNOWN_GOOD_CONFIG}\n[security]\nsandbox = \"off\"\nrogue = true\n");
        assert!(toml::from_str::<Config>(&src).is_err());
    }

    #[test]
    fn clients_empty_array_parses() {
        let parsed: ClientsFile = serde_json::from_str(r#"{"version":2,"clients":[]}"#).unwrap();
        assert_eq!(parsed.version, 2);
        assert!(parsed.clients.is_empty());
    }

    #[test]
    fn clients_one_entry_parses() {
        let json = r#"{
  "version": 2,
  "clients": [
    {
      "name": "dev-vm-1",
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
        assert_eq!(c.providers, vec!["github".to_string()]);
        assert_eq!(c.enrolled_at, "2026-05-26T12:34:56Z");
        assert!(c.note.is_none());
    }

    #[test]
    fn clients_unknown_field_on_entry_rejected() {
        let json = r#"{
  "version": 2,
  "clients": [
    {
      "name": "x",
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
    fn clients_v1_rejected_with_migration_hint() {
        // v1 carried per-client `ip`; operators must re-enroll all clients
        // when upgrading.
        let json = r#"{"version":1,"clients":[]}"#;
        let err = parse_clients_file(json, Path::new("/test/clients.json")).unwrap_err();
        assert!(
            matches!(err, ConfigError::UnsupportedClientsVersion(1)),
            "unexpected error: {err}"
        );
        assert!(
            err.to_string().contains("re-enroll"),
            "error should hint at the migration path: {err}"
        );
    }

    #[test]
    fn clients_v1_ip_field_now_rejected_as_unknown() {
        // Belt-and-suspenders: even if someone forces version=2, the legacy
        // `ip` field is rejected by deny_unknown_fields.
        let json = r#"{
  "version": 2,
  "clients": [
    {
      "name": "x",
      "ip": "10.0.0.1",
      "providers": [],
      "enrolled_at": "2026-01-01T00:00:00Z",
      "note": null
    }
  ]
}"#;
        assert!(serde_json::from_str::<ClientsFile>(json).is_err());
    }
}
