//! Parsing and in-memory representation of `config.toml` and
//! `clients.json`.
//!
//! Single responsibility: turn the on-disk schemas documented in
//! `docs/PROTOCOLS.md` into typed Rust values, and reject unknown
//! fields. No filesystem access — that lives in `crate::loader`.
//! All deserializers carry `#[serde(deny_unknown_fields)]`.

use std::net::SocketAddr;
use std::path::PathBuf;

use derive_more::{Display, From};
use serde::{Deserialize, Serialize};

use crate::note::Note;
use crate::providers::ProviderKind;

/// GitHub App **installation** numeric id (the `installation_id`
/// path parameter on `/app/installations/{id}/access_tokens` etc.).
/// Operator-supplied via `[provider.github]`; distinct newtype so a
/// swap with `RepoId` is a compile error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, From, Deserialize, Serialize)]
#[from(u64)]
#[serde(transparent)]
pub struct InstallationId(u64);

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
    /// Default deployment: `0.0.0.0:9418`. Symbolon terminates Noise NKpsk2
    /// in-process.
    pub bind: SocketAddr,
    /// Path to the symbolon-owned PSK store (`identity:hex_psk` per line).
    /// Loaded once at startup; atomically rewritten by enroll/revoke.
    pub psk_file: PathBuf,
    /// Path to the broker's static X25519 private key: 64 hex chars on
    /// one line (`openssl rand -hex 32`), root-owned, mode 0440. Loaded once at
    /// startup, before the sandbox closes; rotating it requires
    /// re-enrolling every client (see docs/OPERATIONS.md).
    pub static_key_file: PathBuf,
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
    /// Minimum log level the subscriber emits. Accepts `"trace"` /
    /// `"debug"` / `"info"` / `"warn"` / `"error"` per
    /// `docs/PROTOCOLS.md` (matches `tracing::Level`'s `FromStr`).
    #[serde(deserialize_with = "deserialize_tracing_level")]
    pub level: tracing::Level,
}

/// `tracing::Level` doesn't implement `serde::Deserialize`, but its
/// `FromStr` accepts the exact set of strings we already documented
/// in PROTOCOLS.md. This shim bridges the two without inventing a
/// wrapper enum that would have to stay in sync with upstream.
fn deserialize_tracing_level<'de, D>(d: D) -> Result<tracing::Level, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let s = String::deserialize(d)?;
    s.parse().map_err(D::Error::custom)
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
/// `mlockall(MCL_CURRENT | MCL_FUTURE)` so the App private key
/// and in-flight tokens never reach swap. Needs
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

/// App-key signing backend. Required — no default. The daemon never
/// holds the App private key in its own address space; both backends
/// move the key material out of it. `tpm` signs in-process against a
/// vTPM; `file` signs in a sandboxed subprocess that owns the PEM.
/// The choice is the operator's; symbolon obeys — no auto-probing,
/// no runtime fallback.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AppKeyBackend {
    Tpm,
    File,
}

/// `[provider.github.tpm]` section — present iff `app_key_backend =
/// "tpm"`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderGithubTpm {
    /// TPM device path. Default `/dev/tpmrm0` — the kernel
    /// resource-manager node, which multiplexes concurrent access and
    /// virtualizes transient handles. Opened once, blocking, before
    /// the sandbox closes; the fd is then owned by the signing actor
    /// thread for the process lifetime (the sandbox never grants this
    /// path, so it cannot be reopened).
    #[serde(default = "default_tpm_device")]
    pub device: PathBuf,
    /// Persistent handle (`0x81xxxxxx`) of the pre-provisioned
    /// RSA-2048 signing key. TOML hex literal, e.g.
    /// `persistent_handle = 0x81010001`.
    pub persistent_handle: u32,
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
    pub installation_id: InstallationId,
    /// Signing backend selector. Cross-field validation
    /// ([`Config::parse`]) enforces the matching sub-config:
    /// `tpm` ⇒ `[provider.github.tpm]` present, `private_key_path`
    /// absent; `file` ⇒ the reverse.
    pub app_key_backend: AppKeyBackend,
    /// PEM-encoded App private key path — required for and only used
    /// by the `file` backend, where a sandboxed subprocess reads it.
    /// The daemon itself never opens it.
    #[serde(default)]
    pub private_key_path: Option<PathBuf>,
    /// vTPM signing parameters — required for and only used by the
    /// `tpm` backend.
    #[serde(default)]
    pub tpm: Option<ProviderGithubTpm>,
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

fn default_tpm_device() -> PathBuf {
    PathBuf::from("/dev/tpmrm0")
}

fn default_user_agent() -> String {
    "symbolon".to_string()
}

/// Top-level parsed `clients.json`. Serialize side is used by
/// `admin::handle_enroll` / `handle_revoke` when rewriting the
/// file; the round-trip uses the same struct on both ends so the
/// schema can only drift in one place.
///
/// Schema mismatches (added/removed/renamed fields across releases)
/// are caught by `#[serde(deny_unknown_fields)]` + serde's "missing
/// required field" errors. We intentionally don't carry a separate
/// `version` field — for a single-writer/single-reader broker-owned
/// state file, version flags duplicate what serde already enforces.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientsFile {
    pub clients: Vec<ClientEntry>,
}

/// One enrolled client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientEntry {
    pub name: String,
    pub providers: Vec<ProviderKind>,
    /// Enrollment timestamp. Round-trips through RFC 3339 on the
    /// wire (`2026-05-26T12:34:56Z` shape); typing as
    /// `OffsetDateTime` rejects malformed strings at load time.
    #[serde(with = "time::serde::rfc3339")]
    pub enrolled_at: time::OffsetDateTime,
    pub note: Option<Note>,
}

/// Abstract parse error. Boxed so callers can render the
/// Display/source chain without knowing whether the on-disk format
/// is TOML, JSON, or something we swap to later — the format is an
/// implementation detail of `parse`, not a contract.
pub type ParseError = Box<dyn std::error::Error + Send + Sync>;

impl Config {
    /// Parse `config.toml` from a UTF-8 string, then run cross-field
    /// validation that `#[serde(deny_unknown_fields)]` can't express
    /// (the backend selector and its matching sub-config must agree).
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let cfg: Self = toml::from_str(text)?;
        if let Some(gh) = &cfg.provider.github {
            gh.validate_backend()?;
        }
        Ok(cfg)
    }
}

impl ProviderGithub {
    /// Enforce that the signing-backend selector matches the
    /// sub-config actually present: each backend requires exactly its
    /// own keys and forbids the other's, so a typo in `app_key_backend`
    /// fails loudly at startup instead of silently ignoring a
    /// misplaced `private_key_path` or `[...tpm]` block.
    fn validate_backend(&self) -> Result<(), ParseError> {
        match self.app_key_backend {
            AppKeyBackend::Tpm => {
                if self.tpm.is_none() {
                    return Err(
                        "app_key_backend = \"tpm\" requires a [provider.github.tpm] section".into(),
                    );
                }
                if self.private_key_path.is_some() {
                    return Err(
                        "private_key_path is not used with app_key_backend = \"tpm\"; remove it"
                            .into(),
                    );
                }
            }
            AppKeyBackend::File => {
                if self.private_key_path.is_none() {
                    return Err("app_key_backend = \"file\" requires private_key_path".into());
                }
                if self.tpm.is_some() {
                    return Err("[provider.github.tpm] is not used with app_key_backend = \"file\"; remove it".into());
                }
            }
        }
        Ok(())
    }
}

impl ClientsFile {
    /// Parse `clients.json` from a UTF-8 string.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        Ok(serde_json::from_str(text)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN_GOOD_CONFIG: &str = r#"
[listen]
bind = "0.0.0.0:9418"
psk_file = "/var/lib/symbolon/psks"
static_key_file = "/etc/symbolon/broker.key"

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
app_key_backend = "file"
private_key_path = "/etc/symbolon/github-app.pem"
selfcheck_timeout = "5s"
"#;

    const KNOWN_GOOD_TPM_CONFIG: &str = r#"
[listen]
bind = "0.0.0.0:9418"
psk_file = "/var/lib/symbolon/psks"
static_key_file = "/etc/symbolon/broker.key"

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
app_key_backend = "tpm"
selfcheck_timeout = "5s"

[provider.github.tpm]
persistent_handle = 0x81010001
"#;

    #[test]
    fn config_known_good_round_trips() {
        let cfg: Config = toml::from_str(KNOWN_GOOD_CONFIG).unwrap();
        assert_eq!(cfg.listen.bind, "0.0.0.0:9418".parse().unwrap());
        assert_eq!(cfg.listen.psk_file, PathBuf::from("/var/lib/symbolon/psks"));
        assert_eq!(
            cfg.listen.static_key_file,
            PathBuf::from("/etc/symbolon/broker.key")
        );
        assert_eq!(
            cfg.admin.socket_path,
            PathBuf::from("/run/symbolon/admin.sock")
        );
        assert_eq!(
            cfg.clients.file,
            PathBuf::from("/var/lib/symbolon/clients.json")
        );
        assert_eq!(cfg.logging.level, tracing::Level::INFO);
        let gh = cfg.provider.github.expect("github provider present");
        assert_eq!(gh.host, "github.com");
        assert_eq!(gh.api_base, "https://api.github.com");
        assert_eq!(gh.client_id, "Iv23liABCDEFGHIJklmn");
        assert_eq!(gh.installation_id, InstallationId::from(789_012_u64));
        assert_eq!(gh.app_key_backend, AppKeyBackend::File);
        assert_eq!(
            gh.private_key_path,
            Some(PathBuf::from("/etc/symbolon/github-app.pem"))
        );
    }

    #[test]
    fn config_tpm_backend_parses_persistent_handle() {
        let cfg = Config::parse(KNOWN_GOOD_TPM_CONFIG).unwrap();
        let gh = cfg.provider.github.expect("github provider present");
        assert_eq!(gh.app_key_backend, AppKeyBackend::Tpm);
        assert!(gh.private_key_path.is_none());
        let tpm = gh.tpm.expect("tpm sub-config present");
        assert_eq!(tpm.device, PathBuf::from("/dev/tpmrm0"));
        assert_eq!(tpm.persistent_handle, 0x8101_0001);
    }

    #[test]
    fn config_tpm_backend_requires_tpm_section() {
        let src = KNOWN_GOOD_TPM_CONFIG.replace(
            "\n[provider.github.tpm]\npersistent_handle = 0x81010001\n",
            "\n",
        );
        let err = Config::parse(&src).unwrap_err();
        assert!(
            err.to_string().contains("[provider.github.tpm]"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn config_tpm_backend_rejects_private_key_path() {
        let src = KNOWN_GOOD_TPM_CONFIG.replace(
            "app_key_backend = \"tpm\"",
            "app_key_backend = \"tpm\"\nprivate_key_path = \"/etc/symbolon/github-app.pem\"",
        );
        let err = Config::parse(&src).unwrap_err();
        assert!(
            err.to_string().contains("private_key_path"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn config_file_backend_requires_private_key_path() {
        let src =
            KNOWN_GOOD_CONFIG.replace("private_key_path = \"/etc/symbolon/github-app.pem\"\n", "");
        let err = Config::parse(&src).unwrap_err();
        assert!(
            err.to_string().contains("private_key_path"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn config_file_backend_rejects_tpm_section() {
        let src =
            format!("{KNOWN_GOOD_CONFIG}\n[provider.github.tpm]\npersistent_handle = 0x81010001\n");
        let err = Config::parse(&src).unwrap_err();
        assert!(
            err.to_string().contains("[provider.github.tpm]"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn config_rejects_missing_app_key_backend() {
        let src = KNOWN_GOOD_CONFIG.replace("app_key_backend = \"file\"\n", "");
        assert!(Config::parse(&src).is_err());
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
    fn config_rejects_missing_static_key_file() {
        let src = KNOWN_GOOD_CONFIG.replace("static_key_file = \"/etc/symbolon/broker.key\"\n", "");
        assert!(toml::from_str::<Config>(&src).is_err());
    }

    #[test]
    fn log_level_warn_accepted() {
        let cfg: LoggingConfig = toml::from_str(r#"level = "warn""#).unwrap();
        assert_eq!(cfg.level, tracing::Level::WARN);
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
        let parsed = ClientsFile::parse(r#"{"clients":[]}"#).unwrap();
        assert!(parsed.clients.is_empty());
    }

    #[test]
    fn clients_one_entry_parses() {
        let json = r#"{
  "clients": [
    {
      "name": "dev-vm-1",
      "providers": ["github"],
      "enrolled_at": "2026-05-26T12:34:56Z",
      "note": null
    }
  ]
}"#;
        let parsed = ClientsFile::parse(json).unwrap();
        assert_eq!(parsed.clients.len(), 1);
        let c = &parsed.clients[0];
        assert_eq!(c.name, "dev-vm-1");
        assert_eq!(c.providers, vec![ProviderKind::Github]);
        // 2026-05-26T12:34:56Z in unix seconds: parsed via the same
        // RFC3339 adapter the wire uses.
        assert_eq!(
            c.enrolled_at,
            time::OffsetDateTime::parse(
                "2026-05-26T12:34:56Z",
                &time::format_description::well_known::Rfc3339,
            )
            .unwrap()
        );
        assert!(c.note.is_none());
    }

    #[test]
    fn clients_unknown_field_on_entry_rejected() {
        let json = r#"{
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
        assert!(ClientsFile::parse(json).is_err());
    }

    #[test]
    fn clients_ip_field_rejected_as_unknown() {
        // The schema does not carry a per-client `ip` field;
        // deny_unknown_fields rejects it.
        let json = r#"{
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
        assert!(ClientsFile::parse(json).is_err());
    }

    #[test]
    fn clients_unknown_top_level_field_rejected() {
        // Unknown top-level fields must surface the schema mismatch,
        // not be silently dropped.
        let json = r#"{"version":1,"clients":[]}"#;
        assert!(ClientsFile::parse(json).is_err());
    }
}
