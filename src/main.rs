//! Binary entry: parse argv (daemon mode or CLI subcommand), set up
//! tracing for the daemon, hand off to [`gcb::daemon::run`] or
//! [`gcb::admin::cli_dispatch`].

use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use argh::FromArgs;
use tracing::Level;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::{LevelFilter, filter_fn};
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use gcb::admin::CliCommand;
use gcb::config::{self, LogLevel};

const DEFAULT_CONFIG_PATH: &str = "/etc/gcb/config.toml";

#[compio::main]
async fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let cmd_name = argv.first().map(String::as_str).unwrap_or("gcb");
    let mut rest: Vec<&str> = argv.iter().skip(1).map(String::as_str).collect();
    // argh requires a subcommand; preserve the documented bare-`gcb`
    // daemon contract by synthesising `daemon` when only --config (or
    // nothing) is present. Anything else falls through to argh so it
    // can error on unknown flags/subcommands as usual.
    if no_subcommand_present(&rest) {
        rest.push("daemon");
    }
    let args = match Args::from_args(&[cmd_name], &rest) {
        Ok(a) => a,
        Err(early) => match early.status {
            Ok(()) => {
                print!("{}", early.output);
                return ExitCode::SUCCESS;
            }
            Err(()) => {
                eprint!("{}", early.output);
                return ExitCode::from(2);
            }
        },
    };

    let config_path = args
        .config
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));

    match args.cmd {
        Subcommand::Daemon(_) => run_daemon(config_path).await,
        Subcommand::Status(_) => run_cli(config_path, CliCommand::Status).await,
        Subcommand::List(_) => run_cli(config_path, CliCommand::List).await,
        Subcommand::Github(g) => run_cli(config_path, github_to_cli(g)).await,
    }
}

fn no_subcommand_present(args: &[&str]) -> bool {
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if a == "--config" {
            // Skip the flag + its value; if missing, let argh produce
            // the error rather than silently injecting `daemon`.
            if i + 1 >= args.len() {
                return false;
            }
            i += 2;
        } else if a.starts_with("--config=") {
            i += 1;
        } else {
            return false;
        }
    }
    true
}

async fn run_daemon(config_path: PathBuf) -> ExitCode {
    let cfg = match config::load_config(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("gcb: {e}");
            return ExitCode::from(1);
        }
    };
    setup_tracing(cfg.logging.level);

    if let Err(e) = gcb::daemon::run(&cfg, &config_path).await {
        tracing::error!(error = %e, "daemon exiting");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

async fn run_cli(config_path: PathBuf, command: CliCommand) -> ExitCode {
    let cfg = match config::load_config(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("gcb: {e}");
            return ExitCode::from(1);
        }
    };
    match gcb::admin::cli_dispatch(&cfg.admin.socket_path, command).await {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("gcb: {e}");
            ExitCode::from(1)
        }
    }
}

/// gcb — git credentials broker. With no subcommand, runs as a daemon.
#[derive(FromArgs)]
struct Args {
    /// path to config.toml (default /etc/gcb/config.toml)
    #[argh(option)]
    config: Option<PathBuf>,

    #[argh(subcommand)]
    cmd: Subcommand,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Subcommand {
    Daemon(DaemonArgs),
    Status(StatusArgs),
    List(ListArgs),
    Github(GithubArgs),
}

/// run as the broker daemon (default when no subcommand is given)
#[derive(FromArgs)]
#[argh(subcommand, name = "daemon")]
struct DaemonArgs {}

/// show daemon status
#[derive(FromArgs)]
#[argh(subcommand, name = "status")]
struct StatusArgs {}

/// list enrolled clients
#[derive(FromArgs)]
#[argh(subcommand, name = "list")]
struct ListArgs {}

/// GitHub provider commands
#[derive(FromArgs)]
#[argh(subcommand, name = "github")]
struct GithubArgs {
    #[argh(subcommand)]
    cmd: GithubSub,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum GithubSub {
    Enroll(EnrollArgs),
    Revoke(RevokeArgs),
    Mint(MintArgs),
    Selfcheck(SelfcheckArgs),
}

/// enroll a client by source IP
#[derive(FromArgs)]
#[argh(subcommand, name = "enroll")]
struct EnrollArgs {
    #[argh(positional)]
    client: String,
    /// source IP address (attested upstream)
    #[argh(option)]
    ip: IpAddr,
    /// free-form note
    #[argh(option)]
    note: Option<String>,
}

/// revoke an enrolled client
#[derive(FromArgs)]
#[argh(subcommand, name = "revoke")]
struct RevokeArgs {
    #[argh(positional)]
    client: String,
}

/// mint a token for <client> <owner/repo>
#[derive(FromArgs)]
#[argh(subcommand, name = "mint")]
struct MintArgs {
    #[argh(positional)]
    client: String,
    #[argh(positional)]
    repo: String,
}

/// run provider self-check
#[derive(FromArgs)]
#[argh(subcommand, name = "selfcheck")]
struct SelfcheckArgs {}

fn github_to_cli(g: GithubArgs) -> CliCommand {
    match g.cmd {
        GithubSub::Enroll(a) => CliCommand::GithubEnroll {
            client: a.client,
            ip: a.ip,
            note: a.note,
        },
        GithubSub::Revoke(a) => CliCommand::GithubRevoke { client: a.client },
        GithubSub::Mint(a) => CliCommand::GithubMint {
            client: a.client,
            path: a.repo,
        },
        GithubSub::Selfcheck(_) => CliCommand::GithubSelfcheck,
    }
}

fn setup_tracing(level: LogLevel) {
    let level_filter: LevelFilter = match level {
        LogLevel::Trace => LevelFilter::TRACE,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Error => LevelFilter::ERROR,
    };

    let stdout_layer = fmt::layer()
        .event_format(GcbJsonFormatter)
        .fmt_fields(NopFieldsFormatter)
        .with_writer(std::io::stdout)
        .with_filter(filter_fn(|m| {
            !matches!(*m.level(), Level::WARN | Level::ERROR)
        }));
    let stderr_layer = fmt::layer()
        .event_format(GcbJsonFormatter)
        .fmt_fields(NopFieldsFormatter)
        .with_writer(std::io::stderr)
        .with_filter(filter_fn(|m| {
            matches!(*m.level(), Level::WARN | Level::ERROR)
        }));

    tracing_subscriber::registry()
        .with(level_filter)
        .with(stdout_layer)
        .with(stderr_layer)
        .init();
}

/// Custom event formatter that emits the JSON object PROTOCOLS.md
/// § "Logging schema" requires: `ts` (not `timestamp`), `lvl` (not
/// `level`), plus event fields. One line per record.
struct GcbJsonFormatter;

impl<S, N> tracing_subscriber::fmt::FormatEvent<S, N> for GcbJsonFormatter
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> tracing_subscriber::fmt::FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let mut map = serde_json::Map::new();

        let ts = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        map.insert("ts".to_string(), serde_json::Value::String(ts));

        let lvl = match *event.metadata().level() {
            Level::TRACE => "trace",
            Level::DEBUG => "debug",
            Level::INFO => "info",
            Level::WARN => "warn",
            Level::ERROR => "error",
        };
        map.insert("lvl".to_string(), serde_json::Value::String(lvl.into()));

        let mut visitor = JsonVisitor(&mut map);
        event.record(&mut visitor);

        let line =
            serde_json::to_string(&serde_json::Value::Object(map)).map_err(|_| std::fmt::Error)?;
        writeln!(writer, "{line}")
    }
}

struct JsonVisitor<'a>(&'a mut serde_json::Map<String, serde_json::Value>);

impl tracing::field::Visit for JsonVisitor<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(
            field.name().to_string(),
            serde_json::Value::String(value.to_string()),
        );
    }
    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.0.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }
    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.0
            .insert(field.name().to_string(), serde_json::Value::Bool(value));
    }
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        if let Some(n) = serde_json::Number::from_f64(value) {
            self.0
                .insert(field.name().to_string(), serde_json::Value::Number(n));
        }
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(
            field.name().to_string(),
            serde_json::Value::String(format!("{value:?}")),
        );
    }
}

/// `fmt::Layer` requires a `FormatFields` impl alongside the event
/// formatter. We do all field serialisation inside `GcbJsonFormatter`,
/// so this one is a no-op.
struct NopFieldsFormatter;

impl<'a> tracing_subscriber::fmt::FormatFields<'a> for NopFieldsFormatter {
    fn format_fields<R: tracing_subscriber::field::RecordFields>(
        &self,
        _writer: tracing_subscriber::fmt::format::Writer<'_>,
        _fields: R,
    ) -> std::fmt::Result {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureWriterHandle;
        fn make_writer(&'a self) -> Self::Writer {
            CaptureWriterHandle(self.0.clone())
        }
    }

    struct CaptureWriterHandle(Arc<Mutex<Vec<u8>>>);

    impl io::Write for CaptureWriterHandle {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn log_event_renames_fields_ts_and_lvl() {
        use tracing::subscriber::with_default;
        let buf = CaptureWriter::default();
        let layer = fmt::layer()
            .event_format(GcbJsonFormatter)
            .fmt_fields(NopFieldsFormatter)
            .with_writer(buf.clone());
        let subscriber = tracing_subscriber::registry().with(layer);
        with_default(subscriber, || {
            tracing::info!(evt = "test", req_id = "abc123", k = 7);
        });
        let bytes = buf.0.lock().unwrap().clone();
        let line = std::str::from_utf8(&bytes).unwrap().trim();
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(v.get("ts").and_then(|s| s.as_str()).unwrap().ends_with('Z'));
        assert_eq!(v["lvl"], "info");
        assert_eq!(v["evt"], "test");
        assert_eq!(v["req_id"], "abc123");
        assert_eq!(v["k"], 7);
        assert!(v.get("timestamp").is_none(), "should not emit `timestamp`");
        assert!(v.get("level").is_none(), "should not emit `level`");
    }
}
