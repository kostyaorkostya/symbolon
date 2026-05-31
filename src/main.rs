//! Binary entry: parse `--config`, install the JSON tracing
//! subscriber, then hand off to [`gcb::daemon::run`].
//!
//! This session only wires the daemon subcommand. Operator
//! subcommands (`gcb status`, `gcb github enroll`, etc.) land
//! alongside `admin.rs`; for now they print "not implemented" and
//! exit 2.

use std::path::PathBuf;
use std::process::ExitCode;

use tracing::Level;
use tracing_subscriber::filter::{filter_fn, LevelFilter};
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

use gcb::config::{self, LogLevel};

const DEFAULT_CONFIG_PATH: &str = "/etc/gcb/config.toml";

#[compio::main]
async fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse_argv(&argv) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("gcb: {msg}");
            eprintln!("usage: gcb [--config <path>]");
            return ExitCode::from(2);
        }
    };

    match parsed {
        Invocation::Daemon { config_path } => run_daemon(config_path).await,
        Invocation::Subcommand(name) => {
            eprintln!(
                "gcb: subcommand `{name}` is not implemented in this build; only the daemon entrypoint is wired."
            );
            ExitCode::from(2)
        }
    }
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

    if let Err(e) = gcb::daemon::run(&cfg).await {
        tracing::error!(error = %e, "daemon exiting");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

enum Invocation {
    Daemon { config_path: PathBuf },
    Subcommand(String),
}

fn parse_argv(argv: &[String]) -> Result<Invocation, String> {
    let mut config_path: Option<PathBuf> = None;
    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        if let Some(rest) = arg.strip_prefix("--config=") {
            config_path = Some(PathBuf::from(rest));
            i += 1;
        } else if arg == "--config" {
            let next = argv
                .get(i + 1)
                .ok_or_else(|| "--config requires a path argument".to_string())?;
            config_path = Some(PathBuf::from(next));
            i += 2;
        } else if arg.starts_with("--") {
            return Err(format!("unknown flag: {arg}"));
        } else {
            return Ok(Invocation::Subcommand(arg.clone()));
        }
    }
    Ok(Invocation::Daemon {
        config_path: config_path.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH)),
    })
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
        .json()
        .with_writer(std::io::stdout)
        .with_filter(filter_fn(|m| {
            !matches!(*m.level(), Level::WARN | Level::ERROR)
        }));
    let stderr_layer = fmt::layer()
        .json()
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
