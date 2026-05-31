//! Binary entry: parse argv (daemon mode or CLI subcommand), set up
//! tracing for the daemon, hand off to [`gcb::daemon::run`] or
//! [`gcb::admin::cli_dispatch`].

use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use tracing::Level;
use tracing_subscriber::filter::{filter_fn, LevelFilter};
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

use gcb::admin::CliCommand;
use gcb::config::{self, LogLevel};

const DEFAULT_CONFIG_PATH: &str = "/etc/gcb/config.toml";

#[compio::main]
async fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse_argv(&argv) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("gcb: {msg}");
            eprintln!("usage: gcb [--config <path>] [<subcommand> ...]");
            eprintln!(
                "subcommands: status | list | github enroll <client> --ip <ip> [--note <text>]"
            );
            eprintln!("             github revoke <client> | github mint <client> <owner/repo>");
            eprintln!("             github selfcheck");
            return ExitCode::from(2);
        }
    };

    match parsed {
        Invocation::Daemon { config_path } => run_daemon(config_path).await,
        Invocation::Cli {
            config_path,
            command,
        } => run_cli(config_path, command).await,
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

enum Invocation {
    Daemon {
        config_path: PathBuf,
    },
    Cli {
        config_path: PathBuf,
        command: CliCommand,
    },
}

fn parse_argv(argv: &[String]) -> Result<Invocation, String> {
    let mut config_path: Option<PathBuf> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut i = 0;
    // First-pass: extract `--config` (which is a daemon/CLI common flag);
    // collect everything else positionally for the subcommand parser.
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
        } else {
            positional.push(arg.clone());
            i += 1;
        }
    }
    let config_path = config_path.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));

    if positional.is_empty() {
        return Ok(Invocation::Daemon { config_path });
    }

    let command = parse_subcommand(&positional)?;
    Ok(Invocation::Cli {
        config_path,
        command,
    })
}

fn parse_subcommand(positional: &[String]) -> Result<CliCommand, String> {
    let head = positional[0].as_str();
    let rest = &positional[1..];
    match head {
        "status" => {
            if !rest.is_empty() {
                return Err("`status` takes no arguments".to_string());
            }
            Ok(CliCommand::Status)
        }
        "list" => {
            if !rest.is_empty() {
                return Err("`list` takes no arguments".to_string());
            }
            Ok(CliCommand::List)
        }
        "github" => parse_github_subcommand(rest),
        other => Err(format!("unknown subcommand: {other}")),
    }
}

fn parse_github_subcommand(rest: &[String]) -> Result<CliCommand, String> {
    let head = rest
        .first()
        .ok_or("`github` requires a subcommand")?
        .as_str();
    let rest = &rest[1..];
    match head {
        "enroll" => parse_github_enroll(rest),
        "revoke" => {
            if rest.len() != 1 {
                return Err("`github revoke` requires <client>".to_string());
            }
            Ok(CliCommand::GithubRevoke {
                client: rest[0].clone(),
            })
        }
        "mint" => {
            if rest.len() != 2 {
                return Err("`github mint` requires <client> <owner/repo>".to_string());
            }
            Ok(CliCommand::GithubMint {
                client: rest[0].clone(),
                path: rest[1].clone(),
            })
        }
        "selfcheck" => {
            if !rest.is_empty() {
                return Err("`github selfcheck` takes no arguments".to_string());
            }
            Ok(CliCommand::GithubSelfcheck)
        }
        other => Err(format!("unknown github subcommand: {other}")),
    }
}

fn parse_github_enroll(rest: &[String]) -> Result<CliCommand, String> {
    let client = rest
        .first()
        .ok_or("`github enroll` requires <client>")?
        .clone();
    if client.starts_with("--") {
        return Err("missing <client> before flags".to_string());
    }
    let mut ip: Option<IpAddr> = None;
    let mut note: Option<String> = None;
    let mut i = 1;
    while i < rest.len() {
        let arg = &rest[i];
        if arg == "--ip" {
            let val = rest.get(i + 1).ok_or("--ip requires a value")?;
            ip = Some(val.parse().map_err(|_| format!("invalid IP: {val}"))?);
            i += 2;
        } else if let Some(val) = arg.strip_prefix("--ip=") {
            ip = Some(val.parse().map_err(|_| format!("invalid IP: {val}"))?);
            i += 1;
        } else if arg == "--note" {
            let val = rest.get(i + 1).ok_or("--note requires a value")?;
            note = Some(val.clone());
            i += 2;
        } else if let Some(val) = arg.strip_prefix("--note=") {
            note = Some(val.to_string());
            i += 1;
        } else {
            return Err(format!("unexpected argument to enroll: {arg}"));
        }
    }
    let ip = ip.ok_or("`github enroll` requires --ip <ip>")?;
    Ok(CliCommand::GithubEnroll { client, ip, note })
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
