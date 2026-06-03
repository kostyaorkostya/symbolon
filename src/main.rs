//! Binary entry: parse argv (daemon mode or CLI subcommand), set up
//! tracing for the daemon, hand off to [`gcb::daemon::run`] or
//! [`gcb::admin::cli_dispatch`].

use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use argh::FromArgs;

use gcb::admin::CliCommand;
use gcb::config;

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
    gcb::logging::setup_tracing(cfg.logging.level);

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
