//! Binary entry: parse argv (daemon mode or CLI subcommand), set up
//! tracing for the daemon, hand off to [`gcb::run_daemon`] or
//! [`gcb::cli_dispatch`].

use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use argh::FromArgs;

use gcb::CliCommand;

const DEFAULT_CONFIG_PATH: &str = "/etc/gcb/config.toml";

#[compio::main]
async fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let cmd_name = argv.first().map(String::as_str).unwrap_or("gcb");
    let rest: Vec<&str> = argv.iter().skip(1).map(String::as_str).collect();
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

async fn run_daemon(config_path: PathBuf) -> ExitCode {
    let cfg = match gcb::load_config(&config_path).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("gcb: {e}");
            return ExitCode::from(1);
        }
    };
    gcb::setup_tracing(cfg.logging.level);

    let shutdown = compio::runtime::CancelToken::new();
    let shutdown_watcher = gcb::spawn_shutdown_watcher(shutdown.clone());

    let service = match gcb::Service::prepare(&cfg, &config_path, shutdown.clone()).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "prepare failed");
            return ExitCode::from(1);
        }
    };

    let sighup = gcb::spawn_sighup_handler(
        service.state_handle(),
        cfg.clients.file.clone(),
        shutdown.clone(),
    );

    service.selfcheck().await;

    // Lifecycle order: Service::prepare above already loaded
    // config, bound BOTH Unix sockets (the kernel begins queueing
    // incoming connections at bind time), applied the sandbox, and
    // built providers. selfcheck just hit GitHub via HTTPS.
    //
    // Now we tell the init system we're ready. `service.run` below
    // starts the accept loop; any connections the kernel queued
    // between this notification and the first `accept()` syscall
    // (microseconds) are processed normally.
    gcb::ready_notify(cfg.runtime.pidfile.as_deref()).await;
    tracing::info!(evt = "ready", pid = std::process::id());

    let run_result = service.run().await;
    let signal_name = shutdown_watcher.await.unwrap_or("SIGTERM");
    let _ = sighup.await;

    match run_result {
        Ok(stats) => {
            tracing::info!(
                evt = "shutdown",
                signal = signal_name,
                inflight_drained = stats.inflight_drained,
                drain_ms = stats.drain_ms,
                drain_complete = stats.drain_complete,
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!(evt = "run_failed", signal = signal_name, error = %e);
            ExitCode::from(1)
        }
    }
}

async fn run_cli(config_path: PathBuf, command: CliCommand) -> ExitCode {
    let cfg = match gcb::load_config(&config_path).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("gcb: {e}");
            return ExitCode::from(1);
        }
    };
    match gcb::cli_dispatch(&cfg.admin.socket_path, command).await {
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
