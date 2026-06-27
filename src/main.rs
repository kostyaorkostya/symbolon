//! Binary entry: parse argv (daemon mode or CLI subcommand), set up
//! tracing for the daemon, hand off to [`symbolon::run_daemon`] or
//! [`symbolon::cli_dispatch`].

use std::path::PathBuf;
use std::process::ExitCode;

use argh::FromArgs;
use hex::FromHex;

use symbolon::CliCommand;
use symbolon::EventKind;
use symbolon::Psk;

const DEFAULT_CONFIG_PATH: &str = "/etc/symbolon/config.toml";

#[compio::main]
async fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let cmd_name = argv.first().map(String::as_str).unwrap_or("symbolon");
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
        Subcommand::Github(g) => {
            let cmd = match g.cmd {
                GithubSub::Enroll(a) => {
                    let psk = match a.psk.as_deref() {
                        Some(hex) => match Psk::from_hex(hex) {
                            Ok(p) => p,
                            Err(e) => {
                                eprintln!("symbolon: --psk invalid: {e}");
                                return ExitCode::from(2);
                            }
                        },
                        None => {
                            let mut bytes = [0u8; 32];
                            if let Err(e) = getrandom::fill(&mut bytes) {
                                eprintln!("symbolon: failed to read OS RNG: {e}");
                                return ExitCode::from(1);
                            }
                            Psk::from(bytes)
                        }
                    };
                    CliCommand::GithubEnroll {
                        client: a.client,
                        note: a.note,
                        psk,
                    }
                }
                GithubSub::Revoke(a) => CliCommand::GithubRevoke { client: a.client },
                GithubSub::Mint(a) => CliCommand::GithubMint {
                    client: a.client,
                    path: a.repo,
                },
                GithubSub::Selfcheck(_) => CliCommand::GithubSelfcheck,
            };
            run_cli(config_path, cmd).await
        }
    }
}

async fn run_daemon(config_path: PathBuf) -> ExitCode {
    let cfg = match symbolon::load_config(&config_path).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("symbolon: failed to load {}: {e}", config_path.display());
            return ExitCode::from(1);
        }
    };
    symbolon::setup_tracing(cfg.logging.level);

    // Belt-and-suspenders anti-swap hardening. Called BEFORE
    // Service::prepare so the PEM key load + CpuWorker stack
    // allocation both fault into locked pages. Primary defence
    // is operator-disabled swap on the broker host — see
    // docs/INSTALL.md. Required-mode failure is fatal.
    if let Err(e) = symbolon::mlock_apply(cfg.security.mlock) {
        tracing::error!(evt = %EventKind::MlockRequiredFailed, error = %e);
        return ExitCode::from(1);
    }

    let shutdown = compio::runtime::CancelToken::new();
    let shutdown_watcher = match symbolon::spawn_shutdown_watcher(shutdown.clone()) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(evt = %EventKind::SignalRegistrationFailed, signal = "SIGTERM/SIGINT", error = %e);
            return ExitCode::from(1);
        }
    };

    let service = match symbolon::Service::prepare(&cfg, &config_path, shutdown.clone()).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %symbolon::ErrorChain(&e), "prepare failed");
            return ExitCode::from(1);
        }
    };

    let handle = service.handle();
    let sighup = match symbolon::spawn_sighup_handler(
        move || {
            let h = handle.clone();
            async move { h.reload_clients().await }
        },
        shutdown.clone(),
    ) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(evt = %EventKind::SignalRegistrationFailed, signal = "SIGHUP", error = %e);
            return ExitCode::from(1);
        }
    };

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
    symbolon::ready_notify(cfg.runtime.pidfile.as_deref()).await;
    tracing::info!(evt = %EventKind::Ready, pid = std::process::id());

    let run_result = service.run().await;
    let signal_name = shutdown_watcher.await.unwrap_or("SIGTERM");
    let _ = sighup.await;

    match run_result {
        Ok(stats) => {
            tracing::info!(
                evt = %EventKind::Shutdown,
                signal = signal_name,
                inflight_drained = stats.inflight_drained,
                drain_ms = stats.drain_ms,
                drain_complete = stats.drain_complete,
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!(evt = %EventKind::RunFailed, signal = signal_name, error = %e);
            ExitCode::from(1)
        }
    }
}

async fn run_cli(config_path: PathBuf, command: CliCommand) -> ExitCode {
    let cfg = match symbolon::load_config(&config_path).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("symbolon: failed to load {}: {e}", config_path.display());
            return ExitCode::from(1);
        }
    };
    match symbolon::cli_dispatch(&cfg.admin.socket_path, command).await {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("symbolon: {e}");
            ExitCode::from(1)
        }
    }
}

/// symbolon — git credentials broker.
#[derive(FromArgs)]
struct Args {
    /// path to config.toml (default /etc/symbolon/config.toml)
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

/// run as the broker daemon
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

/// enroll a client; prints the 64-hex PSK to stdout for the operator
/// to install on the client side. PSK is freshly generated locally by
/// default; supply your own with `--psk <64-hex>` (useful for backup
/// restore, key rotation, or deterministic test setups).
#[derive(FromArgs)]
#[argh(subcommand, name = "enroll")]
struct EnrollArgs {
    #[argh(positional)]
    client: String,
    /// free-form note
    #[argh(option)]
    note: Option<String>,
    /// optional pre-generated 64-char hex PSK; if omitted the CLI
    /// reads 32 fresh bytes from the OS RNG
    #[argh(option)]
    psk: Option<String>,
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
