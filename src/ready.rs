//! Report daemon readiness to the surrounding init system. Lives
//! *outside* the daemon so daemon code stays init-system-agnostic.
//!
//! Under systemd the idiomatic convention is `Type=notify` with no
//! pidfile (the systemd man pages discourage pidfiles when notify
//! is available). The pidfile path here is for OpenRC's
//! `command_background=yes` + `pidfile=...` convention.

use std::path::Path;

use sd_notify::NotifyState;

use crate::events::EventKind;

/// Call once main has decided the daemon is ready: config loaded,
/// key in memory, sockets bound, sandbox applied, selfcheck done.
///
/// Sends `READY=1` to `$NOTIFY_SOCKET` if set (no-op outside
/// systemd), and writes the current pid to `pidfile` if provided.
/// The pidfile write goes through `atomic_write` so a concurrent
/// reader (init system supervisor) never observes an empty or
/// partial file.
pub async fn notify(pidfile: Option<&Path>) {
    let _ = sd_notify::notify(&[NotifyState::Ready]);
    if let Some(path) = pidfile {
        let contents = format!("{}\n", std::process::id()).into_bytes();
        if let Err(e) = crate::admin::atomic_write(path, contents, 0o644).await {
            tracing::warn!(evt = %EventKind::ReadyPidfileWriteFailed, path = %path.display(), error = %e);
        }
    }
}
