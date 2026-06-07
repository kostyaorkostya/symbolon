//! Tracing-subscriber setup for the daemon. Emits structured JSON
//! to stdout (`info` and below) and stderr (`warn`/`error`), using
//! `tracing-subscriber`'s built-in JSON formatter. Matches AGENTS.md
//! invariant #13 ("structured JSON to stdout").
//!
//! Field names follow `tracing-subscriber`'s defaults — `timestamp`,
//! `level`, `target`, `fields` (or flattened user fields when
//! `flatten_event(true)` is set). User-added fields like `evt`,
//! `req_id`, etc. pass through as top-level JSON keys. See
//! `docs/PROTOCOLS.md` § "Logging schema" for the full event
//! catalog.

use tracing::Level;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::{LevelFilter, filter_fn};
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::LogLevel;

pub fn setup_tracing(level: LogLevel) {
    let level_filter: LevelFilter = match level {
        LogLevel::Trace => LevelFilter::TRACE,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Error => LevelFilter::ERROR,
    };

    let stdout_layer = fmt::layer()
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_target(false)
        .with_writer(std::io::stdout)
        .with_filter(filter_fn(|m| {
            !matches!(*m.level(), Level::WARN | Level::ERROR)
        }));
    let stderr_layer = fmt::layer()
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_target(false)
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
    fn log_event_passes_through_user_fields() {
        use tracing::subscriber::with_default;
        let buf = CaptureWriter::default();
        let layer = fmt::layer()
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .with_span_list(false)
            .with_target(false)
            .with_writer(buf.clone());
        let subscriber = tracing_subscriber::registry().with(layer);
        with_default(subscriber, || {
            tracing::info!(evt = "test", req_id = "abc123", k = 7);
        });
        let bytes = buf.0.lock().unwrap().clone();
        let line = std::str::from_utf8(&bytes).unwrap().trim();
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        // Built-in JSON formatter uses `timestamp` and `level`.
        assert!(v.get("timestamp").is_some(), "missing timestamp: {line}");
        assert_eq!(v["level"], "INFO");
        // User-added fields are flattened to top-level keys.
        assert_eq!(v["evt"], "test");
        assert_eq!(v["req_id"], "abc123");
        assert_eq!(v["k"], 7);
    }
}
