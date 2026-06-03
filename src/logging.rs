//! Tracing-subscriber setup for the daemon, with a custom JSON event
//! formatter that emits the `ts` / `lvl` / `evt` schema PROTOCOLS.md
//! § "Logging schema" mandates (instead of `tracing-subscriber`'s
//! default `timestamp` / `level` field names).
//!
//! Info-and-below events go to stdout; warn and error go to stderr,
//! matching AGENTS.md invariant #13.

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

/// Emits one JSON object per event with `ts` (RFC 3339 UTC), `lvl`,
/// plus the event's fields. PROTOCOLS.md § "Logging schema" requires
/// these names; the default `tracing-subscriber::fmt::format::Json`
/// uses `timestamp` / `level`, so we roll our own.
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
