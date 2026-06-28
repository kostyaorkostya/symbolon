//! Typed correlation IDs.
//!
//! `ReqId` is the broker-side correlation ID generated once per
//! inbound connection (or once per admin request). `OutReqId` is
//! generated once per outbound HTTPS call to the upstream provider.
//! Both are ULID strings under the hood, but threading them through
//! the codebase as distinct types makes a wrong-id swap a
//! compile-time error rather than a runtime correlation bug that
//! would be near-impossible to spot in logs.
//!
//! See `docs/PROTOCOLS.md` § "Logging schema" for the wire-visible
//! field names these types are serialised as.

use derive_more::{AsRef, Display, From};
use serde::Serialize;

/// Broker-side per-request correlation id. Generated once per
/// inbound TCP connection (or once per admin UDS request) at the
/// edge; threaded into every log event and outbound provider call.
#[derive(Debug, AsRef, Display, From)]
#[as_ref(str)]
#[from(String)]
pub struct ReqId(String);

impl ReqId {
    /// Generate a fresh ULID-based request id.
    // `Default` deliberately NOT impl'd: minting a fresh ULID on
    // `Default::default()` is non-pure and surprises generic callers
    // that expect Default to be cheap and side-effect-free (POLA).
    // Every call site uses `ReqId::new()` explicitly.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(ulid::Ulid::new().to_string())
    }
}

/// Per-outbound-HTTPS-call correlation id. Generated inside the
/// provider's `with_breadcrumbs` wrapper, one per call. Distinct
/// from [`ReqId`] so a swap at the breadcrumb logging site is a
/// compile error.
#[derive(Debug, Clone, AsRef, Display, From, Serialize)]
#[as_ref(str)]
#[from(String)]
#[serde(transparent)]
pub struct OutReqId(String);

impl OutReqId {
    // Same `Default`-not-impl'd rationale as `ReqId::new` above.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(ulid::Ulid::new().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn req_id_and_out_req_id_are_distinct_types() {
        // Compile-time check: a fn taking ReqId rejects OutReqId.
        fn takes_req_id(_: &ReqId) {}
        let r = ReqId::new();
        takes_req_id(&r);
        // The line `takes_req_id(&OutReqId::new())` would fail to
        // compile, which is the whole point.
    }

    #[test]
    fn display_emits_inner_string() {
        let r = ReqId::from("0123456789ABCDEFGHJKMNPQRS".to_string());
        assert_eq!(r.to_string(), "0123456789ABCDEFGHJKMNPQRS");
    }
}
