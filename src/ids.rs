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
use serde::{Deserialize, Serialize};

/// Broker-side per-request correlation id. Generated once per
/// inbound TCP connection (or once per admin UDS request) at the
/// edge; threaded into every log event and outbound provider call.
#[derive(Debug, Clone, PartialEq, Eq, Hash, AsRef, Display, From, Serialize, Deserialize)]
#[as_ref(str)]
#[from(String)]
#[serde(transparent)]
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

impl From<&str> for ReqId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Per-outbound-HTTPS-call correlation id. Generated inside the
/// provider's `with_breadcrumbs` wrapper, one per call. Distinct
/// from [`ReqId`] so a swap at the breadcrumb logging site is a
/// compile error.
#[derive(Debug, Clone, PartialEq, Eq, Hash, AsRef, Display, From, Serialize, Deserialize)]
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

impl From<&str> for OutReqId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
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
    fn new_generates_distinct_ids() {
        let a = ReqId::new();
        let b = ReqId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn display_emits_inner_string() {
        let r = ReqId::from("0123456789ABCDEFGHJKMNPQRS".to_string());
        assert_eq!(r.to_string(), "0123456789ABCDEFGHJKMNPQRS");
    }

    #[test]
    fn serde_transparent_serialises_as_bare_string() {
        let r = ReqId::from("abc".to_string());
        assert_eq!(serde_json::to_string(&r).unwrap(), "\"abc\"");
        let back: ReqId = serde_json::from_str("\"abc\"").unwrap();
        assert_eq!(back, r);
    }
}
