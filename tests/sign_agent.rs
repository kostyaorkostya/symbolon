//! Direct end-to-end test of the `file`-backend signing agent: spawn
//! the real `symbolon __sign-agent` subprocess (under its actual
//! Landlock + seccomp self-sandbox), self-check it, and sign.
//!
//! The determinism of RSASSA-PKCS1-v1_5 gives a strong assertion: the
//! agent's JWT MUST byte-equal an in-process sign of the same claims
//! with the same key. If the agent's seccomp allowlist were missing a
//! syscall the sign path needs, the subprocess would be killed and
//! `self_check` / `sign` would surface `BackendDead` instead.

use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

use symbolon::{AgentSpawn, JwtClaims, JwtSigningKey, SpawnedBackend};

fn fixture_pem_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test_app_key.pem")
}

fn symbolon_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_symbolon"))
}

fn claims() -> JwtClaims {
    JwtClaims::new(
        UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        "Iv1.agent-test",
    )
}

#[compio::test]
async fn agent_signs_and_self_checks() {
    let backend =
        Box::new(AgentSpawn::spawn(&symbolon_exe(), &fixture_pem_path()).expect("spawn agent"))
            .into_backend();

    // Ping/Pong: the subprocess survived its self-sandbox and serves.
    backend.self_check().await.expect("agent self_check");

    let jwt = backend.sign(&claims()).await.expect("agent sign");

    // RS256 is deterministic: the agent's token must match an
    // in-process sign of the same (claims, key).
    let pem = std::fs::read(fixture_pem_path()).unwrap();
    let key = JwtSigningKey::from_pem(&pem).unwrap();
    let expected = key.sign_rs256(&claims()).unwrap();
    assert_eq!(
        jwt, expected,
        "agent JWT must match deterministic in-process sign"
    );
    assert_eq!(jwt.split('.').count(), 3);
}

#[compio::test]
async fn agent_dies_cleanly_on_drop() {
    // Dropping the backend closes the socketpair; the agent sees EOF
    // and exits. This must not hang (the actor thread joins on Drop).
    let backend =
        Box::new(AgentSpawn::spawn(&symbolon_exe(), &fixture_pem_path()).expect("spawn agent"))
            .into_backend();
    backend.self_check().await.expect("agent self_check");
    drop(backend); // joins the io thread, which reaps the child
}
