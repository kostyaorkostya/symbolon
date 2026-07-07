//! Admin socket end-to-end tests: send JSON op, observe response.

mod common;

use std::os::unix::fs::PermissionsExt;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{
    CLIENT_ID, OWNER, REPO, TOKEN, admin_request, mount_mint_ok, mount_repo_ok, spawn_daemon,
    test_broker_pub, unique_paths_full, write_clients_json, write_psks_file,
};

#[compio::test]
async fn admin_status_reports_uptime_and_provider_count() {
    let paths = unique_paths_full();
    write_clients_json(&paths.clients, &[]);
    let server = MockServer::start().await;
    spawn_daemon(&paths, server.uri()).await;

    let resp = admin_request(&paths.admin, serde_json::json!({"op": "status"})).await;
    assert_eq!(resp["ok"], serde_json::json!(true));
    assert_eq!(resp["client_count"], 0);
    assert_eq!(resp["providers"], serde_json::json!(["github"]));
}

#[compio::test]
async fn admin_pubkey_returns_broker_public_key() {
    let paths = unique_paths_full();
    write_clients_json(&paths.clients, &[]);
    let server = MockServer::start().await;
    spawn_daemon(&paths, server.uri()).await;

    let resp = admin_request(&paths.admin, serde_json::json!({"op": "pubkey"})).await;
    assert_eq!(resp["ok"], serde_json::json!(true));
    // The daemon derives the public key from the same fixed test
    // private key `common` wrote to disk — assert the exact hex.
    assert_eq!(
        resp["broker_public_key"],
        serde_json::json!(test_broker_pub().to_string())
    );
}

#[compio::test]
async fn admin_list_initially_empty() {
    let paths = unique_paths_full();
    write_clients_json(&paths.clients, &[]);
    let server = MockServer::start().await;
    spawn_daemon(&paths, server.uri()).await;

    let resp = admin_request(&paths.admin, serde_json::json!({"op": "list"})).await;
    assert_eq!(resp["ok"], serde_json::json!(true));
    assert!(resp["clients"].as_array().unwrap().is_empty());
}

/// A fixed all-`0xCD` PSK that several tests use for enroll requests.
/// On the admin wire it serialises as a JSON array of 32 numbers
/// (the default for `[u8; 32]`); on disk it lands as the matching
/// 64-char hex string `TEST_PSK_HEX`.
const TEST_PSK: [u8; 32] = [0xCD; 32];
const TEST_PSK_HEX: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

#[compio::test]
async fn admin_enroll_persists_to_clients_json_and_psk_file() {
    let paths = unique_paths_full();
    write_clients_json(&paths.clients, &[]);
    let server = MockServer::start().await;
    spawn_daemon(&paths, server.uri()).await;

    let resp = admin_request(
        &paths.admin,
        serde_json::json!({
            "op": "enroll",
            "provider": "github",
            "client": "vm-1",
            "note": null,
            "psk": TEST_PSK,
        }),
    )
    .await;
    assert_eq!(resp["ok"], serde_json::json!(true), "got: {resp:?}");

    let psk_text = std::fs::read_to_string(&paths.psks).unwrap();
    assert!(
        psk_text.contains(&format!("vm-1:{TEST_PSK_HEX}")),
        "psk file missing entry: {psk_text:?}"
    );
    let psk_mode = std::fs::metadata(&paths.psks).unwrap().permissions().mode() & 0o777;
    assert_eq!(psk_mode, 0o600);

    let clients_text = std::fs::read_to_string(&paths.clients).unwrap();
    assert!(clients_text.contains("\"name\": \"vm-1\""));
    assert!(!clients_text.contains("\"ip\""));
    let cl_mode = std::fs::metadata(&paths.clients)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(cl_mode, 0o640);

    let listed = admin_request(&paths.admin, serde_json::json!({"op": "list"})).await;
    assert_eq!(listed["clients"].as_array().unwrap().len(), 1);
}

#[compio::test]
async fn admin_enroll_appends_without_clobbering_existing() {
    let paths = unique_paths_full();
    write_clients_json(&paths.clients, &["vm-0"]);
    write_psks_file(&paths.psks, &[("vm-0", [0x01; 32])]);
    let server = MockServer::start().await;
    spawn_daemon(&paths, server.uri()).await;

    let resp = admin_request(
        &paths.admin,
        serde_json::json!({
            "op": "enroll",
            "provider": "github",
            "client": "vm-1",
            "note": null,
            "psk": TEST_PSK,
        }),
    )
    .await;
    assert_eq!(resp["ok"], serde_json::json!(true));

    let psk_text = std::fs::read_to_string(&paths.psks).unwrap();
    assert!(
        psk_text.contains("vm-0:0101"),
        "lost pre-existing entry: {psk_text}"
    );
    assert!(psk_text.contains("vm-1:"), "missing new entry: {psk_text}");
}

#[compio::test]
async fn admin_enroll_rejects_duplicate_client_name() {
    let paths = unique_paths_full();
    write_clients_json(&paths.clients, &["vm-1"]);
    write_psks_file(&paths.psks, &[("vm-1", [0x02; 32])]);
    let server = MockServer::start().await;
    spawn_daemon(&paths, server.uri()).await;

    let resp = admin_request(
        &paths.admin,
        serde_json::json!({
            "op": "enroll",
            "provider": "github",
            "client": "vm-1",
            "note": null,
            "psk": TEST_PSK,
        }),
    )
    .await;
    assert_eq!(resp["ok"], serde_json::json!(false));
    assert!(
        resp["error"]
            .as_str()
            .unwrap_or("")
            .contains("already enrolled"),
        "got: {resp:?}"
    );
}

#[compio::test]
async fn admin_enroll_rejects_bad_charset() {
    let paths = unique_paths_full();
    write_clients_json(&paths.clients, &[]);
    let server = MockServer::start().await;
    spawn_daemon(&paths, server.uri()).await;

    let resp = admin_request(
        &paths.admin,
        serde_json::json!({
            "op": "enroll",
            "provider": "github",
            "client": "name with space",
            "note": null,
            "psk": TEST_PSK,
        }),
    )
    .await;
    assert_eq!(resp["ok"], serde_json::json!(false));
}

#[compio::test]
async fn admin_revoke_removes_psk_entry_and_updates_clients() {
    let paths = unique_paths_full();
    write_clients_json(&paths.clients, &[]);
    let server = MockServer::start().await;
    spawn_daemon(&paths, server.uri()).await;

    let enroll = admin_request(
        &paths.admin,
        serde_json::json!({
            "op": "enroll",
            "provider": "github",
            "client": "vm-1",
            "note": null,
            "psk": TEST_PSK,
        }),
    )
    .await;
    assert_eq!(enroll["ok"], serde_json::json!(true));

    let revoke = admin_request(
        &paths.admin,
        serde_json::json!({
            "op": "revoke",
            "provider": "github",
            "client": "vm-1",
        }),
    )
    .await;
    assert_eq!(revoke["ok"], serde_json::json!(true));

    let psk_text = std::fs::read_to_string(&paths.psks).unwrap();
    assert!(
        !psk_text.contains("vm-1:"),
        "psks file still has vm-1: {psk_text}"
    );

    let listed = admin_request(&paths.admin, serde_json::json!({"op": "list"})).await;
    assert!(listed["clients"].as_array().unwrap().is_empty());
}

#[compio::test]
async fn admin_revoke_unknown_client_returns_error() {
    let paths = unique_paths_full();
    write_clients_json(&paths.clients, &[]);
    let server = MockServer::start().await;
    spawn_daemon(&paths, server.uri()).await;

    let resp = admin_request(
        &paths.admin,
        serde_json::json!({"op": "revoke", "provider": "github", "client": "ghost"}),
    )
    .await;
    assert_eq!(resp["ok"], serde_json::json!(false));
    assert!(
        resp["error"]
            .as_str()
            .unwrap_or("")
            .contains("no enrolled client"),
        "got: {resp:?}"
    );
}

#[compio::test]
async fn admin_mint_calls_provider_via_wiremock() {
    let paths = unique_paths_full();
    write_clients_json(&paths.clients, &["vm-1"]);
    write_psks_file(&paths.psks, &[("vm-1", [0x03; 32])]);
    let server = MockServer::start().await;
    mount_repo_ok(&server).await;
    mount_mint_ok(&server).await;
    spawn_daemon(&paths, server.uri()).await;

    let resp = admin_request(
        &paths.admin,
        serde_json::json!({
            "op": "mint",
            "provider": "github",
            "client": "vm-1",
            "path": format!("{OWNER}/{REPO}"),
        }),
    )
    .await;
    assert_eq!(resp["ok"], serde_json::json!(true));
    assert_eq!(resp["username"], "x-access-token");
    assert_eq!(resp["password"], TOKEN);
}

#[compio::test]
async fn admin_selfcheck_against_wiremock() {
    let paths = unique_paths_full();
    write_clients_json(&paths.clients, &[]);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/app"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 12345,
            "client_id": CLIENT_ID,
        })))
        .mount(&server)
        .await;
    spawn_daemon(&paths, server.uri()).await;

    let resp = admin_request(
        &paths.admin,
        serde_json::json!({"op": "selfcheck", "provider": "github"}),
    )
    .await;
    assert_eq!(
        resp["ok"],
        serde_json::json!(true),
        "selfcheck failed: {resp:?}"
    );
    // GitHub-specific selfcheck fields nest under `details`; the
    // abstract `SelfcheckOutcome` carries only the generalisable
    // ones at the top level.
    assert_eq!(resp["details"]["client_id"], CLIENT_ID);
}
