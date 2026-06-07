//! Admin socket end-to-end tests: send JSON op, observe response.

mod common;

use std::os::unix::fs::PermissionsExt;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{
    CLIENT_ID, OWNER, REPO, TOKEN, admin_request, mount_mint_ok, mount_repo_ok, spawn_daemon,
    unique_paths_full, write_clients_json,
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
    assert_eq!(resp["providers"], serde_json::json!(["github.com"]));
    paths.cleanup();
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
    paths.cleanup();
}

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
            "ip": "192.168.122.10",
            "note": null,
        }),
    )
    .await;
    assert_eq!(resp["ok"], serde_json::json!(true));
    let psk_hex = resp["psk_hex"].as_str().unwrap();
    assert_eq!(psk_hex.len(), 64);
    assert!(psk_hex.chars().all(|c| c.is_ascii_hexdigit()));

    let psk_text = std::fs::read_to_string(&paths.psk).unwrap();
    assert!(
        psk_text.starts_with(&format!("vm-1:{psk_hex}")),
        "got: {psk_text:?}"
    );
    let psk_mode = std::fs::metadata(&paths.psk).unwrap().permissions().mode() & 0o777;
    assert_eq!(psk_mode, 0o600);

    let clients_text = std::fs::read_to_string(&paths.clients).unwrap();
    assert!(clients_text.contains("\"name\": \"vm-1\""));
    assert!(clients_text.contains("\"192.168.122.10\""));
    let cl_mode = std::fs::metadata(&paths.clients)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(cl_mode, 0o640);

    let listed = admin_request(&paths.admin, serde_json::json!({"op": "list"})).await;
    assert_eq!(listed["clients"].as_array().unwrap().len(), 1);

    paths.cleanup();
}

#[compio::test]
async fn admin_enroll_appends_without_clobbering_existing() {
    let paths = unique_paths_full();
    write_clients_json(&paths.clients, &[("vm-0", "192.168.122.9")]);
    std::fs::write(&paths.psk, "vm-0:0123abcd\n").unwrap();
    let server = MockServer::start().await;
    spawn_daemon(&paths, server.uri()).await;

    let resp = admin_request(
        &paths.admin,
        serde_json::json!({
            "op": "enroll",
            "provider": "github",
            "client": "vm-1",
            "ip": "192.168.122.10",
            "note": null,
        }),
    )
    .await;
    assert_eq!(resp["ok"], serde_json::json!(true));

    let psk_text = std::fs::read_to_string(&paths.psk).unwrap();
    assert!(
        psk_text.contains("vm-0:0123abcd"),
        "lost pre-existing entry: {psk_text}"
    );
    assert!(psk_text.contains("vm-1:"), "missing new entry: {psk_text}");

    paths.cleanup();
}

#[compio::test]
async fn admin_enroll_rejects_duplicate_client_name() {
    let paths = unique_paths_full();
    write_clients_json(&paths.clients, &[("vm-1", "192.168.122.10")]);
    let server = MockServer::start().await;
    spawn_daemon(&paths, server.uri()).await;

    let resp = admin_request(
        &paths.admin,
        serde_json::json!({
            "op": "enroll",
            "provider": "github",
            "client": "vm-1",
            "ip": "192.168.122.20",
            "note": null,
        }),
    )
    .await;
    assert_eq!(resp["ok"], serde_json::json!(false));
    assert_eq!(resp["code"], "client_already_enrolled");
    paths.cleanup();
}

#[compio::test]
async fn admin_enroll_rejects_duplicate_ip() {
    let paths = unique_paths_full();
    write_clients_json(&paths.clients, &[("vm-1", "192.168.122.10")]);
    let server = MockServer::start().await;
    spawn_daemon(&paths, server.uri()).await;

    let resp = admin_request(
        &paths.admin,
        serde_json::json!({
            "op": "enroll",
            "provider": "github",
            "client": "vm-2",
            "ip": "192.168.122.10",
            "note": null,
        }),
    )
    .await;
    assert_eq!(resp["ok"], serde_json::json!(false));
    assert_eq!(resp["code"], "client_ip_collision");
    paths.cleanup();
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
            "ip": "192.168.122.10",
            "note": null,
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

    let psk_text = std::fs::read_to_string(&paths.psk).unwrap();
    assert!(
        !psk_text.contains("vm-1:"),
        "psk still has vm-1: {psk_text}"
    );

    let listed = admin_request(&paths.admin, serde_json::json!({"op": "list"})).await;
    assert!(listed["clients"].as_array().unwrap().is_empty());

    paths.cleanup();
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
    assert_eq!(resp["code"], "unknown_client");
    paths.cleanup();
}

#[compio::test]
async fn admin_mint_calls_provider_via_wiremock() {
    let paths = unique_paths_full();
    write_clients_json(&paths.clients, &[("vm-1", "192.168.122.10")]);
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
    paths.cleanup();
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
    assert_eq!(resp["client_id"], CLIENT_ID);
    paths.cleanup();
}
