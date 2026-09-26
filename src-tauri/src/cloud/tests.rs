use super::gdrive::{generate_pkce, GoogleDriveProvider};
use super::*;
use crate::db::{init_db, set_setting};
use rusqlite::Connection;

fn setup_test_db() -> Connection {
    let conn = Connection::open_in_memory().expect("Failed to open test in-memory database");
    init_db(&conn).expect("Failed to initialize test database schema");
    conn
}

#[test]
fn test_pkce_generation() {
    let pkce1 = generate_pkce();
    let pkce2 = generate_pkce();

    assert_ne!(pkce1.verifier, pkce2.verifier);
    assert_ne!(pkce1.challenge, pkce2.challenge);
    assert!(!pkce1.verifier.is_empty());
    assert!(!pkce1.challenge.is_empty());
}

#[test]
fn test_google_drive_status_transitions() {
    let conn = setup_test_db();
    let provider = GoogleDriveProvider::default();

    // 1. Initial state: Disconnected
    let status = provider
        .get_status(&conn)
        .expect("get_status should succeed");
    assert!(!status.is_connected);
    assert_eq!(status.account_email, None);
    assert_eq!(status.provider_type, CloudProviderType::GoogleDrive);

    // 2. Simulate connected by setting tokens in SQLite
    set_setting(
        &conn,
        gdrive::GDRIVE_SETTING_ACCESS_TOKEN,
        "mock_access_token_abc",
    )
    .unwrap();
    set_setting(
        &conn,
        gdrive::GDRIVE_SETTING_USER_EMAIL,
        "engineer@example.com",
    )
    .unwrap();

    let status = provider
        .get_status(&conn)
        .expect("get_status should succeed");
    assert!(status.is_connected);
    assert_eq!(
        status.account_email,
        Some("engineer@example.com".to_string())
    );

    // 3. Disconnect
    provider
        .disconnect(&conn)
        .expect("disconnect should succeed");
    let status = provider
        .get_status(&conn)
        .expect("get_status should succeed");
    assert!(!status.is_connected);
    assert_eq!(status.account_email, None);
}

#[test]
fn test_all_provider_statuses() {
    let conn = setup_test_db();
    let list = get_all_provider_statuses(&conn);

    assert_eq!(list.len(), 5);
    assert_eq!(list[0].provider_type, CloudProviderType::GoogleDrive);
    assert!(list[0].is_supported);
    assert_eq!(list[1].provider_type, CloudProviderType::Mega);
    assert!(!list[1].is_supported);
    assert_eq!(list[2].provider_type, CloudProviderType::ProtonDrive);
    assert_eq!(list[3].provider_type, CloudProviderType::Filen);
    assert_eq!(list[4].provider_type, CloudProviderType::S3);
}

#[test]
fn test_auth_url_construction() {
    let pkce = generate_pkce();
    let url = GoogleDriveProvider::build_auth_url(
        "mock-client-id.apps.googleusercontent.com",
        "http://127.0.0.1:8080",
        &pkce,
    )
    .expect("build_auth_url should succeed");

    assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth"));
    assert!(url.contains("client_id=mock-client-id"));
    assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A8080"));
    assert!(url.contains("code_challenge_method=S256"));
}
