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
    let provider = GoogleDriveProvider;

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

#[test]
fn test_remote_snapshot_summary_serialization() {
    let summary = RemoteSnapshotSummary {
        snapshot_id: "snap-2026-dr-01".to_string(),
        source_name: "Personal Vault".to_string(),
        created_at: "2026-10-02T12:00:00Z".to_string(),
        total_files: 42,
        total_size_bytes: 1048576,
        is_encrypted: true,
        encryption_algorithm: Some("AES-256-GCM".to_string()),
        provider: "Google Drive".to_string(),
        vault_folder_id: "vault-folder-123".to_string(),
        snapshot_folder_id: "snap-folder-456".to_string(),
        is_imported: false,
    };

    let json = serde_json::to_string(&summary).expect("Serialization failed");
    assert!(json.contains("\"snapshot_id\":\"snap-2026-dr-01\""));
    assert!(json.contains("\"is_imported\":false"));
    assert!(json.contains("\"encryption_algorithm\":\"AES-256-GCM\""));

    let deserialized: RemoteSnapshotSummary =
        serde_json::from_str(&json).expect("Deserialization failed");
    assert_eq!(deserialized.snapshot_id, summary.snapshot_id);
    assert_eq!(deserialized.total_files, 42);
    assert!(deserialized.is_encrypted);
    assert!(!deserialized.is_imported);
}

#[test]
fn test_disaster_recovery_catalog_rebuild_simulation() {
    let mut conn = setup_test_db();

    // Verify database initially empty
    let initial_snapshots = crate::db::get_snapshots(&conn).expect("get_snapshots should succeed");
    assert!(initial_snapshots.is_empty());

    // Construct mock manifest simulated from cloud download
    let manifest = crate::models::BackupManifest {
        id: "disaster-recov-001".to_string(),
        source_path: "/home/user/Documents".to_string(),
        source_name: "Documents".to_string(),
        created_at: chrono::Utc::now(),
        total_files: 2,
        total_size_bytes: 2048,
        is_encrypted: true,
        encryption_algorithm: Some("AES-256-GCM".to_string()),
        salt_hex: Some("abcdef123456".to_string()),
        files: vec![
            crate::models::FileMetadata {
                relative_path: "secret.txt".to_string(),
                absolute_path: "/home/user/Documents/secret.txt".to_string(),
                size_bytes: 1024,
                sha256_hash: "mockhash1".to_string(),
                modified_timestamp: 1720000000,
            },
            crate::models::FileMetadata {
                relative_path: "budget.xlsx".to_string(),
                absolute_path: "/home/user/Documents/budget.xlsx".to_string(),
                size_bytes: 1024,
                sha256_hash: "mockhash2".to_string(),
                modified_timestamp: 1720000100,
            },
        ],
    };

    // Rebuild/import snapshot into SQLite
    crate::db::insert_snapshot(&mut conn, &manifest, "completed")
        .expect("insert_snapshot should succeed");
    crate::db::mark_snapshot_synced(&conn, &manifest.id)
        .expect("mark_snapshot_synced should succeed");

    crate::db::mark_file_synced(&conn, &manifest.id, "secret.txt", "cloud-file-id-1")
        .expect("mark_file_synced should succeed");
    crate::db::mark_file_synced(&conn, &manifest.id, "budget.xlsx", "cloud-file-id-2")
        .expect("mark_file_synced should succeed");

    // Verify local catalog is fully restored
    let snapshots = crate::db::get_snapshots(&conn).expect("get_snapshots should succeed");
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].id, "disaster-recov-001");
    assert!(snapshots[0].cloud_synced);

    let files = crate::db::get_snapshot_files(&conn, "disaster-recov-001")
        .expect("get_snapshot_files should succeed");
    assert_eq!(files.len(), 2);
    assert!(files[0].cloud_synced);
    assert!(files[1].cloud_synced);
    assert_eq!(files[0].relative_path, "budget.xlsx");
    assert_eq!(files[0].cloud_file_id, Some("cloud-file-id-2".to_string()));
    assert_eq!(files[1].relative_path, "secret.txt");
    assert_eq!(files[1].cloud_file_id, Some("cloud-file-id-1".to_string()));
}
