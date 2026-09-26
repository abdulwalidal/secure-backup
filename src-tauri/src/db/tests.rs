use super::*;
use crate::models::{BackupManifest, FileMetadata};
use chrono::Utc;
use rusqlite::Connection;

fn setup_test_db() -> Connection {
    let conn = Connection::open_in_memory().expect("Failed to open test in-memory database");
    init_db(&conn).expect("Failed to initialize test database schema");
    conn
}

fn sample_manifest(id: &str, file_count: usize, encrypted: bool) -> BackupManifest {
    let mut files = Vec::new();
    for i in 0..file_count {
        files.push(FileMetadata {
            relative_path: format!("documents/report_{}.pdf", i),
            absolute_path: format!("/home/user/documents/report_{}.pdf", i),
            size_bytes: 1024 * (i as u64 + 1),
            sha256_hash: format!("fakehash{:064x}", i),
            modified_timestamp: 1710000000 + i as u64,
        });
    }

    BackupManifest {
        id: id.to_string(),
        source_path: "/home/user/documents".to_string(),
        source_name: "documents".to_string(),
        created_at: Utc::now(),
        total_files: file_count,
        total_size_bytes: files.iter().map(|f| f.size_bytes).sum(),
        is_encrypted: encrypted,
        encryption_algorithm: if encrypted {
            Some("AES-256-GCM".to_string())
        } else {
            None
        },
        salt_hex: if encrypted {
            Some("0123456789abcdef".to_string())
        } else {
            None
        },
        files,
    }
}

#[test]
fn test_database_initialization() {
    let conn = setup_test_db();

    // Verify tables exist
    let count: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('snapshots', 'snapshot_files', 'app_settings')",
            [],
            |row| row.get(0),
        )
        .expect("Querying sqlite_master failed");

    assert_eq!(count, 3, "All 3 tables must exist");
}

#[test]
fn test_insert_and_query_snapshot() {
    let mut conn = setup_test_db();
    let manifest = sample_manifest("snapshot-001", 3, true);

    insert_snapshot(&mut conn, &manifest, "completed").expect("Insert snapshot should succeed");

    let snapshots = get_snapshots(&conn).expect("get_snapshots should succeed");
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].id, "snapshot-001");
    assert_eq!(snapshots[0].source_name, "documents");
    assert_eq!(snapshots[0].total_files, 3);
    assert!(snapshots[0].is_encrypted);
    assert_eq!(snapshots[0].status, "completed");

    let files =
        get_snapshot_files(&conn, "snapshot-001").expect("get_snapshot_files should succeed");
    assert_eq!(files.len(), 3);
    assert_eq!(files[0].relative_path, "documents/report_0.pdf");
    assert_eq!(files[0].stored_filename, "report_0.pdf.enc");
}

#[test]
fn test_cascade_deletion() {
    let mut conn = setup_test_db();
    let manifest = sample_manifest("snapshot-cascade", 2, false);

    insert_snapshot(&mut conn, &manifest, "completed").unwrap();

    let files_before = get_snapshot_files(&conn, "snapshot-cascade").unwrap();
    assert_eq!(files_before.len(), 2);

    conn.execute("DELETE FROM snapshots WHERE id = ?1", ["snapshot-cascade"])
        .unwrap();

    let files_after = get_snapshot_files(&conn, "snapshot-cascade").unwrap();
    assert_eq!(
        files_after.len(),
        0,
        "Files should be deleted when snapshot is removed"
    );
}

#[test]
fn test_database_stats() {
    let mut conn = setup_test_db();
    let m1 = sample_manifest("snap-1", 2, false);
    let m2 = sample_manifest("snap-2", 3, true);

    insert_snapshot(&mut conn, &m1, "completed").unwrap();
    insert_snapshot(&mut conn, &m2, "completed").unwrap();

    let stats = get_db_stats(&conn).expect("get_db_stats should succeed");
    assert_eq!(stats.total_snapshots, 2);
    assert_eq!(stats.total_files_indexed, 5);
    assert_eq!(
        stats.total_bytes_backed_up,
        m1.total_size_bytes + m2.total_size_bytes
    );
}

#[test]
fn test_settings_storage() {
    let conn = setup_test_db();

    // Verify initial missing
    let val = get_setting(&conn, "gdrive_token").unwrap();
    assert_eq!(val, None);

    // Insert setting
    set_setting(&conn, "gdrive_token", "sample_access_token_123").unwrap();
    let val = get_setting(&conn, "gdrive_token").unwrap();
    assert_eq!(val, Some("sample_access_token_123".to_string()));

    // Update setting
    set_setting(&conn, "gdrive_token", "updated_token_456").unwrap();
    let val = get_setting(&conn, "gdrive_token").unwrap();
    assert_eq!(val, Some("updated_token_456".to_string()));

    // Delete setting
    delete_setting(&conn, "gdrive_token").unwrap();
    let val = get_setting(&conn, "gdrive_token").unwrap();
    assert_eq!(val, None);
}
