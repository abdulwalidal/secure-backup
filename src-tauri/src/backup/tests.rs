use crate::backup::{create_local_backup, list_local_backups};
use crate::encryption::decrypt_file;
use std::fs;

#[test]
fn test_create_and_list_local_backup() {
    let test_dir = std::env::temp_dir().join("sb_integration_source");
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).unwrap();

    let file1 = test_dir.join("file1.txt");
    let file2 = test_dir.join("sub").join("file2.txt");
    fs::create_dir_all(test_dir.join("sub")).unwrap();

    fs::write(&file1, b"first content").unwrap();
    fs::write(&file2, b"second nested content").unwrap();

    let backup_result = create_local_backup(&test_dir, None).unwrap();
    assert_eq!(backup_result.manifest.total_files, 2);
    assert_eq!(backup_result.manifest.files.len(), 2);
    assert!(!backup_result.is_encrypted);

    // Verify manifest JSON exists on disk
    let manifest_path = std::path::Path::new(&backup_result.target_directory).join("manifest.json");
    assert!(manifest_path.exists());

    // Verify backups can be listed
    let backups = list_local_backups().unwrap();
    assert!(!backups.is_empty());
    assert!(backups.iter().any(|b| b.id == backup_result.backup_id));

    // Cleanup
    let _ = fs::remove_dir_all(&test_dir);
    let _ = fs::remove_dir_all(&backup_result.target_directory);
}

#[test]
fn test_create_encrypted_local_backup_and_recovery() {
    let test_dir = std::env::temp_dir().join("sb_enc_integration_source");
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).unwrap();

    let secret_file = test_dir.join("secret_data.txt");
    let secret_content = b"Top secret zero-knowledge user document.";
    fs::write(&secret_file, secret_content).unwrap();

    let passphrase = "correct-horse-battery-staple";
    let backup_result = create_local_backup(&test_dir, Some(passphrase)).unwrap();

    assert!(backup_result.is_encrypted);
    assert!(backup_result.manifest.is_encrypted);

    // Verify encrypted manifest exists on disk and plaintext manifest DOES NOT
    let enc_manifest_path =
        std::path::Path::new(&backup_result.target_directory).join("manifest.json.enc");
    let plain_manifest_path =
        std::path::Path::new(&backup_result.target_directory).join("manifest.json");
    assert!(enc_manifest_path.exists());
    assert!(!plain_manifest_path.exists());

    // Verify manifest starts with SECBKP01 magic header
    let enc_manifest_bytes = fs::read(&enc_manifest_path).unwrap();
    assert_eq!(&enc_manifest_bytes[..8], crate::encryption::MAGIC_HEADER);

    // Verify manifest decrypts to identical model
    let dec_manifest_bytes =
        crate::encryption::decrypt_archive_payload(&enc_manifest_bytes, passphrase).unwrap();
    let recovered_manifest: crate::models::BackupManifest =
        serde_json::from_slice(&dec_manifest_bytes).unwrap();
    assert_eq!(recovered_manifest.id, backup_result.manifest.id);
    assert_eq!(recovered_manifest.total_files, 1);
    assert_eq!(recovered_manifest.files[0].relative_path, "secret_data.txt");

    // Verify data file on disk is an encrypted opaque <UUID>.enc file
    let stored_filename = recovered_manifest.files[0]
        .stored_filename
        .as_ref()
        .expect("stored_filename should be set for encrypted backup");
    assert!(stored_filename.ends_with(".enc"));
    assert!(!stored_filename.contains("secret_data"));
    let enc_file_path = std::path::Path::new(&backup_result.target_directory)
        .join("data")
        .join(stored_filename);
    assert!(enc_file_path.exists());

    // Verify raw file content is encrypted (not plaintext)
    let raw_bytes = fs::read(&enc_file_path).unwrap();
    assert!(!raw_bytes
        .windows(secret_content.len())
        .any(|w| w == secret_content));

    // Verify decryption restores exact original content
    let restored_file = std::env::temp_dir().join("sb_recovered_secret.txt");
    decrypt_file(&enc_file_path, &restored_file, passphrase).unwrap();
    let recovered_bytes = fs::read(&restored_file).unwrap();
    assert_eq!(recovered_bytes, secret_content);

    // Verify decryption with wrong password fails
    let failed_restore = std::env::temp_dir().join("sb_failed_secret.txt");
    let bad_decrypt = decrypt_file(&enc_file_path, &failed_restore, "wrong-password");
    assert!(bad_decrypt.is_err());

    // Cleanup
    let _ = fs::remove_dir_all(&test_dir);
    let _ = fs::remove_dir_all(&backup_result.target_directory);
    let _ = fs::remove_file(&restored_file);
    let _ = fs::remove_file(&failed_restore);
}

#[test]
fn test_manifest_roundtrip_model_serialization_and_encryption() {
    let manifest = crate::models::BackupManifest {
        id: "snap_roundtrip_test".to_string(),
        source_path: "/data/docs".to_string(),
        source_name: "docs".to_string(),
        created_at: chrono::Utc::now(),
        total_files: 2,
        total_size_bytes: 4096,
        is_encrypted: true,
        encryption_algorithm: Some("AES-256-GCM / Argon2id".to_string()),
        salt_hex: Some("11223344556677889900aabbccddeeff".to_string()),
        files: vec![
            crate::models::FileMetadata {
                relative_path: "sub/report.pdf".to_string(),
                absolute_path: "/data/docs/sub/report.pdf".to_string(),
                size_bytes: 2048,
                sha256_hash: "abcdef0123456789".to_string(),
                modified_timestamp: 1720000000,
                stored_filename: Some("550e8400-e29b-41d4-a716-446655440000.enc".to_string()),
            },
            crate::models::FileMetadata {
                relative_path: "notes.txt".to_string(),
                absolute_path: "/data/docs/notes.txt".to_string(),
                size_bytes: 2048,
                sha256_hash: "9876543210fedcba".to_string(),
                modified_timestamp: 1720000100,
                stored_filename: Some("6ba7b810-9dad-11d1-80b4-00c04fd430c8.enc".to_string()),
            },
        ],
        manifest_version: Some(2),
    };

    let pw = "robust-roundtrip-passphrase";
    let json_str = serde_json::to_string(&manifest).unwrap();
    let enc_bytes =
        crate::encryption::encrypt_archive_payload_with_passphrase(json_str.as_bytes(), pw)
            .expect("Manifest encryption should succeed");

    assert_eq!(&enc_bytes[..8], crate::encryption::MAGIC_HEADER);

    let dec_bytes = crate::encryption::decrypt_archive_payload(&enc_bytes, pw)
        .expect("Manifest decryption should succeed");
    let recovered: crate::models::BackupManifest = serde_json::from_slice(&dec_bytes).unwrap();

    assert_eq!(recovered.id, manifest.id);
    assert_eq!(recovered.source_path, manifest.source_path);
    assert_eq!(recovered.source_name, manifest.source_name);
    assert_eq!(recovered.total_files, 2);
    assert_eq!(recovered.total_size_bytes, 4096);
    assert_eq!(recovered.files.len(), 2);
    assert_eq!(recovered.files[0].relative_path, "sub/report.pdf");
    assert_eq!(recovered.files[1].sha256_hash, "9876543210fedcba");

    // Decrypting with wrong passphrase fails
    assert!(crate::encryption::decrypt_archive_payload(&enc_bytes, "incorrect-pass").is_err());
}

#[test]
fn test_invalid_plaintext_json_manifest_rejection() {
    let pw = "invalid-json-passphrase";
    let invalid_json = b"This is NOT valid JSON syntax {{{ [[[ :::";
    let enc_bytes =
        crate::encryption::encrypt_archive_payload_with_passphrase(invalid_json, pw).unwrap();

    let dec_bytes = crate::encryption::decrypt_archive_payload(&enc_bytes, pw).unwrap();
    assert_eq!(dec_bytes, invalid_json);

    let parse_res = serde_json::from_slice::<crate::models::BackupManifest>(&dec_bytes);
    assert!(parse_res.is_err());
}

#[test]
fn test_empty_snapshot_manifest_encryption() {
    let test_dir = std::env::temp_dir().join("sb_empty_enc_source");
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).unwrap();

    let pw = "empty-snapshot-passphrase";
    let backup_result = create_local_backup(&test_dir, Some(pw)).unwrap();

    assert_eq!(backup_result.manifest.total_files, 0);
    assert_eq!(backup_result.manifest.files.len(), 0);

    let enc_manifest_path =
        std::path::Path::new(&backup_result.target_directory).join("manifest.json.enc");
    assert!(enc_manifest_path.exists());
    assert!(!std::path::Path::new(&backup_result.target_directory)
        .join("manifest.json")
        .exists());

    let enc_bytes = fs::read(&enc_manifest_path).unwrap();
    let dec_bytes = crate::encryption::decrypt_archive_payload(&enc_bytes, pw).unwrap();
    let recovered: crate::models::BackupManifest = serde_json::from_slice(&dec_bytes).unwrap();
    assert_eq!(recovered.total_files, 0);
    assert!(recovered.files.is_empty());

    let _ = fs::remove_dir_all(&test_dir);
    let _ = fs::remove_dir_all(&backup_result.target_directory);
}

#[test]
fn test_unicode_and_spaces_manifest_encryption() {
    let test_dir = std::env::temp_dir().join("sb_unicode_enc_source");
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).unwrap();

    let unicode_file = test_dir.join("dossier_café_日本語_2026.txt");
    let spaces_file = test_dir.join("quarterly report finance final.csv");

    fs::write(&unicode_file, "UTF-8 content: 東京 🗼 & Zürich 🧀").unwrap();
    fs::write(&spaces_file, "col1,col2\nval1,val2").unwrap();

    let pw = "unicode-manifest-passphrase";
    let backup_result = create_local_backup(&test_dir, Some(pw)).unwrap();

    let enc_manifest_path =
        std::path::Path::new(&backup_result.target_directory).join("manifest.json.enc");
    let enc_bytes = fs::read(&enc_manifest_path).unwrap();
    let dec_bytes = crate::encryption::decrypt_archive_payload(&enc_bytes, pw).unwrap();
    let recovered: crate::models::BackupManifest = serde_json::from_slice(&dec_bytes).unwrap();

    assert_eq!(recovered.total_files, 2);
    assert!(recovered
        .files
        .iter()
        .any(|f| f.relative_path == "dossier_café_日本語_2026.txt"));
    assert!(recovered
        .files
        .iter()
        .any(|f| f.relative_path == "quarterly report finance final.csv"));

    let _ = fs::remove_dir_all(&test_dir);
    let _ = fs::remove_dir_all(&backup_result.target_directory);
}

#[test]
fn test_opaque_snapshot_id_and_uuidv4_properties() {
    let test_dir = std::env::temp_dir().join("sb_opaque_test_source_Financials");
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).unwrap();
    fs::write(test_dir.join("test.txt"), b"sample payload").unwrap();

    let pw = "passphrase-for-opaque-id-test";

    // 1. Encrypted backup must have opaque snapshot ID
    let backup1 = create_local_backup(&test_dir, Some(pw)).unwrap();
    let backup2 = create_local_backup(&test_dir, Some(pw)).unwrap();

    // Must NOT leak source folder name ("Financials")
    assert!(!backup1.backup_id.contains("Financials"));
    assert!(!backup2.backup_id.contains("Financials"));

    // Two consecutive backups must have different IDs
    assert_ne!(backup1.backup_id, backup2.backup_id);

    // Format must be YYYYMMDD_HHMMSS_<UUIDv4>
    assert!(backup1.backup_id.len() >= 52); // 15 chars timestamp + 1 underscore + 36 chars UUID = 52
    let parts: Vec<&str> = backup1.backup_id.splitn(3, '_').collect();
    assert_eq!(parts.len(), 3);
    let uuid_str = parts[2];
    let parsed_uuid =
        uuid::Uuid::parse_str(uuid_str).expect("Snapshot ID suffix must be valid UUID");
    assert_eq!(
        parsed_uuid.get_version(),
        Some(uuid::Version::Random),
        "Snapshot ID UUID must be version 4 (random)"
    );

    // 2. Unencrypted backup must preserve readable source name
    let unenc_backup = create_local_backup(&test_dir, None).unwrap();
    assert!(unenc_backup.backup_id.contains("Financials"));

    let _ = fs::remove_dir_all(&test_dir);
    let _ = fs::remove_dir_all(&backup1.target_directory);
    let _ = fs::remove_dir_all(&backup2.target_directory);
    let _ = fs::remove_dir_all(&unenc_backup.target_directory);
}

#[test]
fn test_privacy_regression_zero_leakage_in_cloud_object_names() {
    let test_dir = std::env::temp_dir().join("sb_privacy_regression_FinancialRecords");
    let _ = fs::remove_dir_all(&test_dir);

    let sub1 = test_dir.join("Financial Records 2026");
    let sub2 = test_dir.join("Private Photos");
    let sub3 = test_dir.join("Secret Project");

    fs::create_dir_all(&sub1).unwrap();
    fs::create_dir_all(&sub2).unwrap();
    fs::create_dir_all(&sub3).unwrap();

    fs::write(sub1.join("report.pdf"), b"Confidential financial statement").unwrap();
    fs::write(sub2.join("vacation.jpg"), b"Private photo data").unwrap();
    fs::write(sub3.join("passwords.txt"), b"Root password data").unwrap();

    let pw = "privacy-test-strong-passphrase";
    let backup_result = create_local_backup(&test_dir, Some(pw)).unwrap();

    // Verify snapshot ID does not contain sensitive tokens
    let forbidden_tokens = [
        "Financial",
        "Records",
        "Private",
        "Photos",
        "vacation",
        "Secret",
        "Project",
        "passwords",
        "report",
    ];

    for token in &forbidden_tokens {
        assert!(
            !backup_result.backup_id.contains(token),
            "Snapshot ID '{}' exposed sensitive token '{}'",
            backup_result.backup_id,
            token
        );
    }

    // Inspect files in data directory
    let data_dir = std::path::Path::new(&backup_result.target_directory).join("data");
    let entries = fs::read_dir(&data_dir).unwrap();
    let mut file_names = Vec::new();

    for entry in entries {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        file_names.push(name);
    }

    assert_eq!(file_names.len(), 3);

    let forbidden_exts = [".pdf", ".jpg", ".txt"];

    for file_name in &file_names {
        // Must be <UUIDv4>.enc
        assert!(
            file_name.ends_with(".enc"),
            "Filename '{}' does not end with .enc",
            file_name
        );
        let stem = file_name.strip_suffix(".enc").unwrap();
        let parsed_uuid = uuid::Uuid::parse_str(stem)
            .unwrap_or_else(|_| panic!("Filename '{}' stem is not a valid UUID", file_name));
        assert_eq!(
            parsed_uuid.get_version(),
            Some(uuid::Version::Random),
            "File UUID must be version 4"
        );

        // Must not expose sensitive tokens
        for token in &forbidden_tokens {
            assert!(
                !file_name.contains(token),
                "Filename '{}' exposed token '{}'",
                file_name,
                token
            );
        }

        // Must not expose original file extensions
        for ext in &forbidden_exts {
            assert!(
                !file_name.contains(ext),
                "Filename '{}' exposed original extension '{}'",
                file_name,
                ext
            );
        }
    }

    // Verify the decrypted manifest internally holds the authentic mappings
    let enc_manifest_path =
        std::path::Path::new(&backup_result.target_directory).join("manifest.json.enc");
    let enc_bytes = fs::read(&enc_manifest_path).unwrap();
    let dec_bytes = crate::encryption::decrypt_archive_payload(&enc_bytes, pw).unwrap();
    let recovered: crate::models::BackupManifest = serde_json::from_slice(&dec_bytes).unwrap();

    assert_eq!(recovered.files.len(), 3);
    for file in &recovered.files {
        let stored = file
            .stored_filename
            .as_ref()
            .expect("stored_filename must be set");
        assert!(file_names.contains(stored));
    }

    let _ = fs::remove_dir_all(&test_dir);
    let _ = fs::remove_dir_all(&backup_result.target_directory);
}

#[test]
fn test_duplicate_basenames_receive_unique_uuids() {
    let test_dir = std::env::temp_dir().join("sb_dup_basenames_source");
    let _ = fs::remove_dir_all(&test_dir);

    let f1 = test_dir.join("folder1");
    let f2 = test_dir.join("folder2");
    let f3 = test_dir.join("folder3");

    fs::create_dir_all(&f1).unwrap();
    fs::create_dir_all(&f2).unwrap();
    fs::create_dir_all(&f3).unwrap();

    fs::write(f1.join("report.pdf"), b"report content from folder 1").unwrap();
    fs::write(f2.join("report.pdf"), b"report content from folder 2").unwrap();
    fs::write(f3.join("report.pdf"), b"report content from folder 3").unwrap();

    let pw = "dup-basenames-pw";
    let backup_result = create_local_backup(&test_dir, Some(pw)).unwrap();

    let files = &backup_result.manifest.files;
    assert_eq!(files.len(), 3);

    let mut uuids = std::collections::HashSet::new();
    for f in files {
        let stored = f.stored_filename.as_ref().unwrap();
        assert!(stored.ends_with(".enc"));
        assert!(
            uuids.insert(stored.clone()),
            "Duplicate UUID assigned: {}",
            stored
        );
    }

    assert_eq!(
        uuids.len(),
        3,
        "All 3 duplicate basenames must have unique UUIDs"
    );

    let _ = fs::remove_dir_all(&test_dir);
    let _ = fs::remove_dir_all(&backup_result.target_directory);
}

#[test]
fn test_legacy_manifest_deserialization_backward_compatibility() {
    // Legacy JSON from #26/#27 without stored_filename or manifest_version
    let legacy_json = r#"{
        "id": "20261001_120000_Documents",
        "source_path": "/home/user/Documents",
        "source_name": "Documents",
        "created_at": "2026-10-01T12:00:00Z",
        "total_files": 1,
        "total_size_bytes": 1024,
        "is_encrypted": true,
        "encryption_algorithm": "AES-256-GCM / Argon2id",
        "salt_hex": "00112233445566778899aabbccddeeff",
        "files": [
            {
                "relative_path": "tax.pdf",
                "absolute_path": "/home/user/Documents/tax.pdf",
                "size_bytes": 1024,
                "sha256_hash": "deadbeef1234",
                "modified_timestamp": 1720000000
            }
        ]
    }"#;

    let manifest: crate::models::BackupManifest = serde_json::from_str(legacy_json).unwrap();
    assert_eq!(manifest.manifest_version, None);
    assert_eq!(manifest.files[0].stored_filename, None);
    assert_eq!(manifest.files[0].relative_path, "tax.pdf");
}

#[test]
fn test_delete_local_backup_removes_directory_and_files() {
    use crate::backup::delete_local_backup;

    let test_dir = std::env::temp_dir().join("sb_delete_backup_test_source");
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).unwrap();
    fs::write(test_dir.join("sample.txt"), b"sample data for deletion").unwrap();

    let backup_res = create_local_backup(&test_dir, Some("delete_pw_123")).unwrap();
    let backup_dir = std::path::PathBuf::from(&backup_res.target_directory);

    assert!(
        backup_dir.exists(),
        "Target backup dir must exist before deletion"
    );
    assert!(backup_dir.join("manifest.json.enc").exists());

    // Execute deletion
    let deleted = delete_local_backup(&backup_res.backup_id).unwrap();
    assert!(deleted, "delete_local_backup must return true on success");
    assert!(
        !backup_dir.exists(),
        "Target backup dir must be completely removed from disk"
    );

    let _ = fs::remove_dir_all(&test_dir);
}

#[test]
fn test_delete_local_backup_path_traversal_rejection() {
    use crate::backup::delete_local_backup;

    let res1 = delete_local_backup("../malicious");
    assert!(res1.is_err());
    assert_eq!(res1.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);

    let res2 = delete_local_backup("folder/subfolder");
    assert!(res2.is_err());
    assert_eq!(res2.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);

    let res3 = delete_local_backup("folder\\subfolder");
    assert!(res3.is_err());
    assert_eq!(res3.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);

    let res4 = delete_local_backup("");
    assert!(res4.is_err());
    assert_eq!(res4.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn test_delete_local_backup_nonexistent_returns_not_found() {
    use crate::backup::delete_local_backup;

    let res = delete_local_backup("nonexistent_backup_id_99999999");
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::NotFound);
}
