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

    // Verify data file on disk is an encrypted .enc file
    let enc_file_path = std::path::Path::new(&backup_result.target_directory)
        .join("data")
        .join("secret_data.txt.enc");
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
            },
            crate::models::FileMetadata {
                relative_path: "notes.txt".to_string(),
                absolute_path: "/data/docs/notes.txt".to_string(),
                size_bytes: 2048,
                sha256_hash: "9876543210fedcba".to_string(),
                modified_timestamp: 1720000100,
            },
        ],
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
