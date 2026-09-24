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
