use super::*;
use crate::encryption::{derive_key, encrypt_file, generate_salt};
use crate::hashing::hash_bytes;
use crate::models::FileMetadata;
use std::fs;

fn create_temp_dest_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sb_test_restore_{}_{}",
        name,
        rand::random::<u32>()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn test_path_traversal_rejections() {
    let dest_dir = create_temp_dest_dir("path_traversal");

    // 1. Relative parent traversal
    assert!(validate_and_resolve_destination(&dest_dir, "../outside.txt").is_err());
    assert!(validate_and_resolve_destination(&dest_dir, "foo/../../outside.txt").is_err());
    assert!(validate_and_resolve_destination(&dest_dir, "nested/..").is_err());
    assert!(validate_and_resolve_destination(&dest_dir, "..\\windows\\outside.txt").is_err());

    // 2. Absolute POSIX paths
    assert!(validate_and_resolve_destination(&dest_dir, "/etc/passwd").is_err());
    assert!(validate_and_resolve_destination(&dest_dir, "/tmp/evil").is_err());

    // 3. Windows drive letter paths
    assert!(validate_and_resolve_destination(&dest_dir, "C:\\Windows\\System32\\cmd.exe").is_err());
    assert!(validate_and_resolve_destination(&dest_dir, "D:/secrets.txt").is_err());
    assert!(validate_and_resolve_destination(&dest_dir, "c:file.txt").is_err());

    // 4. Windows UNC paths
    assert!(
        validate_and_resolve_destination(&dest_dir, "\\\\attacker-server\\share\\malware.exe")
            .is_err()
    );
    assert!(
        validate_and_resolve_destination(&dest_dir, "//attacker-server/share/malware.exe").is_err()
    );

    // 5. Empty or null byte paths
    assert!(validate_and_resolve_destination(&dest_dir, "").is_err());
    assert!(validate_and_resolve_destination(&dest_dir, "file\0name.txt").is_err());

    // 6. Colons in path component
    assert!(validate_and_resolve_destination(&dest_dir, "foo:bar").is_err());

    // 7. Legitimate relative paths should succeed
    let valid = validate_and_resolve_destination(&dest_dir, "sub/dir/safe_file.txt");
    assert!(valid.is_ok());
    assert!(valid.unwrap().starts_with(dest_dir.canonicalize().unwrap()));

    let _ = fs::remove_dir_all(&dest_dir);
}

#[test]
fn test_restore_single_and_multiple_files_with_nested_directories() {
    let dest_dir = create_temp_dest_dir("multi_nested");
    let pw = "my-restore-passphrase-2026";
    let salt = generate_salt();
    let key = derive_key(pw, &salt).unwrap();

    // Prepare files
    let tmp_src = create_temp_dest_dir("src_files");
    let file1_src = tmp_src.join("hello.txt");
    let file2_src = tmp_src.join("nested.md");
    let content1 = b"Hello, world!";
    let content2 = b"# Nested Markdown Document\nRestoration test.";

    fs::write(&file1_src, content1).unwrap();
    fs::write(&file2_src, content2).unwrap();

    let enc1 = tmp_src.join("hello.txt.enc");
    let enc2 = tmp_src.join("nested.md.enc");
    encrypt_file(&file1_src, &enc1, &key, &salt).unwrap();
    encrypt_file(&file2_src, &enc2, &key, &salt).unwrap();

    let bytes1 = fs::read(&enc1).unwrap();
    let bytes2 = fs::read(&enc2).unwrap();

    let meta1 = FileMetadata {
        relative_path: "hello.txt".to_string(),
        absolute_path: file1_src.to_string_lossy().to_string(),
        size_bytes: content1.len() as u64,
        sha256_hash: hash_bytes(content1),
        modified_timestamp: 1700000000,
    };
    let meta2 = FileMetadata {
        relative_path: "sub/folder/nested.md".to_string(),
        absolute_path: file2_src.to_string_lossy().to_string(),
        size_bytes: content2.len() as u64,
        sha256_hash: hash_bytes(content2),
        modified_timestamp: 1700000000,
    };

    let dest1 = validate_and_resolve_destination(&dest_dir, &meta1.relative_path).unwrap();
    let dest2 = validate_and_resolve_destination(&dest_dir, &meta2.relative_path).unwrap();

    let mut cached_key = None;

    let res1 = restore_single_payload(
        &bytes1,
        &meta1,
        true,
        &dest1,
        ConflictPolicy::Skip,
        &mut cached_key,
        Some(pw),
    );
    assert!(res1.is_ok());

    let res2 = restore_single_payload(
        &bytes2,
        &meta2,
        true,
        &dest2,
        ConflictPolicy::Skip,
        &mut cached_key,
        Some(pw),
    );
    assert!(res2.is_ok());

    // Verify files exist and have exact content
    assert_eq!(fs::read(&dest1).unwrap(), content1);
    assert_eq!(fs::read(&dest2).unwrap(), content2);

    let _ = fs::remove_dir_all(&dest_dir);
    let _ = fs::remove_dir_all(&tmp_src);
}

#[test]
fn test_restore_empty_file_unicode_and_spaces() {
    let dest_dir = create_temp_dest_dir("unicode_spaces_empty");
    let pw = "special-filenames-pw";
    let salt = generate_salt();
    let key = derive_key(pw, &salt).unwrap();
    let tmp_src = create_temp_dest_dir("special_src");

    let empty_src = tmp_src.join("empty.txt");
    let unicode_src = tmp_src.join("résumé_日本語_2026.txt");
    let spaces_src = tmp_src.join("my secret document backup.txt");

    fs::write(&empty_src, b"").unwrap();
    fs::write(
        &unicode_src,
        "SecureBackup supports UTF-8: 東京 & München".as_bytes(),
    )
    .unwrap();
    fs::write(&spaces_src, b"Content with spaces in filename").unwrap();

    let empty_enc = tmp_src.join("empty.enc");
    let unicode_enc = tmp_src.join("unicode.enc");
    let spaces_enc = tmp_src.join("spaces.enc");

    encrypt_file(&empty_src, &empty_enc, &key, &salt).unwrap();
    encrypt_file(&unicode_src, &unicode_enc, &key, &salt).unwrap();
    encrypt_file(&spaces_src, &spaces_enc, &key, &salt).unwrap();

    let mut cached_key = None;

    // 1. Empty file
    let meta_empty = FileMetadata {
        relative_path: "empty.txt".to_string(),
        absolute_path: empty_src.to_string_lossy().to_string(),
        size_bytes: 0,
        sha256_hash: hash_bytes(b""),
        modified_timestamp: 1700000000,
    };
    let dest_empty =
        validate_and_resolve_destination(&dest_dir, &meta_empty.relative_path).unwrap();
    let res_empty = restore_single_payload(
        &fs::read(&empty_enc).unwrap(),
        &meta_empty,
        true,
        &dest_empty,
        ConflictPolicy::Skip,
        &mut cached_key,
        Some(pw),
    );
    assert!(res_empty.is_ok());
    assert_eq!(fs::read(&dest_empty).unwrap(), b"");

    // 2. Unicode file
    let meta_unicode = FileMetadata {
        relative_path: "résumé_日本語_2026.txt".to_string(),
        absolute_path: unicode_src.to_string_lossy().to_string(),
        size_bytes: fs::metadata(&unicode_src).unwrap().len(),
        sha256_hash: hash_bytes(&fs::read(&unicode_src).unwrap()),
        modified_timestamp: 1700000000,
    };
    let dest_unicode =
        validate_and_resolve_destination(&dest_dir, &meta_unicode.relative_path).unwrap();
    let res_unicode = restore_single_payload(
        &fs::read(&unicode_enc).unwrap(),
        &meta_unicode,
        true,
        &dest_unicode,
        ConflictPolicy::Skip,
        &mut cached_key,
        Some(pw),
    );
    assert!(res_unicode.is_ok());
    assert_eq!(
        fs::read(&dest_unicode).unwrap(),
        fs::read(&unicode_src).unwrap()
    );

    // 3. Spaces in filename
    let meta_spaces = FileMetadata {
        relative_path: "folder with spaces/my secret document backup.txt".to_string(),
        absolute_path: spaces_src.to_string_lossy().to_string(),
        size_bytes: fs::metadata(&spaces_src).unwrap().len(),
        sha256_hash: hash_bytes(&fs::read(&spaces_src).unwrap()),
        modified_timestamp: 1700000000,
    };
    let dest_spaces =
        validate_and_resolve_destination(&dest_dir, &meta_spaces.relative_path).unwrap();
    let res_spaces = restore_single_payload(
        &fs::read(&spaces_enc).unwrap(),
        &meta_spaces,
        true,
        &dest_spaces,
        ConflictPolicy::Skip,
        &mut cached_key,
        Some(pw),
    );
    assert!(res_spaces.is_ok());
    assert_eq!(
        fs::read(&dest_spaces).unwrap(),
        fs::read(&spaces_src).unwrap()
    );

    let _ = fs::remove_dir_all(&dest_dir);
    let _ = fs::remove_dir_all(&tmp_src);
}

#[test]
fn test_wrong_passphrase_rejection() {
    let dest_dir = create_temp_dest_dir("wrong_pw");
    let pw = "correct-passphrase";
    let salt = generate_salt();
    let key = derive_key(pw, &salt).unwrap();
    let tmp_src = create_temp_dest_dir("wrong_pw_src");

    let src = tmp_src.join("data.txt");
    fs::write(&src, b"Sensitive financial document").unwrap();

    let enc = tmp_src.join("data.enc");
    encrypt_file(&src, &enc, &key, &salt).unwrap();

    let meta = FileMetadata {
        relative_path: "data.txt".to_string(),
        absolute_path: src.to_string_lossy().to_string(),
        size_bytes: 28,
        sha256_hash: hash_bytes(b"Sensitive financial document"),
        modified_timestamp: 1700000000,
    };
    let dest = validate_and_resolve_destination(&dest_dir, &meta.relative_path).unwrap();
    let mut cached_key = None;

    let res = restore_single_payload(
        &fs::read(&enc).unwrap(),
        &meta,
        true,
        &dest,
        ConflictPolicy::Skip,
        &mut cached_key,
        Some("wrong-passphrase"),
    );

    assert!(res.is_err());
    assert!(!dest.exists()); // Plaintext must never be written on authentication failure

    let _ = fs::remove_dir_all(&dest_dir);
    let _ = fs::remove_dir_all(&tmp_src);
}

#[test]
fn test_corrupted_ciphertext_and_invalid_header_rejection() {
    let dest_dir = create_temp_dest_dir("tamper_test");
    let pw = "tamper-passphrase";
    let salt = generate_salt();
    let key = derive_key(pw, &salt).unwrap();
    let tmp_src = create_temp_dest_dir("tamper_src");

    let src = tmp_src.join("tamper.txt");
    fs::write(&src, b"Original tamper detection text").unwrap();
    let enc = tmp_src.join("tamper.enc");
    encrypt_file(&src, &enc, &key, &salt).unwrap();

    let mut corrupted_bytes = fs::read(&enc).unwrap();
    // Tamper with ciphertext byte (after 36 byte header)
    corrupted_bytes[38] ^= 0x55;

    let meta = FileMetadata {
        relative_path: "tamper.txt".to_string(),
        absolute_path: src.to_string_lossy().to_string(),
        size_bytes: 30,
        sha256_hash: hash_bytes(b"Original tamper detection text"),
        modified_timestamp: 1700000000,
    };
    let dest = validate_and_resolve_destination(&dest_dir, &meta.relative_path).unwrap();
    let mut cached_key = None;

    // 1. Corrupted ciphertext fails GCM authentication
    let res_corrupted = restore_single_payload(
        &corrupted_bytes,
        &meta,
        true,
        &dest,
        ConflictPolicy::Skip,
        &mut cached_key,
        Some(pw),
    );
    assert!(res_corrupted.is_err());
    assert!(!dest.exists());

    // 2. Corrupted magic header
    let mut bad_header_bytes = fs::read(&enc).unwrap();
    bad_header_bytes[0] = b'B';
    bad_header_bytes[1] = b'A';
    bad_header_bytes[2] = b'D';

    let res_header = restore_single_payload(
        &bad_header_bytes,
        &meta,
        true,
        &dest,
        ConflictPolicy::Skip,
        &mut cached_key,
        Some(pw),
    );
    assert!(res_header.is_err());
    assert!(!dest.exists());

    let _ = fs::remove_dir_all(&dest_dir);
    let _ = fs::remove_dir_all(&tmp_src);
}

#[test]
fn test_sha256_integrity_mismatch_rejection() {
    let dest_dir = create_temp_dest_dir("sha_mismatch");
    let pw = "integrity-pw";
    let salt = generate_salt();
    let key = derive_key(pw, &salt).unwrap();
    let tmp_src = create_temp_dest_dir("sha_src");

    let src = tmp_src.join("file.txt");
    fs::write(&src, b"Good data").unwrap();
    let enc = tmp_src.join("file.enc");
    encrypt_file(&src, &enc, &key, &salt).unwrap();

    let meta_wrong_hash = FileMetadata {
        relative_path: "file.txt".to_string(),
        absolute_path: src.to_string_lossy().to_string(),
        size_bytes: 9,
        sha256_hash: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        modified_timestamp: 1700000000,
    };
    let dest = validate_and_resolve_destination(&dest_dir, &meta_wrong_hash.relative_path).unwrap();
    let mut cached_key = None;

    let res = restore_single_payload(
        &fs::read(&enc).unwrap(),
        &meta_wrong_hash,
        true,
        &dest,
        ConflictPolicy::Skip,
        &mut cached_key,
        Some(pw),
    );
    assert!(res.is_err());
    assert!(!dest.exists()); // Plaintext must not exist if hash mismatch occurs

    let _ = fs::remove_dir_all(&dest_dir);
    let _ = fs::remove_dir_all(&tmp_src);
}

#[test]
fn test_conflict_policies_and_overwrite_protection() {
    let dest_dir = create_temp_dest_dir("conflict_policies");
    let pw = "conflict-pw";
    let salt = generate_salt();
    let key = derive_key(pw, &salt).unwrap();
    let tmp_src = create_temp_dest_dir("conflict_src");

    let original_dest_content = b"Pre-existing user file content that must NOT be lost on failure!";
    let new_content = b"New restored snapshot content.";

    let src = tmp_src.join("conflict.txt");
    fs::write(&src, new_content).unwrap();
    let enc = tmp_src.join("conflict.enc");
    encrypt_file(&src, &enc, &key, &salt).unwrap();

    let meta = FileMetadata {
        relative_path: "conflict.txt".to_string(),
        absolute_path: src.to_string_lossy().to_string(),
        size_bytes: new_content.len() as u64,
        sha256_hash: hash_bytes(new_content),
        modified_timestamp: 1700000000,
    };
    let dest = validate_and_resolve_destination(&dest_dir, &meta.relative_path).unwrap();

    // 1. ConflictPolicy::Skip
    fs::write(&dest, original_dest_content).unwrap();
    let mut cached_key = None;
    let res_skip = restore_single_payload(
        &fs::read(&enc).unwrap(),
        &meta,
        true,
        &dest,
        ConflictPolicy::Skip,
        &mut cached_key,
        Some(pw),
    );
    assert!(res_skip.is_ok());
    // Dest content remains unchanged
    assert_eq!(fs::read(&dest).unwrap(), original_dest_content);

    // 2. ConflictPolicy::Fail
    let res_fail = restore_single_payload(
        &fs::read(&enc).unwrap(),
        &meta,
        true,
        &dest,
        ConflictPolicy::Fail,
        &mut cached_key,
        Some(pw),
    );
    assert!(res_fail.is_err());
    assert_eq!(fs::read(&dest).unwrap(), original_dest_content);

    // 3. Overwrite protection: wrong passphrase must NOT overwrite existing file!
    let res_bad_pw_overwrite = restore_single_payload(
        &fs::read(&enc).unwrap(),
        &meta,
        true,
        &dest,
        ConflictPolicy::Overwrite,
        &mut cached_key,
        Some("wrong-passphrase"),
    );
    assert!(res_bad_pw_overwrite.is_err());
    assert_eq!(fs::read(&dest).unwrap(), original_dest_content); // STILL PRESERVED!

    // 4. Overwrite protection: corrupted ciphertext must NOT overwrite existing file!
    let mut bad_enc = fs::read(&enc).unwrap();
    bad_enc[40] ^= 0xFF;
    let res_bad_enc_overwrite = restore_single_payload(
        &bad_enc,
        &meta,
        true,
        &dest,
        ConflictPolicy::Overwrite,
        &mut cached_key,
        Some(pw),
    );
    assert!(res_bad_enc_overwrite.is_err());
    assert_eq!(fs::read(&dest).unwrap(), original_dest_content); // STILL PRESERVED!

    // 5. Successful Overwrite: valid password and intact ciphertext safely replaces file
    let res_overwrite = restore_single_payload(
        &fs::read(&enc).unwrap(),
        &meta,
        true,
        &dest,
        ConflictPolicy::Overwrite,
        &mut cached_key,
        Some(pw),
    );
    assert!(res_overwrite.is_ok());
    assert_eq!(fs::read(&dest).unwrap(), new_content); // Now successfully updated

    let _ = fs::remove_dir_all(&dest_dir);
    let _ = fs::remove_dir_all(&tmp_src);
}

#[test]
fn test_complete_end_to_end_local_snapshot_restore() {
    let tmp_source = create_temp_dest_dir("e2e_source");
    let file1 = tmp_source.join("doc1.txt");
    let file2 = tmp_source.join("sub").join("doc2.json");
    fs::create_dir_all(tmp_source.join("sub")).unwrap();
    fs::write(&file1, b"E2E Document 1 content").unwrap();
    fs::write(&file2, b"{\"key\": \"value 2\"}").unwrap();

    let passphrase = "e2e-restore-passphrase";
    let backup_result = crate::backup::create_local_backup(&tmp_source, Some(passphrase)).unwrap();

    let dest_dir = create_temp_dest_dir("e2e_dest");
    let options = RestoreOptions {
        destination_dir: &dest_dir,
        passphrase: Some(passphrase),
        conflict_policy: ConflictPolicy::Overwrite,
    };

    let restore_result = restore_local_snapshot(&backup_result.backup_id, &options).unwrap();

    assert_eq!(restore_result.total_files, 2);
    assert_eq!(restore_result.files_restored, 2);
    assert_eq!(restore_result.files_failed, 0);
    assert_eq!(restore_result.files_skipped, 0);

    let restored_file1 = dest_dir.join("doc1.txt");
    let restored_file2 = dest_dir.join("sub").join("doc2.json");

    assert!(restored_file1.exists());
    assert!(restored_file2.exists());
    assert_eq!(fs::read(restored_file1).unwrap(), b"E2E Document 1 content");
    assert_eq!(fs::read(restored_file2).unwrap(), b"{\"key\": \"value 2\"}");

    let _ = fs::remove_dir_all(&tmp_source);
    let _ = fs::remove_dir_all(&dest_dir);
    let _ = fs::remove_dir_all(&backup_result.target_directory);
}

#[test]
fn test_missing_source_file_and_missing_snapshot() {
    let dest_dir = create_temp_dest_dir("missing_test");
    let options = RestoreOptions {
        destination_dir: &dest_dir,
        passphrase: Some("some-pass"),
        conflict_policy: ConflictPolicy::Skip,
    };

    // 1. Non-existent snapshot ID fails gracefully
    let res_no_snap = restore_local_snapshot("non_existent_snapshot_id_9999", &options);
    assert!(res_no_snap.is_err());

    // 2. Snapshot where a file is deleted from backup archive before restore
    let tmp_source = create_temp_dest_dir("missing_src");
    let file = tmp_source.join("deleted_later.txt");
    fs::write(&file, b"Will be deleted").unwrap();
    let backup_result = crate::backup::create_local_backup(&tmp_source, Some("pass")).unwrap();

    // Manually delete the .enc file
    let enc_path = Path::new(&backup_result.target_directory)
        .join("data")
        .join("deleted_later.txt.enc");
    let _ = fs::remove_file(enc_path);

    let restore_options = RestoreOptions {
        destination_dir: &dest_dir,
        passphrase: Some("pass"),
        conflict_policy: ConflictPolicy::Skip,
    };

    let restore_result =
        restore_local_snapshot(&backup_result.backup_id, &restore_options).unwrap();
    assert_eq!(restore_result.files_failed, 1);
    assert_eq!(restore_result.files_restored, 0);
    assert!(restore_result.items[0].error.is_some());

    let _ = fs::remove_dir_all(&tmp_source);
    let _ = fs::remove_dir_all(&dest_dir);
    let _ = fs::remove_dir_all(&backup_result.target_directory);
}

#[test]
fn test_restore_encrypted_manifest_success_and_wrong_passphrase() {
    let tmp_src = create_temp_dest_dir("enc_manifest_src");
    let file = tmp_src.join("data.txt");
    fs::write(
        &file,
        b"Highly secret content for encrypted manifest restore",
    )
    .unwrap();

    let pw = "manifest-restore-passphrase";
    let backup_res = crate::backup::create_local_backup(&tmp_src, Some(pw)).unwrap();

    // Verify manifest.json.enc exists on disk and manifest.json does NOT
    let enc_manifest = Path::new(&backup_res.target_directory).join("manifest.json.enc");
    assert!(enc_manifest.exists());
    assert!(!Path::new(&backup_res.target_directory)
        .join("manifest.json")
        .exists());

    let dest_dir = create_temp_dest_dir("enc_manifest_dest");

    // 1. Wrong passphrase fails cleanly and leaves destination directory untouched
    let wrong_options = RestoreOptions {
        destination_dir: &dest_dir,
        passphrase: Some("completely-wrong-password"),
        conflict_policy: ConflictPolicy::Overwrite,
    };
    let wrong_res = restore_local_snapshot(&backup_res.backup_id, &wrong_options);
    assert!(wrong_res.is_err());
    assert!(wrong_res
        .unwrap_err()
        .contains("Manifest decryption failed"));
    assert!(!dest_dir.join("data.txt").exists());

    // 2. Missing passphrase fails cleanly
    let no_pass_options = RestoreOptions {
        destination_dir: &dest_dir,
        passphrase: None,
        conflict_policy: ConflictPolicy::Overwrite,
    };
    let no_pass_res = restore_local_snapshot(&backup_res.backup_id, &no_pass_options);
    assert!(no_pass_res.is_err());

    // 3. Correct passphrase restores file faithfully
    let correct_options = RestoreOptions {
        destination_dir: &dest_dir,
        passphrase: Some(pw),
        conflict_policy: ConflictPolicy::Overwrite,
    };
    let restore_res = restore_local_snapshot(&backup_res.backup_id, &correct_options).unwrap();
    assert_eq!(restore_res.files_restored, 1);
    assert_eq!(restore_res.files_failed, 0);
    assert_eq!(
        fs::read(dest_dir.join("data.txt")).unwrap(),
        b"Highly secret content for encrypted manifest restore"
    );

    let _ = fs::remove_dir_all(&tmp_src);
    let _ = fs::remove_dir_all(&dest_dir);
    let _ = fs::remove_dir_all(&backup_res.target_directory);
}

#[test]
fn test_restore_encrypted_manifest_tampering() {
    let tmp_src = create_temp_dest_dir("tamper_manifest_src");
    let file = tmp_src.join("data.txt");
    fs::write(&file, b"Tamper protection test payload").unwrap();

    let pw = "tamper-passphrase-2026";
    let backup_res = crate::backup::create_local_backup(&tmp_src, Some(pw)).unwrap();
    let enc_manifest_path = Path::new(&backup_res.target_directory).join("manifest.json.enc");

    // Corrupt one byte of the encrypted manifest
    let mut bytes = fs::read(&enc_manifest_path).unwrap();
    let len = bytes.len();
    bytes[len - 2] ^= 0x42; // Corrupt authentication tag
    fs::write(&enc_manifest_path, &bytes).unwrap();

    let dest_dir = create_temp_dest_dir("tamper_manifest_dest");
    let options = RestoreOptions {
        destination_dir: &dest_dir,
        passphrase: Some(pw),
        conflict_policy: ConflictPolicy::Overwrite,
    };

    let res = restore_local_snapshot(&backup_res.backup_id, &options);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Manifest decryption failed"));
    assert!(!dest_dir.join("data.txt").exists());

    let _ = fs::remove_dir_all(&tmp_src);
    let _ = fs::remove_dir_all(&dest_dir);
    let _ = fs::remove_dir_all(&backup_res.target_directory);
}

#[test]
fn test_restore_manifest_substitution_attack_detected() {
    let tmp_src1 = create_temp_dest_dir("subst_src1");
    let tmp_src2 = create_temp_dest_dir("subst_src2");
    fs::write(tmp_src1.join("file1.txt"), b"Content 1").unwrap();
    fs::write(tmp_src2.join("file2.txt"), b"Content 2").unwrap();

    let pw = "subst-passphrase";
    let backup1 = crate::backup::create_local_backup(&tmp_src1, Some(pw)).unwrap();
    let backup2 = crate::backup::create_local_backup(&tmp_src2, Some(pw)).unwrap();

    let manifest1 = Path::new(&backup1.target_directory).join("manifest.json.enc");
    let manifest2 = Path::new(&backup2.target_directory).join("manifest.json.enc");

    // Replace backup2's manifest with backup1's manifest
    fs::copy(&manifest1, &manifest2).unwrap();

    let dest_dir = create_temp_dest_dir("subst_dest");
    let options = RestoreOptions {
        destination_dir: &dest_dir,
        passphrase: Some(pw),
        conflict_policy: ConflictPolicy::Overwrite,
    };

    // Attempting to restore backup2 with backup1's substituted manifest must fail
    let res = restore_local_snapshot(&backup2.backup_id, &options);
    assert!(res.is_err());
    assert!(res
        .unwrap_err()
        .contains("Possible manifest substitution attack detected"));

    let _ = fs::remove_dir_all(&tmp_src1);
    let _ = fs::remove_dir_all(&tmp_src2);
    let _ = fs::remove_dir_all(&dest_dir);
    let _ = fs::remove_dir_all(&backup1.target_directory);
    let _ = fs::remove_dir_all(&backup2.target_directory);
}

#[test]
fn test_restore_legacy_plaintext_manifest_backward_compatibility() {
    let tmp_src = create_temp_dest_dir("legacy_src");
    let file = tmp_src.join("legacy_doc.txt");
    fs::write(&file, b"Legacy backup unencrypted manifest content").unwrap();

    let pw = "legacy-pass";
    let salt = generate_salt();
    let key = derive_key(pw, &salt).unwrap();

    let snap_id = "legacy_snapshot_2026";
    let backups_base = crate::backup::get_backups_dir();
    let snapshot_dir = backups_base.join(snap_id);
    let data_dir = snapshot_dir.join("data");
    fs::create_dir_all(&data_dir).unwrap();

    let enc_file = data_dir.join("legacy_doc.txt.enc");
    encrypt_file(&file, &enc_file, &key, &salt).unwrap();

    let manifest = crate::models::BackupManifest {
        id: snap_id.to_string(),
        source_path: tmp_src.to_string_lossy().to_string(),
        source_name: "legacy".to_string(),
        created_at: chrono::Utc::now(),
        total_files: 1,
        total_size_bytes: fs::metadata(&file).unwrap().len(),
        is_encrypted: true,
        encryption_algorithm: Some("AES-256-GCM / Argon2id".to_string()),
        salt_hex: Some(hex::encode(salt)),
        files: vec![crate::models::FileMetadata {
            relative_path: "legacy_doc.txt".to_string(),
            absolute_path: file.to_string_lossy().to_string(),
            size_bytes: fs::metadata(&file).unwrap().len(),
            sha256_hash: hash_bytes(&fs::read(&file).unwrap()),
            modified_timestamp: 1720000000,
        }],
    };

    // Save as plaintext manifest.json (legacy format)
    let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
    fs::write(snapshot_dir.join("manifest.json"), manifest_json).unwrap();

    let dest_dir = create_temp_dest_dir("legacy_dest");
    let options = RestoreOptions {
        destination_dir: &dest_dir,
        passphrase: Some(pw),
        conflict_policy: ConflictPolicy::Overwrite,
    };

    let restore_res = restore_local_snapshot(snap_id, &options).unwrap();
    assert_eq!(restore_res.files_restored, 1);
    assert_eq!(
        fs::read(dest_dir.join("legacy_doc.txt")).unwrap(),
        b"Legacy backup unencrypted manifest content"
    );

    let _ = fs::remove_dir_all(&tmp_src);
    let _ = fs::remove_dir_all(&dest_dir);
    let _ = fs::remove_dir_all(&snapshot_dir);
}
