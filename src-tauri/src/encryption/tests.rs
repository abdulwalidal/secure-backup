use super::*;
use std::fs;
use zeroize::Zeroize;

#[test]
fn test_zeroize_key_array() {
    let mut key = [0x5au8; 32];
    assert!(key.iter().all(|&b| b == 0x5a));
    key.zeroize();
    assert_eq!(key, [0u8; 32]);
}

#[test]
fn test_derive_key_and_zeroize() {
    let salt = generate_salt();
    let mut key = derive_key("sample-passphrase-to-zeroize", &salt).unwrap();
    assert_ne!(key, [0u8; 32]);
    key.zeroize();
    assert_eq!(key, [0u8; 32]);
}

#[test]
fn test_zeroize_vector_buffer() {
    let mut sensitive_data = vec![0xffu8; 64];
    assert!(sensitive_data.iter().all(|&b| b == 0xff));
    sensitive_data.zeroize();
    assert!(sensitive_data.iter().all(|&b| b == 0));
}

#[test]
fn test_argon2_key_derivation_deterministic() {
    let salt = [42u8; SALT_LEN];
    let key1 = derive_key("correct-horse-battery", &salt).unwrap();
    let key2 = derive_key("correct-horse-battery", &salt).unwrap();
    assert_eq!(key1, key2);

    let key_wrong = derive_key("different-password", &salt).unwrap();
    assert_ne!(key1, key_wrong);
}

#[test]
fn test_aes256_gcm_roundtrip() {
    let salt = generate_salt();
    let key = derive_key("my-secret-vault", &salt).unwrap();
    let original_data = b"Highly confidential backup data. Keep safe.";

    let (ciphertext, nonce) = encrypt_bytes(original_data, &key).unwrap();
    assert_ne!(&ciphertext[..], original_data);

    let decrypted = decrypt_bytes(&ciphertext, &nonce, &key).unwrap();
    assert_eq!(&decrypted[..], original_data);
}

#[test]
fn test_tamper_detection() {
    let salt = generate_salt();
    let key = derive_key("integrity-test-passphrase", &salt).unwrap();
    let original_data = b"Tamper detection verification string.";

    let (mut ciphertext, nonce) = encrypt_bytes(original_data, &key).unwrap();

    // Flip one bit in ciphertext to simulate tampering or corruption
    ciphertext[0] ^= 0x01;

    let result = decrypt_bytes(&ciphertext, &nonce, &key);
    assert!(result.is_err());
}

#[test]
fn test_file_encryption_and_decryption() {
    let tmp = std::env::temp_dir();
    let plain_src = tmp.join("sb_plain_test.txt");
    let enc_dest = tmp.join("sb_test.enc");
    let dec_dest = tmp.join("sb_restored_test.txt");

    let test_content = b"Zero-knowledge encrypted desktop file on Ubuntu Linux!";
    fs::write(&plain_src, test_content).unwrap();

    let salt = generate_salt();
    let key = derive_key("test-password-123", &salt).unwrap();

    // Encrypt file
    encrypt_file(&plain_src, &enc_dest, &key, &salt).unwrap();

    // Ensure encrypted file content is not plaintext
    let enc_bytes = fs::read(&enc_dest).unwrap();
    assert!(!enc_bytes
        .windows(test_content.len())
        .any(|w| w == test_content));

    // Decrypt with correct password
    decrypt_file(&enc_dest, &dec_dest, "test-password-123").unwrap();
    let restored = fs::read(&dec_dest).unwrap();
    assert_eq!(restored, test_content);

    // Decrypt with WRONG password should fail
    let wrong_dest = tmp.join("sb_wrong_test.txt");
    let bad_result = decrypt_file(&enc_dest, &wrong_dest, "wrong-password");
    assert!(bad_result.is_err());

    // Cleanup
    let _ = fs::remove_file(plain_src);
    let _ = fs::remove_file(enc_dest);
    let _ = fs::remove_file(dec_dest);
    let _ = fs::remove_file(wrong_dest);
}

#[test]
fn test_archive_payload_roundtrip_and_structure() {
    let password = "manifest-test-passphrase-2026";
    let original_data = b"{\"snapshot_id\": \"snap_123\", \"files\": [\"a.txt\", \"b.txt\"]}";

    let encrypted = encrypt_archive_payload_with_passphrase(original_data, password)
        .expect("Encryption failed");

    // Verify SECBKP01 structure: 8B magic + 16B salt + 12B nonce + ciphertext + 16B GCM tag
    assert!(encrypted.len() >= 8 + SALT_LEN + NONCE_LEN + 16);
    assert_eq!(&encrypted[..8], MAGIC_HEADER);

    // Verify salt can be extracted
    let salt = extract_salt_from_archive(&encrypted).expect("Salt extraction failed");
    assert_eq!(&salt[..], &encrypted[8..24]);

    // Verify successful decryption with correct passphrase
    let decrypted = decrypt_archive_payload(&encrypted, password).expect("Decryption failed");
    assert_eq!(decrypted, original_data);

    // Verify decryption with wrong passphrase fails
    let wrong_res = decrypt_archive_payload(&encrypted, "wrong-passphrase");
    assert!(wrong_res.is_err());
}

#[test]
fn test_archive_payload_tampering_detection() {
    let password = "tamper-protection-passphrase";
    let original_data = b"Top secret backup manifest payload.";

    let encrypted = encrypt_archive_payload_with_passphrase(original_data, password)
        .expect("Encryption failed");

    // 1. Corrupt magic header
    let mut bad_header = encrypted.clone();
    bad_header[0] = b'X';
    assert!(decrypt_archive_payload(&bad_header, password).is_err());

    // 2. Corrupt salt
    let mut bad_salt = encrypted.clone();
    bad_salt[8] ^= 0xff;
    assert!(decrypt_archive_payload(&bad_salt, password).is_err());

    // 3. Corrupt nonce
    let mut bad_nonce = encrypted.clone();
    bad_nonce[24] ^= 0x55;
    assert!(decrypt_archive_payload(&bad_nonce, password).is_err());

    // 4. Corrupt ciphertext body
    let mut bad_ciphertext = encrypted.clone();
    bad_ciphertext[36] ^= 0xaa;
    assert!(decrypt_archive_payload(&bad_ciphertext, password).is_err());

    // 5. Corrupt GCM authentication tag (last 16 bytes)
    let mut bad_tag = encrypted.clone();
    let last_idx = bad_tag.len() - 1;
    bad_tag[last_idx] ^= 0x01;
    assert!(decrypt_archive_payload(&bad_tag, password).is_err());

    // 6. Truncated payload
    let truncated = &encrypted[..20];
    assert!(decrypt_archive_payload(truncated, password).is_err());
}
