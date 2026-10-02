use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const MAGIC_HEADER: &[u8; 8] = b"SECBKP01";

/// Generates a cryptographically secure random 16-byte salt using the OS RNG.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generates a cryptographically secure random 12-byte nonce for AES-GCM.
pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Derives a 256-bit encryption key from a passphrase and a salt using Argon2id.
pub fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    let params = Params::new(
        19 * 1024, // 19 MiB memory cost
        2,         // 2 iterations
        1,         // 1 degree of parallelism
        Some(32),  // 32-byte (256-bit) output
    )
    .map_err(|e| format!("Argon2 params error: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Key derivation error: {}", e))?;

    Ok(key)
}

/// Encrypts in-memory bytes with AES-256-GCM.
pub fn encrypt_bytes(data: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, [u8; NONCE_LEN]), String> {
    let nonce_bytes = generate_nonce();
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Failed to initialize cipher: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| format!("Encryption error: {}", e))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypts in-memory ciphertext with AES-256-GCM.
pub fn decrypt_bytes(
    ciphertext: &[u8],
    nonce_bytes: &[u8; NONCE_LEN],
    key: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Failed to initialize cipher: {}", e))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
        "Decryption failed: invalid passphrase or corrupted/tampered data.".to_string()
    })?;

    Ok(plaintext)
}

/// Encrypts a source file into a destination file with the binary format:
/// [ MAGIC (8B) | SALT (16B) | NONCE (12B) | CIPHERTEXT + TAG ]
pub fn encrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(
    src: P,
    dest: Q,
    key: &[u8; 32],
    salt: &[u8; SALT_LEN],
) -> io::Result<()> {
    let mut file = File::open(src)?;
    let mut plaintext = Vec::new();
    file.read_to_end(&mut plaintext)?;

    let (ciphertext, nonce) = encrypt_bytes(&plaintext, key).map_err(io::Error::other)?;

    let mut out = File::create(dest)?;
    out.write_all(MAGIC_HEADER)?;
    out.write_all(salt)?;
    out.write_all(&nonce)?;
    out.write_all(&ciphertext)?;

    Ok(())
}

/// Decrypts the raw byte payload of a SECBKP01 encrypted archive.
pub fn decrypt_archive_payload(buffer: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let header_len = MAGIC_HEADER.len() + SALT_LEN + NONCE_LEN;
    if buffer.len() < header_len {
        return Err("File is too small to be a valid Secure Backup encrypted archive.".to_string());
    }

    if &buffer[..8] != MAGIC_HEADER {
        return Err("Invalid file format: missing Secure Backup magic header.".to_string());
    }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&buffer[8..24]);

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&buffer[24..36]);

    let ciphertext = &buffer[36..];

    let key = derive_key(password, &salt)?;
    decrypt_bytes(ciphertext, &nonce, &key)
}

/// Extracts the 16-byte Argon2id salt from a SECBKP01 encrypted archive header.
pub fn extract_salt_from_archive(buffer: &[u8]) -> Result<[u8; SALT_LEN], String> {
    let header_len = MAGIC_HEADER.len() + SALT_LEN + NONCE_LEN;
    if buffer.len() < header_len {
        return Err("File is too small to be a valid Secure Backup encrypted archive.".to_string());
    }
    if &buffer[..8] != MAGIC_HEADER {
        return Err("Invalid file format: missing Secure Backup magic header.".to_string());
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&buffer[8..24]);
    Ok(salt)
}

/// Decrypts a SECBKP01 archive payload using an already-derived AES-256 key.
pub fn decrypt_archive_payload_with_key(buffer: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let header_len = MAGIC_HEADER.len() + SALT_LEN + NONCE_LEN;
    if buffer.len() < header_len {
        return Err("File is too small to be a valid Secure Backup encrypted archive.".to_string());
    }

    if &buffer[..8] != MAGIC_HEADER {
        return Err("Invalid file format: missing Secure Backup magic header.".to_string());
    }

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&buffer[24..36]);

    let ciphertext = &buffer[36..];
    decrypt_bytes(ciphertext, &nonce, key)
}

/// Decrypts an encrypted file produced by `encrypt_file` using the provided passphrase.
pub fn decrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(
    src: P,
    dest: Q,
    password: &str,
) -> io::Result<()> {
    let mut file = File::open(src)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let plaintext = decrypt_archive_payload(&buffer, password)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut out = File::create(dest)?;
    out.write_all(&plaintext)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
}
