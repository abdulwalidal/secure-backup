use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Computes the SHA-256 hash of a file using buffered chunk streaming.
/// Memory usage remains minimal regardless of file size.
pub fn hash_file<P: AsRef<Path>>(path: P) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024]; // 64 KB buffer

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

/// Computes the SHA-256 hash of in-memory bytes.
pub fn hash_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    #[test]
    fn test_hash_empty_file() {
        let temp_path = std::env::temp_dir().join("test_secure_backup_empty.txt");
        let _ = fs::File::create(&temp_path).unwrap();
        // SHA-256 for empty input is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = hash_file(&temp_path).unwrap();
        let _ = fs::remove_file(&temp_path);
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_hash_known_content() {
        let temp_path = std::env::temp_dir().join("test_secure_backup_content.txt");
        let mut file = fs::File::create(&temp_path).unwrap();
        file.write_all(b"secure backup").unwrap();
        drop(file);
        // echo -n "secure backup" | sha256sum -> cb1145101236a8002629f6e0ada7ec7f56d0ec331c9a7a92d3baa532dcd3454b
        let hash = hash_file(&temp_path).unwrap();
        let _ = fs::remove_file(&temp_path);
        assert_eq!(
            hash,
            "cb1145101236a8002629f6e0ada7ec7f56d0ec331c9a7a92d3baa532dcd3454b"
        );
    }
}
