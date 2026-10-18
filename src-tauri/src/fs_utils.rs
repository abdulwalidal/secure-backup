use std::fs;
use std::io;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Ensures that a directory exists and enforces restrictive permissions (0700: rwx------) on Unix.
///
/// If the directory does not exist, it is created along with all parent components.
/// If it already exists, its permissions are updated to 0700 to harden existing installations.
/// On non-Unix platforms (such as Windows), this creates the directory if needed and performs no-op for permissions.
pub fn ensure_secure_dir(path: &Path) -> io::Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
    }

    #[cfg(unix)]
    {
        let permissions = fs::Permissions::from_mode(0o700);
        fs::set_permissions(path, permissions)?;
    }

    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}

/// Enforces restrictive permissions (0600: rw-------) on an existing file on Unix.
///
/// On non-Unix platforms (such as Windows), this is a safe no-op.
pub fn ensure_secure_file(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let permissions = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions)?;
    }

    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn test_ensure_secure_dir_creates_with_0700() {
        let temp_dir =
            std::env::temp_dir().join(format!("secbkp_fsutil_dir_new_{}", uuid::Uuid::new_v4()));
        let _ = fs::remove_dir_all(&temp_dir);

        ensure_secure_dir(&temp_dir).expect("ensure_secure_dir should succeed");
        assert!(temp_dir.exists());

        let metadata = fs::metadata(&temp_dir).expect("metadata should succeed");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "Newly created directory must have 0700 permissions"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    #[cfg(unix)]
    fn test_ensure_secure_dir_hardens_existing_permissive_directory() {
        let temp_dir =
            std::env::temp_dir().join(format!("secbkp_fsutil_dir_harden_{}", uuid::Uuid::new_v4()));
        let _ = fs::remove_dir_all(&temp_dir);

        fs::create_dir_all(&temp_dir).expect("create_dir_all should succeed");
        fs::set_permissions(&temp_dir, fs::Permissions::from_mode(0o755))
            .expect("set 0755 permissions");

        let mode_before = fs::metadata(&temp_dir)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode_before, 0o755);

        ensure_secure_dir(&temp_dir).expect("ensure_secure_dir on existing dir");
        let mode_after = fs::metadata(&temp_dir)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode_after, 0o700,
            "Permissive 0755 directory must be hardened to 0700"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    #[cfg(unix)]
    fn test_ensure_secure_file_hardens_existing_file() {
        let temp_file =
            std::env::temp_dir().join(format!("secbkp_fsutil_file_{}.txt", uuid::Uuid::new_v4()));
        let _ = fs::remove_file(&temp_file);

        fs::write(&temp_file, b"confidential content").expect("write file");
        fs::set_permissions(&temp_file, fs::Permissions::from_mode(0o644))
            .expect("set 0644 permissions");

        let mode_before = fs::metadata(&temp_file)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode_before, 0o644);

        ensure_secure_file(&temp_file).expect("ensure_secure_file should succeed");
        let mode_after = fs::metadata(&temp_file)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode_after, 0o600,
            "Permissive 0644 file must be hardened to 0600"
        );

        let _ = fs::remove_file(&temp_file);
    }
}
