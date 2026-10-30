#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
#[test]
fn protect_directory_sets_owner_only_permissions() {
    let directory = std::env::temp_dir().join("secure_backup_security_test_dir");

    if directory.exists() {
        std::fs::remove_dir_all(&directory).unwrap();
    }

    std::fs::create_dir(&directory).unwrap();

    crate::security::protect_directory(&directory).unwrap();

    let mode = std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777;

    assert_eq!(mode, 0o700);

    std::fs::remove_dir_all(&directory).unwrap();
}

#[cfg(unix)]
#[test]
fn protect_file_sets_owner_only_permissions() {
    let file = std::env::temp_dir().join("secure_backup_security_test_file");

    if file.exists() {
        std::fs::remove_file(&file).unwrap();
    }

    std::fs::write(&file, b"test").unwrap();

    crate::security::protect_file(&file).unwrap();

    let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;

    assert_eq!(mode, 0o600);

    std::fs::remove_file(&file).unwrap();
}
#[cfg(windows)]
#[test]
fn protect_functions_succeed_on_windows() {
    let directory = std::env::temp_dir().join("secure_backup_security_test_dir");

    if directory.exists() {
        std::fs::remove_dir_all(&directory).unwrap();
    }

    std::fs::create_dir(&directory).unwrap();

    crate::security::protect_directory(&directory).unwrap();

    let file = directory.join("protected.txt");
    std::fs::write(&file, b"test").unwrap();

    crate::security::protect_file(&file).unwrap();

    std::fs::remove_dir_all(&directory).unwrap();
}
