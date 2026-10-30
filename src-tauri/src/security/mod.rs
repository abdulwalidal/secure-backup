#[cfg(unix)]
use std::fs;
use std::io;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Restricts an application-owned directory to its owner on Unix systems.
///
/// On Windows, this function currently leaves the existing Windows ACLs
/// unchanged because POSIX permission modes do not apply there.
pub fn protect_directory<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let path = path.as_ref();

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

/// Restricts an application-owned file to its owner on Unix systems.
///
/// On Windows, this function leaves the existing Windows ACLs unchanged
/// because POSIX permission modes do not apply there.
pub fn protect_file<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let path = path.as_ref();

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
mod tests;
