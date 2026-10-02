use crate::cloud::gdrive::GoogleDriveProvider;
use crate::encryption::{
    decrypt_archive_payload_with_key, derive_key, extract_salt_from_archive, SALT_LEN,
};
use crate::hashing::hash_bytes;
use crate::models::{BackupManifest, FileMetadata};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[cfg(test)]
pub mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictPolicy {
    Skip,
    Overwrite,
    Fail,
}

impl Default for ConflictPolicy {
    fn default() -> Self {
        ConflictPolicy::Skip
    }
}

impl std::str::FromStr for ConflictPolicy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "skip" => Ok(ConflictPolicy::Skip),
            "overwrite" => Ok(ConflictPolicy::Overwrite),
            "fail" | "cancel" => Ok(ConflictPolicy::Fail),
            other => Err(format!(
                "Invalid conflict policy '{}'. Valid options: 'skip', 'overwrite', 'fail'.",
                other
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreSource {
    Local,
    GoogleDrive,
}

impl std::str::FromStr for RestoreSource {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "local" => Ok(RestoreSource::Local),
            "google_drive" | "googledrive" | "cloud" => Ok(RestoreSource::GoogleDrive),
            other => Err(format!(
                "Invalid restore source '{}'. Valid options: 'local', 'google_drive'.",
                other
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreFileItem {
    pub relative_path: String,
    pub status: String, // "restored", "skipped", "failed"
    pub size_bytes: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreResult {
    pub snapshot_id: String,
    pub destination_directory: String,
    pub source: RestoreSource,
    pub total_files: usize,
    pub files_restored: usize,
    pub files_skipped: usize,
    pub files_failed: usize,
    pub total_bytes_restored: u64,
    pub elapsed_millis: u128,
    pub items: Vec<RestoreFileItem>,
}

pub struct RestoreOptions<'a> {
    pub destination_dir: &'a Path,
    pub passphrase: Option<&'a str>,
    pub conflict_policy: ConflictPolicy,
}

/// Validates a relative file path against directory traversal attacks and resolves
/// it safely against the selected destination root directory.
///
/// Security rules enforced:
/// - Rejects null bytes
/// - Rejects Windows UNC network paths (`\\server\...`, `//server/...`)
/// - Rejects Windows drive prefix paths (`C:\...`, `D:...`)
/// - Rejects absolute POSIX paths (`/...`)
/// - Rejects relative parent traversal components (`..`)
/// - Rejects component colons (Windows alternate data streams / volume letters)
/// - Normalizes both forward and backslashes cross-platform
/// - Enforces that the canonical resolved path strictly resides inside the canonical destination root
/// - Rejects symlinks at destination
pub fn validate_and_resolve_destination(
    dest_root: &Path,
    rel_path: &str,
) -> Result<PathBuf, String> {
    let trimmed = rel_path.trim();
    if trimmed.is_empty() {
        return Err("Path is empty.".to_string());
    }

    if trimmed.contains('\0') {
        return Err("Path contains null byte.".to_string());
    }

    // Reject Windows UNC paths
    if trimmed.starts_with("\\\\") || trimmed.starts_with("//") {
        return Err(format!("Windows UNC path rejected: '{}'", trimmed));
    }

    // Reject Windows drive letters (e.g. C:\... or C:... or c:/...)
    let bytes = trimmed.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(format!("Windows drive path rejected: '{}'", trimmed));
    }

    // Reject absolute paths
    if trimmed.starts_with('/') || trimmed.starts_with('\\') {
        return Err(format!("Absolute path rejected: '{}'", trimmed));
    }

    // Normalize backslashes to forward slashes for cross-platform component validation
    let normalized = trimmed.replace('\\', "/");

    let mut safe_parts = Vec::new();
    for part in normalized.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err(format!(
                "Path traversal component '..' detected in: '{}'",
                trimmed
            ));
        }
        if part.contains(':') {
            return Err(format!(
                "Path component contains illegal character ':': '{}'",
                part
            ));
        }
        safe_parts.push(part);
    }

    if safe_parts.is_empty() {
        return Err("Path resolves to empty root.".to_string());
    }

    // Canonicalize destination root
    let canonical_dest = dest_root
        .canonicalize()
        .map_err(|e| format!("Destination directory {:?} does not exist or cannot be accessed: {}", dest_root, e))?;

    if !canonical_dest.is_dir() {
        return Err(format!("Destination path {:?} is not a directory.", dest_root));
    }

    let mut target = canonical_dest.clone();
    for part in &safe_parts {
        target.push(part);
    }

    // Ensure the constructed target does not resolve outside canonical_dest
    // Check nearest existing ancestor
    let mut ancestor = target.clone();
    while !ancestor.exists() {
        if let Some(parent) = ancestor.parent() {
            ancestor = parent.to_path_buf();
        } else {
            break;
        }
    }

    if ancestor.exists() {
        let canonical_ancestor = ancestor
            .canonicalize()
            .map_err(|e| format!("Failed to canonicalize ancestor {:?}: {}", ancestor, e))?;

        if !canonical_ancestor.starts_with(&canonical_dest) {
            return Err(format!(
                "Path traversal violation: resolved path {:?} escapes destination {:?}",
                target, canonical_dest
            ));
        }
    }

    // Reject symlinks at destination
    if target.is_symlink() {
        return Err(format!(
            "Destination path {:?} is an existing symlink (rejected for security).",
            target
        ));
    }

    Ok(target)
}

enum FileRestoreOutcome {
    Restored { bytes: u64 },
    Skipped { reason: String },
}

/// Restores a single file payload to the destination path according to conflict policy,
/// decryption requirements, and SHA-256 integrity verification.
///
/// CRITICAL: In overwrite mode, destination files are NEVER touched or modified until:
/// 1. Payload decryption succeeds (and AES-GCM 16-byte authentication tag validates)
/// 2. SHA-256 verification succeeds against expected metadata hash.
fn restore_single_payload(
    file_bytes: &[u8],
    file_meta: &FileMetadata,
    is_encrypted: bool,
    dest_path: &Path,
    conflict_policy: ConflictPolicy,
    cached_key: &mut Option<([u8; SALT_LEN], String, [u8; 32])>,
    passphrase: Option<&str>,
) -> Result<FileRestoreOutcome, String> {
    // 1. Check existing file according to conflict policy
    if dest_path.exists() {
        match conflict_policy {
            ConflictPolicy::Skip => {
                return Ok(FileRestoreOutcome::Skipped {
                    reason: "File already exists in destination".to_string(),
                });
            }
            ConflictPolicy::Fail => {
                return Err(format!(
                    "Destination file already exists: {:?}",
                    dest_path
                ));
            }
            ConflictPolicy::Overwrite => {
                // Proceed with decrypt & verify FIRST before touching existing file
            }
        }
    }

    // 2. Decrypt or use raw bytes
    let plaintext = if is_encrypted {
        let pw = passphrase
            .ok_or_else(|| "Passphrase is required to decrypt snapshot files.".to_string())?;

        let file_salt = extract_salt_from_archive(file_bytes)?;
        let pw_hash = hash_bytes(pw.as_bytes());

        // Reuse cached derived key if salt and passphrase match
        let key = match cached_key {
            Some((cached_salt, cached_pw_hash, k))
                if *cached_salt == file_salt && *cached_pw_hash == pw_hash =>
            {
                *k
            }
            _ => {
                let derived = derive_key(pw, &file_salt)?;
                *cached_key = Some((file_salt, pw_hash, derived));
                derived
            }
        };

        match decrypt_archive_payload_with_key(file_bytes, &key) {
            Ok(p) => p,
            Err(e) => {
                *cached_key = None;
                return Err(e);
            }
        }
    } else {
        file_bytes.to_vec()
    };

    // 3. Verify SHA-256 checksum on decrypted plaintext
    if !file_meta.sha256_hash.trim().is_empty() {
        let computed_hash = hash_bytes(&plaintext);
        if computed_hash.to_ascii_lowercase() != file_meta.sha256_hash.trim().to_ascii_lowercase() {
            return Err(format!(
                "SHA-256 integrity mismatch for '{}': expected {}, computed {}",
                file_meta.relative_path, file_meta.sha256_hash, computed_hash
            ));
        }
    }

    // 4. Verification succeeded - now safely write plaintext to destination
    if let Some(parent) = dest_path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            format!("Failed to create parent directory {:?}: {}", parent, e)
        })?;
    }

    let bytes_len = plaintext.len() as u64;

    // Use atomic temporary write in same parent directory then rename
    let temp_dest = dest_path.with_extension(format!("sbtmp_{}", rand::random::<u32>()));
    {
        let mut temp_file = File::create(&temp_dest).map_err(|e| {
            format!("Failed to create temporary file {:?}: {}", temp_dest, e)
        })?;
        temp_file.write_all(&plaintext).map_err(|e| {
            let _ = fs::remove_file(&temp_dest);
            format!("Failed to write plaintext {:?}: {}", temp_dest, e)
        })?;
    }

    fs::rename(&temp_dest, dest_path).map_err(|e| {
        let _ = fs::remove_file(&temp_dest);
        format!("Failed to finalize restored file {:?}: {}", dest_path, e)
    })?;

    Ok(FileRestoreOutcome::Restored { bytes: bytes_len })
}

/// Restores a snapshot from the local backup storage directory.
pub fn restore_local_snapshot(
    snapshot_id: &str,
    options: &RestoreOptions,
) -> Result<RestoreResult, String> {
    let start_time = Instant::now();
    let backups_base = crate::backup::get_backups_dir();
    let snapshot_dir = backups_base.join(snapshot_id);

    if !snapshot_dir.exists() {
        return Err(format!(
            "Local snapshot folder for '{}' not found at {:?}. If this was created on another machine, use Google Drive restore.",
            snapshot_id, snapshot_dir
        ));
    }

    let manifest_path = snapshot_dir.join("manifest.json");
    if !manifest_path.exists() {
        return Err(format!(
            "Snapshot manifest not found at {:?}.",
            manifest_path
        ));
    }

    let manifest_content = fs::read_to_string(&manifest_path)
        .map_err(|e| format!("Failed to read manifest {:?}: {}", manifest_path, e))?;

    let manifest: BackupManifest = serde_json::from_str(&manifest_content)
        .map_err(|e| format!("Failed to parse manifest JSON: {}", e))?;

    let mut files_restored = 0;
    let mut files_skipped = 0;
    let mut files_failed = 0;
    let mut total_bytes_restored = 0u64;
    let mut items = Vec::new();
    let mut cached_key = None;

    let data_dir = snapshot_dir.join("data");

    for file_meta in &manifest.files {
        // Validate target path
        let dest_path = match validate_and_resolve_destination(options.destination_dir, &file_meta.relative_path) {
            Ok(p) => p,
            Err(e) => {
                files_failed += 1;
                items.push(RestoreFileItem {
                    relative_path: file_meta.relative_path.clone(),
                    status: "failed".to_string(),
                    size_bytes: file_meta.size_bytes,
                    error: Some(e),
                });
                continue;
            }
        };

        // Locate source file on disk
        let candidates = [
            data_dir.join(format!("{}.enc", file_meta.relative_path)),
            data_dir.join(&file_meta.relative_path),
            snapshot_dir.join(format!("{}.enc", file_meta.relative_path)),
            snapshot_dir.join(&file_meta.relative_path),
        ];

        let src_file_path = candidates.iter().find(|p| p.exists());

        let src_path = match src_file_path {
            Some(p) => p,
            None => {
                files_failed += 1;
                items.push(RestoreFileItem {
                    relative_path: file_meta.relative_path.clone(),
                    status: "failed".to_string(),
                    size_bytes: file_meta.size_bytes,
                    error: Some(format!("Source backup file missing on disk for '{}'", file_meta.relative_path)),
                });
                continue;
            }
        };

        let file_bytes = match fs::read(src_path) {
            Ok(b) => b,
            Err(e) => {
                files_failed += 1;
                items.push(RestoreFileItem {
                    relative_path: file_meta.relative_path.clone(),
                    status: "failed".to_string(),
                    size_bytes: file_meta.size_bytes,
                    error: Some(format!("Failed to read source file {:?}: {}", src_path, e)),
                });
                continue;
            }
        };

        match restore_single_payload(
            &file_bytes,
            file_meta,
            manifest.is_encrypted,
            &dest_path,
            options.conflict_policy,
            &mut cached_key,
            options.passphrase,
        ) {
            Ok(FileRestoreOutcome::Restored { bytes }) => {
                files_restored += 1;
                total_bytes_restored += bytes;
                items.push(RestoreFileItem {
                    relative_path: file_meta.relative_path.clone(),
                    status: "restored".to_string(),
                    size_bytes: bytes,
                    error: None,
                });
            }
            Ok(FileRestoreOutcome::Skipped { reason }) => {
                files_skipped += 1;
                items.push(RestoreFileItem {
                    relative_path: file_meta.relative_path.clone(),
                    status: "skipped".to_string(),
                    size_bytes: file_meta.size_bytes,
                    error: Some(reason),
                });
            }
            Err(err) => {
                files_failed += 1;
                items.push(RestoreFileItem {
                    relative_path: file_meta.relative_path.clone(),
                    status: "failed".to_string(),
                    size_bytes: file_meta.size_bytes,
                    error: Some(err),
                });
            }
        }
    }

    Ok(RestoreResult {
        snapshot_id: snapshot_id.to_string(),
        destination_directory: options.destination_dir.to_string_lossy().to_string(),
        source: RestoreSource::Local,
        total_files: manifest.files.len(),
        files_restored,
        files_skipped,
        files_failed,
        total_bytes_restored,
        elapsed_millis: start_time.elapsed().as_millis(),
        items,
    })
}

/// Restores a snapshot directly from Google Drive cloud storage without storing
/// unencrypted intermediate files on disk.
pub fn restore_cloud_snapshot(
    conn: &Connection,
    snapshot_id: &str,
    options: &RestoreOptions,
) -> Result<RestoreResult, String> {
    let start_time = Instant::now();
    let access_token = GoogleDriveProvider::get_valid_access_token(conn)?;

    // 1. Locate "Secure Backup Vault" root folder
    let search_query =
        "name = 'Secure Backup Vault' and mimeType = 'application/vnd.google-apps.folder' and trashed = false";

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("HTTP client init failed: {}", e))?;

    let search_res = client
        .get("https://www.googleapis.com/drive/v3/files")
        .bearer_auth(&access_token)
        .query(&[("q", search_query), ("fields", "files(id, name)")])
        .send()
        .map_err(|e| format!("Google Drive vault search failed: {}", e))?;

    #[derive(Deserialize)]
    struct FileEntry {
        id: String,
    }
    #[derive(Deserialize)]
    struct FileList {
        files: Vec<FileEntry>,
    }

    let vault_id = if search_res.status().is_success() {
        let list: FileList = search_res
            .json()
            .map_err(|e| format!("Failed to parse vault search response: {}", e))?;
        list.files.first().map(|f| f.id.clone())
    } else {
        None
    }
    .ok_or_else(|| "Google Drive 'Secure Backup Vault' not found. Please sync a backup first.".to_string())?;

    // 2. Locate snapshot subfolder in vault
    let snapshot_folder_query = format!(
        "name = '{}' and mimeType = 'application/vnd.google-apps.folder' and '{}' in parents and trashed = false",
        snapshot_id.replace('\'', "\\'"),
        vault_id
    );

    let snap_search_res = client
        .get("https://www.googleapis.com/drive/v3/files")
        .bearer_auth(&access_token)
        .query(&[("q", snapshot_folder_query.as_str()), ("fields", "files(id, name)")])
        .send()
        .map_err(|e| format!("Snapshot search in Google Drive failed: {}", e))?;

    let snapshot_folder_id = if snap_search_res.status().is_success() {
        let list: FileList = snap_search_res
            .json()
            .map_err(|e| format!("Failed to parse snapshot search response: {}", e))?;
        list.files.first().map(|f| f.id.clone())
    } else {
        None
    }
    .ok_or_else(|| format!("Snapshot folder '{}' not found in Google Drive vault.", snapshot_id))?;

    // 3. List files inside snapshot folder
    let children = GoogleDriveProvider::list_children(&access_token, &snapshot_folder_id, None)?;

    // 4. Download manifest.json
    let manifest_file = children
        .iter()
        .find(|(_, name)| name == "manifest.json")
        .ok_or_else(|| format!("No manifest.json found in Google Drive snapshot '{}'.", snapshot_id))?;

    let manifest_bytes = GoogleDriveProvider::download_file_bytes(&access_token, &manifest_file.0)?;
    let manifest: BackupManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("Failed to parse remote manifest.json: {}", e))?;

    let mut files_restored = 0;
    let mut files_skipped = 0;
    let mut files_failed = 0;
    let mut total_bytes_restored = 0u64;
    let mut items = Vec::new();
    let mut cached_key = None;

    for file_meta in &manifest.files {
        // Validate destination path
        let dest_path = match validate_and_resolve_destination(options.destination_dir, &file_meta.relative_path) {
            Ok(p) => p,
            Err(e) => {
                files_failed += 1;
                items.push(RestoreFileItem {
                    relative_path: file_meta.relative_path.clone(),
                    status: "failed".to_string(),
                    size_bytes: file_meta.size_bytes,
                    error: Some(e),
                });
                continue;
            }
        };

        // Determine expected remote filename
        let original_name = Path::new(&file_meta.relative_path)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());

        let candidates = if manifest.is_encrypted {
            vec![
                format!("{}.enc", original_name),
                format!("{}.enc", file_meta.relative_path),
                original_name.clone(),
            ]
        } else {
            vec![original_name.clone(), file_meta.relative_path.clone()]
        };

        let remote_file = children.iter().find(|(_, name)| candidates.contains(name));

        let remote_file_id = match remote_file {
            Some((id, _)) => id,
            None => {
                files_failed += 1;
                items.push(RestoreFileItem {
                    relative_path: file_meta.relative_path.clone(),
                    status: "failed".to_string(),
                    size_bytes: file_meta.size_bytes,
                    error: Some(format!("Remote file object missing in cloud snapshot for '{}'", file_meta.relative_path)),
                });
                continue;
            }
        };

        // Download directly into memory
        let file_bytes = match GoogleDriveProvider::download_file_bytes(&access_token, remote_file_id) {
            Ok(b) => b,
            Err(e) => {
                files_failed += 1;
                items.push(RestoreFileItem {
                    relative_path: file_meta.relative_path.clone(),
                    status: "failed".to_string(),
                    size_bytes: file_meta.size_bytes,
                    error: Some(format!("Failed to download file from Google Drive: {}", e)),
                });
                continue;
            }
        };

        // Decrypt, verify, and write
        match restore_single_payload(
            &file_bytes,
            file_meta,
            manifest.is_encrypted,
            &dest_path,
            options.conflict_policy,
            &mut cached_key,
            options.passphrase,
        ) {
            Ok(FileRestoreOutcome::Restored { bytes }) => {
                files_restored += 1;
                total_bytes_restored += bytes;
                items.push(RestoreFileItem {
                    relative_path: file_meta.relative_path.clone(),
                    status: "restored".to_string(),
                    size_bytes: bytes,
                    error: None,
                });
            }
            Ok(FileRestoreOutcome::Skipped { reason }) => {
                files_skipped += 1;
                items.push(RestoreFileItem {
                    relative_path: file_meta.relative_path.clone(),
                    status: "skipped".to_string(),
                    size_bytes: file_meta.size_bytes,
                    error: Some(reason),
                });
            }
            Err(err) => {
                files_failed += 1;
                items.push(RestoreFileItem {
                    relative_path: file_meta.relative_path.clone(),
                    status: "failed".to_string(),
                    size_bytes: file_meta.size_bytes,
                    error: Some(err),
                });
            }
        }
    }

    Ok(RestoreResult {
        snapshot_id: snapshot_id.to_string(),
        destination_directory: options.destination_dir.to_string_lossy().to_string(),
        source: RestoreSource::GoogleDrive,
        total_files: manifest.files.len(),
        files_restored,
        files_skipped,
        files_failed,
        total_bytes_restored,
        elapsed_millis: start_time.elapsed().as_millis(),
        items,
    })
}
