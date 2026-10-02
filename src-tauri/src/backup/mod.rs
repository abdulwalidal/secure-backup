use crate::encryption::{derive_key, encrypt_file, generate_salt};
use crate::hashing::hash_file;
use crate::models::{BackupManifest, BackupResult, FileMetadata};
use chrono::Utc;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

/// Base directory for local backups: ~/.local/share/secure-backup/backups
pub fn get_backups_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("secure-backup")
        .join("backups")
}

/// Recursively scans a source directory, computing file metadata and SHA-256 hashes.
pub fn scan_directory<P: AsRef<Path>>(source: P) -> io::Result<Vec<FileMetadata>> {
    let source_path = source.as_ref();
    let mut files = Vec::new();

    for entry in WalkDir::new(source_path)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() {
            let abs_path = entry.path().to_path_buf();
            let rel_path = match abs_path.strip_prefix(source_path) {
                Ok(p) => p.to_string_lossy().to_string(),
                Err(_) => entry.file_name().to_string_lossy().to_string(),
            };

            let metadata = entry.metadata()?;
            let size_bytes = metadata.len();
            let modified_timestamp = metadata
                .modified()
                .unwrap_or(SystemTime::now())
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let sha256_hash = hash_file(&abs_path)?;

            files.push(FileMetadata {
                relative_path: rel_path,
                absolute_path: abs_path.to_string_lossy().to_string(),
                size_bytes,
                sha256_hash,
                modified_timestamp,
                stored_filename: None,
            });
        }
    }

    Ok(files)
}

/// Creates a structured local backup for the given source directory.
/// If a passphrase is provided, all files are encrypted using AES-256-GCM with Argon2id.
pub fn create_local_backup<P: AsRef<Path>>(
    source: P,
    passphrase: Option<&str>,
) -> io::Result<BackupResult> {
    let start_time = Instant::now();
    let source_path = source.as_ref();

    if !source_path.exists() || !source_path.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Source directory does not exist or is not a directory.",
        ));
    }

    let source_name = source_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "backup".to_string());

    // 1. Scan and hash all files
    let mut files = scan_directory(source_path)?;
    let total_size_bytes: u64 = files.iter().map(|f| f.size_bytes).sum();
    let total_files = files.len();

    let is_encrypted = passphrase.is_some() && !passphrase.unwrap().trim().is_empty();

    // 2. Prepare backup snapshot folder
    let backup_id = if is_encrypted {
        format!(
            "{}_{}",
            Utc::now().format("%Y%m%d_%H%M%S"),
            uuid::Uuid::new_v4()
        )
    } else {
        format!("{}_{}", Utc::now().format("%Y%m%d_%H%M%S"), source_name)
    };
    let backups_base = get_backups_dir();
    let snapshot_dir = backups_base.join(&backup_id);
    let snapshot_data_dir = snapshot_dir.join("data");
    fs::create_dir_all(&snapshot_data_dir)?;

    let mut salt_hex = None;
    let mut encryption_algorithm = None;

    if is_encrypted {
        let pw = passphrase.unwrap();
        let salt = generate_salt();
        let key =
            derive_key(pw, &salt).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        salt_hex = Some(hex::encode(salt));
        encryption_algorithm = Some("AES-256-GCM / Argon2id".to_string());

        // 3. Encrypt each file into an opaque <UUIDv4>.enc flat file
        for file_meta in &mut files {
            let stored_name = format!("{}.enc", uuid::Uuid::new_v4());
            file_meta.stored_filename = Some(stored_name.clone());
            let dest_path = snapshot_data_dir.join(&stored_name);
            encrypt_file(&file_meta.absolute_path, &dest_path, &key, &salt)?;
        }
    } else {
        // Plaintext copy
        for file_meta in &files {
            let dest_path = snapshot_data_dir.join(&file_meta.relative_path);
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&file_meta.absolute_path, &dest_path)?;
        }
    }

    // 4. Construct and save the BackupManifest
    let manifest = BackupManifest {
        id: backup_id.clone(),
        source_path: source_path.to_string_lossy().to_string(),
        source_name,
        created_at: Utc::now(),
        total_files,
        total_size_bytes,
        is_encrypted,
        encryption_algorithm,
        salt_hex,
        files,
        manifest_version: if is_encrypted { Some(2) } else { Some(1) },
    };

    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    if is_encrypted {
        // Encrypt manifest with SECBKP01 format and save as manifest.json.enc
        let pw = passphrase.unwrap();
        let enc_manifest_bytes = crate::encryption::encrypt_archive_payload_with_passphrase(
            manifest_json.as_bytes(),
            pw,
        )
        .map_err(io::Error::other)?;

        let enc_manifest_path = snapshot_dir.join("manifest.json.enc");
        let mut enc_manifest_file = File::create(enc_manifest_path)?;
        enc_manifest_file.write_all(&enc_manifest_bytes)?;
    } else {
        // Save plaintext manifest.json for unencrypted backups
        let manifest_path = snapshot_dir.join("manifest.json");
        let mut manifest_file = File::create(manifest_path)?;
        manifest_file.write_all(manifest_json.as_bytes())?;
    }

    // 5. Persist snapshot records in local SQLite database
    if let Ok(mut conn) = crate::db::get_connection() {
        let _ = crate::db::insert_snapshot(&mut conn, &manifest, "completed");
    }

    let elapsed_millis = start_time.elapsed().as_millis();

    Ok(BackupResult {
        backup_id,
        manifest,
        target_directory: snapshot_dir.to_string_lossy().to_string(),
        is_encrypted,
        elapsed_millis,
    })
}

/// Reads all saved backup manifests from the local backup directory or SQLite catalog.
pub fn list_local_backups() -> io::Result<Vec<BackupManifest>> {
    let backups_base = get_backups_dir();
    if !backups_base.exists() {
        return Ok(Vec::new());
    }

    let mut manifests = Vec::new();
    let conn = crate::db::get_connection().ok();

    for entry in fs::read_dir(backups_base)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let manifest_path = entry.path().join("manifest.json");
            let enc_manifest_path = entry.path().join("manifest.json.enc");
            let folder_id = entry.file_name().to_string_lossy().to_string();

            // 1. Check for legacy / unencrypted plaintext manifest.json
            if manifest_path.exists() {
                if let Ok(content) = fs::read_to_string(&manifest_path) {
                    if let Ok(manifest) = serde_json::from_str::<BackupManifest>(&content) {
                        manifests.push(manifest);
                        continue;
                    }
                }
            }

            // 2. Check for encrypted manifest.json.enc
            if enc_manifest_path.exists() {
                if let Some(ref c) = conn {
                    if let Ok(manifest) = get_manifest_from_db(c, &folder_id) {
                        manifests.push(manifest);
                        continue;
                    }
                }

                manifests.push(BackupManifest {
                    id: folder_id,
                    source_path: String::new(),
                    source_name: "Encrypted Backup".to_string(),
                    created_at: Utc::now(),
                    total_files: 0,
                    total_size_bytes: 0,
                    is_encrypted: true,
                    encryption_algorithm: Some("AES-256-GCM / Argon2id".to_string()),
                    salt_hex: None,
                    files: Vec::new(),
                    manifest_version: Some(2),
                });
            }
        }
    }

    manifests.sort_by_key(|a| std::cmp::Reverse(a.created_at));
    Ok(manifests)
}

fn get_manifest_from_db(
    conn: &rusqlite::Connection,
    snapshot_id: &str,
) -> Result<BackupManifest, String> {
    let mut stmt = conn
        .prepare(
            r#"
            SELECT
                id, source_path, source_name, created_at,
                total_files, total_size_bytes, is_encrypted,
                encryption_algorithm, salt_hex
            FROM snapshots
            WHERE id = ?1
            "#,
        )
        .map_err(|e| e.to_string())?;

    let manifest = stmt
        .query_row(rusqlite::params![snapshot_id], |row| {
            let is_encrypted_int: i64 = row.get(6)?;
            let created_at_str: String = row.get(3)?;
            let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            Ok(BackupManifest {
                id: row.get(0)?,
                source_path: row.get(1)?,
                source_name: row.get(2)?,
                created_at,
                total_files: row.get::<_, i64>(4)? as usize,
                total_size_bytes: row.get::<_, i64>(5)? as u64,
                is_encrypted: is_encrypted_int != 0,
                encryption_algorithm: row.get(7)?,
                salt_hex: row.get(8)?,
                files: Vec::new(),
                manifest_version: if is_encrypted_int != 0 {
                    Some(2)
                } else {
                    Some(1)
                },
            })
        })
        .map_err(|e| e.to_string())?;

    let file_records = crate::db::get_snapshot_files(conn, snapshot_id)?;
    let files = file_records
        .into_iter()
        .map(|f| FileMetadata {
            relative_path: f.relative_path,
            absolute_path: String::new(),
            size_bytes: f.size_bytes,
            sha256_hash: f.sha256_hash,
            modified_timestamp: f.modified_timestamp,
            stored_filename: Some(f.stored_filename),
        })
        .collect();

    Ok(BackupManifest { files, ..manifest })
}

#[cfg(test)]
mod tests;
