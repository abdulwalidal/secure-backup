use crate::backup::{create_local_backup, list_local_backups};
use crate::models::{BackupManifest, BackupResult, CommandResult, FolderInfo};
use std::fs;
use std::path::Path;

#[tauri::command]
pub fn inspect_folder(path: String) -> CommandResult<FolderInfo> {
    let p = Path::new(&path);
    if !p.exists() {
        return CommandResult {
            success: false,
            data: None,
            error: Some("The selected path does not exist.".to_string()),
        };
    }

    if !p.is_dir() {
        return CommandResult {
            success: false,
            data: None,
            error: Some("The selected path is not a directory.".to_string()),
        };
    }

    let folder_name = p
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.clone());

    let mut file_count = 0;
    let mut total_size_bytes = 0;

    if let Ok(entries) = fs::read_dir(p) {
        for entry in entries.flatten() {
            file_count += 1;
            if let Ok(meta) = entry.metadata() {
                total_size_bytes += meta.len();
            }
        }
    }

    CommandResult {
        success: true,
        data: Some(FolderInfo {
            path,
            name: folder_name,
            exists: true,
            is_dir: true,
            file_count,
            total_size_bytes,
        }),
        error: None,
    }
}

#[tauri::command]
pub fn start_local_backup(
    source_path: String,
    passphrase: Option<String>,
) -> CommandResult<BackupResult> {
    let pass_ref = passphrase.as_deref();
    match create_local_backup(&source_path, pass_ref) {
        Ok(result) => CommandResult {
            success: true,
            data: Some(result),
            error: None,
        },
        Err(err) => CommandResult {
            success: false,
            data: None,
            error: Some(format!("Backup failed: {}", err)),
        },
    }
}

#[tauri::command]
pub fn get_backup_history() -> CommandResult<Vec<BackupManifest>> {
    match list_local_backups() {
        Ok(manifests) => CommandResult {
            success: true,
            data: Some(manifests),
            error: None,
        },
        Err(err) => CommandResult {
            success: false,
            data: None,
            error: Some(format!("Failed to retrieve backup history: {}", err)),
        },
    }
}

#[tauri::command]
pub fn test_encryption_roundtrip(sample_text: String, passphrase: String) -> CommandResult<String> {
    use crate::encryption::{decrypt_bytes, derive_key, encrypt_bytes, generate_salt};

    let salt = generate_salt();
    let key = match derive_key(&passphrase, &salt) {
        Ok(k) => k,
        Err(e) => {
            return CommandResult {
                success: false,
                data: None,
                error: Some(e),
            }
        }
    };

    let (ciphertext, nonce) = match encrypt_bytes(sample_text.as_bytes(), &key) {
        Ok(res) => res,
        Err(e) => {
            return CommandResult {
                success: false,
                data: None,
                error: Some(e),
            }
        }
    };

    match decrypt_bytes(&ciphertext, &nonce, &key) {
        Ok(dec) => {
            let recovered = String::from_utf8_lossy(&dec).to_string();
            CommandResult {
                success: true,
                data: Some(recovered),
                error: None,
            }
        }
        Err(e) => CommandResult {
            success: false,
            data: None,
            error: Some(e),
        },
    }
}

#[tauri::command]
pub fn get_database_snapshots() -> CommandResult<Vec<crate::models::SnapshotRecord>> {
    let conn = match crate::db::get_connection() {
        Ok(c) => c,
        Err(e) => {
            return CommandResult {
                success: false,
                data: None,
                error: Some(e),
            }
        }
    };

    match crate::db::get_snapshots(&conn) {
        Ok(snapshots) => CommandResult {
            success: true,
            data: Some(snapshots),
            error: None,
        },
        Err(e) => CommandResult {
            success: false,
            data: None,
            error: Some(e),
        },
    }
}

#[tauri::command]
pub fn get_database_snapshot_files(
    snapshot_id: String,
) -> CommandResult<Vec<crate::models::FileRecord>> {
    let conn = match crate::db::get_connection() {
        Ok(c) => c,
        Err(e) => {
            return CommandResult {
                success: false,
                data: None,
                error: Some(e),
            }
        }
    };

    match crate::db::get_snapshot_files(&conn, &snapshot_id) {
        Ok(files) => CommandResult {
            success: true,
            data: Some(files),
            error: None,
        },
        Err(e) => CommandResult {
            success: false,
            data: None,
            error: Some(e),
        },
    }
}

#[tauri::command]
pub fn get_database_stats() -> CommandResult<crate::models::DbStats> {
    let conn = match crate::db::get_connection() {
        Ok(c) => c,
        Err(e) => {
            return CommandResult {
                success: false,
                data: None,
                error: Some(e),
            }
        }
    };

    match crate::db::get_db_stats(&conn) {
        Ok(stats) => CommandResult {
            success: true,
            data: Some(stats),
            error: None,
        },
        Err(e) => CommandResult {
            success: false,
            data: None,
            error: Some(e),
        },
    }
}

#[tauri::command]
pub fn get_cloud_providers() -> CommandResult<Vec<crate::cloud::CloudConnectionStatus>> {
    let conn = match crate::db::get_connection() {
        Ok(c) => c,
        Err(e) => {
            return CommandResult {
                success: false,
                data: None,
                error: Some(e),
            }
        }
    };

    let providers = crate::cloud::get_all_provider_statuses(&conn);
    CommandResult {
        success: true,
        data: Some(providers),
        error: None,
    }
}

#[tauri::command]
pub async fn connect_google_drive() -> CommandResult<crate::cloud::CloudConnectionStatus> {
    let join_handle = tauri::async_runtime::spawn_blocking(|| {
        let mut conn = match crate::db::get_connection() {
            Ok(c) => c,
            Err(e) => return Err(e),
        };

        crate::cloud::gdrive::GoogleDriveProvider::perform_oauth_flow(&mut conn)
    });

    match join_handle.await {
        Ok(Ok(status)) => CommandResult {
            success: true,
            data: Some(status),
            error: None,
        },
        Ok(Err(err)) => CommandResult {
            success: false,
            data: None,
            error: Some(err),
        },
        Err(join_err) => CommandResult {
            success: false,
            data: None,
            error: Some(format!("OAuth background task failed: {}", join_err)),
        },
    }
}

#[tauri::command]
pub fn disconnect_cloud_provider(provider_type: String) -> CommandResult<bool> {
    use crate::cloud::CloudProvider;

    let conn = match crate::db::get_connection() {
        Ok(c) => c,
        Err(e) => {
            return CommandResult {
                success: false,
                data: None,
                error: Some(e),
            }
        }
    };

    if provider_type == "google_drive" || provider_type == "GoogleDrive" {
        let gdrive = crate::cloud::gdrive::GoogleDriveProvider;
        match gdrive.disconnect(&conn) {
            Ok(_) => CommandResult {
                success: true,
                data: Some(true),
                error: None,
            },
            Err(e) => CommandResult {
                success: false,
                data: None,
                error: Some(e),
            },
        }
    } else {
        CommandResult {
            success: false,
            data: None,
            error: Some(format!("Unsupported provider type: {}", provider_type)),
        }
    }
}

#[tauri::command]
pub async fn sync_snapshot_to_cloud(
    snapshot_id: String,
    provider_type: String,
) -> CommandResult<crate::cloud::UploadSummary> {
    use crate::cloud::CloudProvider;

    let join_handle = tauri::async_runtime::spawn_blocking(move || {
        let conn = match crate::db::get_connection() {
            Ok(c) => c,
            Err(e) => return Err(e),
        };

        if provider_type == "google_drive" || provider_type == "GoogleDrive" {
            let gdrive = crate::cloud::gdrive::GoogleDriveProvider;
            gdrive.upload_snapshot(&conn, &snapshot_id)
        } else {
            Err(format!("Unsupported cloud provider: {}", provider_type))
        }
    });

    match join_handle.await {
        Ok(Ok(summary)) => CommandResult {
            success: true,
            data: Some(summary),
            error: None,
        },
        Ok(Err(err)) => CommandResult {
            success: false,
            data: None,
            error: Some(err),
        },
        Err(join_err) => CommandResult {
            success: false,
            data: None,
            error: Some(format!("Sync background task failed: {}", join_err)),
        },
    }
}

#[tauri::command]
pub async fn discover_cloud_snapshots(
    provider_type: String,
) -> CommandResult<Vec<crate::cloud::RemoteSnapshotSummary>> {
    use crate::cloud::CloudProvider;

    let join_handle = tauri::async_runtime::spawn_blocking(move || {
        let conn = match crate::db::get_connection() {
            Ok(c) => c,
            Err(e) => return Err(e),
        };

        if provider_type == "google_drive" || provider_type == "GoogleDrive" {
            let gdrive = crate::cloud::gdrive::GoogleDriveProvider;
            gdrive.discover_remote_snapshots(&conn)
        } else {
            Err(format!("Unsupported cloud provider: {}", provider_type))
        }
    });

    match join_handle.await {
        Ok(Ok(snapshots)) => CommandResult {
            success: true,
            data: Some(snapshots),
            error: None,
        },
        Ok(Err(err)) => CommandResult {
            success: false,
            data: None,
            error: Some(err),
        },
        Err(join_err) => CommandResult {
            success: false,
            data: None,
            error: Some(format!("Discovery background task failed: {}", join_err)),
        },
    }
}

#[tauri::command]
pub async fn rebuild_database_from_cloud(provider_type: String) -> CommandResult<usize> {
    use crate::cloud::CloudProvider;

    let join_handle = tauri::async_runtime::spawn_blocking(move || {
        let mut conn = match crate::db::get_connection() {
            Ok(c) => c,
            Err(e) => return Err(e),
        };

        if provider_type == "google_drive" || provider_type == "GoogleDrive" {
            let gdrive = crate::cloud::gdrive::GoogleDriveProvider;
            gdrive.rebuild_catalog_from_cloud(&mut conn)
        } else {
            Err(format!("Unsupported cloud provider: {}", provider_type))
        }
    });

    match join_handle.await {
        Ok(Ok(imported_count)) => CommandResult {
            success: true,
            data: Some(imported_count),
            error: None,
        },
        Ok(Err(err)) => CommandResult {
            success: false,
            data: None,
            error: Some(err),
        },
        Err(join_err) => CommandResult {
            success: false,
            data: None,
            error: Some(format!(
                "Rebuild catalog background task failed: {}",
                join_err
            )),
        },
    }
}

#[tauri::command]
pub async fn restore_snapshot(
    snapshot_id: String,
    destination_dir: String,
    passphrase: Option<String>,
    conflict_policy: Option<String>,
    source_type: Option<String>,
) -> CommandResult<crate::restore::RestoreResult> {
    use crate::restore::{
        restore_cloud_snapshot, restore_local_snapshot, ConflictPolicy, RestoreOptions,
        RestoreSource,
    };
    use std::path::PathBuf;
    use std::str::FromStr;

    // 1. Validate destination path
    let dest_path = PathBuf::from(&destination_dir);
    if !dest_path.exists() {
        return CommandResult {
            success: false,
            data: None,
            error: Some(
                "Destination directory does not exist. Please select a valid folder.".to_string(),
            ),
        };
    }
    if !dest_path.is_dir() {
        return CommandResult {
            success: false,
            data: None,
            error: Some("Selected destination path is not a directory.".to_string()),
        };
    }

    // 2. Parse conflict policy strongly typed enum
    let policy = match conflict_policy.as_deref() {
        Some(s) => match ConflictPolicy::from_str(s) {
            Ok(p) => p,
            Err(e) => {
                return CommandResult {
                    success: false,
                    data: None,
                    error: Some(e),
                }
            }
        },
        None => ConflictPolicy::default(),
    };

    // 3. Parse and validate restore source enum (Do not blindly trust source_type!)
    let parsed_source = match source_type.as_deref() {
        Some(s) => match RestoreSource::from_str(s) {
            Ok(src) => src,
            Err(e) => {
                return CommandResult {
                    success: false,
                    data: None,
                    error: Some(e),
                }
            }
        },
        None => {
            let local_dir = crate::backup::get_backups_dir().join(&snapshot_id);
            if local_dir.exists() {
                RestoreSource::Local
            } else {
                RestoreSource::GoogleDrive
            }
        }
    };

    let join_handle = tauri::async_runtime::spawn_blocking(move || {
        let options = RestoreOptions {
            destination_dir: &dest_path,
            passphrase: passphrase.as_deref().filter(|s| !s.trim().is_empty()),
            conflict_policy: policy,
        };

        // 4. Validate that snapshot source is supported and available
        match parsed_source {
            RestoreSource::Local => {
                let local_dir = crate::backup::get_backups_dir().join(&snapshot_id);
                if !local_dir.exists() {
                    return Err(format!(
                        "Snapshot '{}' is not available in local storage. Use Google Drive restore instead.",
                        snapshot_id
                    ));
                }
                restore_local_snapshot(&snapshot_id, &options)
            }
            RestoreSource::GoogleDrive => {
                let conn = match crate::db::get_connection() {
                    Ok(c) => c,
                    Err(e) => return Err(format!("Database error: {}", e)),
                };

                restore_cloud_snapshot(&conn, &snapshot_id, &options)
            }
        }
    });

    match join_handle.await {
        Ok(Ok(res)) => CommandResult {
            success: true,
            data: Some(res),
            error: None,
        },
        Ok(Err(err)) => CommandResult {
            success: false,
            data: None,
            error: Some(err),
        },
        Err(join_err) => CommandResult {
            success: false,
            data: None,
            error: Some(format!("Restore background task failed: {}", join_err)),
        },
    }
}
