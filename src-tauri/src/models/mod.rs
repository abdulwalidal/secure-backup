use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub relative_path: String,
    pub absolute_path: String,
    pub size_bytes: u64,
    pub sha256_hash: String,
    pub modified_timestamp: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_filename: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub id: String,
    pub source_path: String,
    pub source_name: String,
    pub created_at: DateTime<Utc>,
    pub total_files: usize,
    pub total_size_bytes: u64,
    pub is_encrypted: bool,
    pub encryption_algorithm: Option<String>,
    pub salt_hex: Option<String>,
    pub files: Vec<FileMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_version: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupResult {
    pub backup_id: String,
    pub manifest: BackupManifest,
    pub target_directory: String,
    pub is_encrypted: bool,
    pub elapsed_millis: u128,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FolderInfo {
    pub path: String,
    pub name: String,
    pub exists: bool,
    pub is_dir: bool,
    pub file_count: usize,
    pub total_size_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommandResult<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRecord {
    pub id: String,
    pub source_path: String,
    pub source_name: String,
    pub created_at: String,
    pub total_files: usize,
    pub total_size_bytes: u64,
    pub is_encrypted: bool,
    pub encryption_algorithm: Option<String>,
    pub salt_hex: Option<String>,
    pub status: String,
    pub cloud_synced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub id: Option<i64>,
    pub snapshot_id: String,
    pub relative_path: String,
    pub size_bytes: u64,
    pub sha256_hash: String,
    pub modified_timestamp: u64,
    pub stored_filename: String,
    pub cloud_file_id: Option<String>,
    pub cloud_synced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbStats {
    pub total_snapshots: usize,
    pub total_files_indexed: usize,
    pub total_bytes_backed_up: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    pub backup_path: String,
    pub free_space_bytes: u64,
    pub used_space_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassphraseVerificationResult {
    pub success: bool,
    pub snapshot_id: String,
    pub source_name: String,
    pub total_files: usize,
    pub total_size_bytes: u64,
    pub verified_file: Option<String>,
    pub sha256_matched: bool,
    pub message: String,
}
