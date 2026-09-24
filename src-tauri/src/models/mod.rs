use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub relative_path: String,
    pub absolute_path: String,
    pub size_bytes: u64,
    pub sha256_hash: String,
    pub modified_timestamp: u64,
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
