use rusqlite::Connection;
use serde::{Deserialize, Serialize};

pub mod gdrive;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloudProviderType {
    GoogleDrive,
    Mega,
    ProtonDrive,
    Filen,
    S3,
}

impl CloudProviderType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CloudProviderType::GoogleDrive => "google_drive",
            CloudProviderType::Mega => "mega",
            CloudProviderType::ProtonDrive => "proton_drive",
            CloudProviderType::Filen => "filen",
            CloudProviderType::S3 => "s3",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            CloudProviderType::GoogleDrive => "Google Drive",
            CloudProviderType::Mega => "Mega.nz",
            CloudProviderType::ProtonDrive => "Proton Drive",
            CloudProviderType::Filen => "Filen.io",
            CloudProviderType::S3 => "Amazon S3 / Compatible",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudConnectionStatus {
    pub provider_type: CloudProviderType,
    pub name: String,
    pub is_connected: bool,
    pub is_supported: bool,
    pub account_email: Option<String>,
    pub storage_used_bytes: Option<u64>,
    pub storage_total_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSummary {
    pub snapshot_id: String,
    pub provider: String,
    pub files_uploaded: usize,
    pub total_bytes_uploaded: u64,
    pub vault_folder_id: String,
    pub snapshot_folder_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteSnapshotSummary {
    pub snapshot_id: String,
    pub source_name: String,
    pub created_at: String,
    pub total_files: usize,
    pub total_size_bytes: u64,
    pub is_encrypted: bool,
    pub encryption_algorithm: Option<String>,
    pub provider: String,
    pub vault_folder_id: String,
    pub snapshot_folder_id: String,
    pub is_imported: bool,
}

pub trait CloudProvider: Send + Sync {
    fn provider_type(&self) -> CloudProviderType;
    fn get_status(&self, conn: &Connection) -> Result<CloudConnectionStatus, String>;
    fn disconnect(&self, conn: &Connection) -> Result<(), String>;
    fn upload_snapshot(
        &self,
        conn: &Connection,
        snapshot_id: &str,
    ) -> Result<UploadSummary, String>;
    fn discover_remote_snapshots(
        &self,
        conn: &Connection,
    ) -> Result<Vec<RemoteSnapshotSummary>, String>;
    fn rebuild_catalog_from_cloud(&self, conn: &mut Connection) -> Result<usize, String>;
}

/// Returns the status list of all registered cloud providers.
pub fn get_all_provider_statuses(conn: &Connection) -> Vec<CloudConnectionStatus> {
    let gdrive = gdrive::GoogleDriveProvider;
    let gdrive_status = gdrive
        .get_status(conn)
        .unwrap_or_else(|_| CloudConnectionStatus {
            provider_type: CloudProviderType::GoogleDrive,
            name: CloudProviderType::GoogleDrive.display_name().to_string(),
            is_connected: false,
            is_supported: true,
            account_email: None,
            storage_used_bytes: None,
            storage_total_bytes: None,
        });

    vec![
        gdrive_status,
        CloudConnectionStatus {
            provider_type: CloudProviderType::Mega,
            name: CloudProviderType::Mega.display_name().to_string(),
            is_connected: false,
            is_supported: false,
            account_email: None,
            storage_used_bytes: None,
            storage_total_bytes: None,
        },
        CloudConnectionStatus {
            provider_type: CloudProviderType::ProtonDrive,
            name: CloudProviderType::ProtonDrive.display_name().to_string(),
            is_connected: false,
            is_supported: false,
            account_email: None,
            storage_used_bytes: None,
            storage_total_bytes: None,
        },
        CloudConnectionStatus {
            provider_type: CloudProviderType::Filen,
            name: CloudProviderType::Filen.display_name().to_string(),
            is_connected: false,
            is_supported: false,
            account_email: None,
            storage_used_bytes: None,
            storage_total_bytes: None,
        },
        CloudConnectionStatus {
            provider_type: CloudProviderType::S3,
            name: CloudProviderType::S3.display_name().to_string(),
            is_connected: false,
            is_supported: false,
            account_email: None,
            storage_used_bytes: None,
            storage_total_bytes: None,
        },
    ]
}

#[cfg(test)]
mod tests;
