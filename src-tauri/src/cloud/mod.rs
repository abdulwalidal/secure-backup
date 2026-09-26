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

pub trait CloudProvider: Send + Sync {
    fn provider_type(&self) -> CloudProviderType;
    fn get_status(&self, conn: &Connection) -> Result<CloudConnectionStatus, String>;
    fn disconnect(&self, conn: &Connection) -> Result<(), String>;
}

/// Returns the status list of all registered cloud providers.
pub fn get_all_provider_statuses(conn: &Connection) -> Vec<CloudConnectionStatus> {
    let gdrive = gdrive::GoogleDriveProvider::default();
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
