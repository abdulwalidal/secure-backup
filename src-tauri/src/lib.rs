pub mod backup;
pub mod cloud;
pub mod commands;
pub mod db;
pub mod encryption;
pub mod hashing;
pub mod models;

use commands::{
    connect_google_drive, disconnect_cloud_provider, get_backup_history, get_cloud_providers,
    get_database_snapshot_files, get_database_snapshots, get_database_stats, inspect_folder,
    start_local_backup, sync_snapshot_to_cloud, test_encryption_roundtrip,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Initialize database on startup
    if let Err(e) = db::get_connection() {
        eprintln!("Warning: Failed to initialize SQLite database: {}", e);
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            inspect_folder,
            start_local_backup,
            get_backup_history,
            test_encryption_roundtrip,
            get_database_snapshots,
            get_database_snapshot_files,
            get_database_stats,
            get_cloud_providers,
            connect_google_drive,
            disconnect_cloud_provider,
            sync_snapshot_to_cloud
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
