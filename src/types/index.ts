export interface FolderInfo {
  path: string;
  name: string;
  exists: boolean;
  is_dir: boolean;
  file_count: number;
  total_size_bytes: number;
}

export interface FileMetadata {
  relative_path: string;
  absolute_path: string;
  size_bytes: number;
  sha256_hash: string;
  modified_timestamp: number;
}

export interface BackupManifest {
  id: string;
  source_path: string;
  source_name: string;
  created_at: string;
  total_files: number;
  total_size_bytes: number;
  is_encrypted: boolean;
  encryption_algorithm?: string;
  salt_hex?: string;
  files: FileMetadata[];
}

export interface BackupResult {
  backup_id: string;
  manifest: BackupManifest;
  target_directory: string;
  is_encrypted: boolean;
  elapsed_millis: number;
}

export interface CommandResult<T> {
  success: boolean;
  data?: T;
  error?: string;
}

export interface PassphraseVerificationResult {
  success: boolean;
  snapshot_id: string;
  source_name: string;
  total_files: number;
  total_size_bytes: number;
  verified_file?: string;
  sha256_matched: boolean;
  message: string;
}

export interface StorageStats {
  backup_path: string;
  free_space_bytes: number;
  used_space_bytes: number;
}

export interface CloudConnectionStatus {
  provider_type: string;
  name: string;
  is_connected: boolean;
  is_supported: boolean;
  account_email?: string;
  storage_used_bytes?: number;
  storage_total_bytes?: number;
}

export interface RemoteSnapshotSummary {
  snapshot_id: string;
  source_name: string;
  created_at: string;
  total_files: number;
  total_size_bytes: number;
  is_encrypted: boolean;
  encryption_algorithm?: string;
  provider: string;
  vault_folder_id: string;
  snapshot_folder_id: string;
  is_imported: boolean;
}

export interface RestoreFileItem {
  relative_path: string;
  status: "restored" | "skipped" | "failed";
  size_bytes: number;
  error?: string;
}

export interface RestoreResult {
  snapshot_id: string;
  destination_directory: string;
  source: "local" | "google_drive";
  total_files: number;
  files_restored: number;
  files_skipped: number;
  files_failed: number;
  total_bytes_restored: number;
  elapsed_millis: number;
  items: RestoreFileItem[];
}

export interface DatabaseSnapshot {
  id: string;
  source_path: string;
  source_name: string;
  created_at: string;
  total_files: number;
  total_size_bytes: number;
  is_encrypted: boolean;
  encryption_algorithm?: string;
  manifest_path?: string;
}

export interface DatabaseSnapshotFile {
  id?: number;
  snapshot_id: string;
  relative_path: string;
  stored_filename?: string;
  size_bytes: number;
  sha256_hash: string;
  modified_timestamp: number;
}

export interface DatabaseStats {
  total_snapshots: number;
  total_files: number;
  total_bytes: number;
  total_files_indexed?: number;
  total_bytes_backed_up?: number;
}

export interface BackupOptions {
  source_path: string;
  passphrase?: string;
  exclude_patterns?: string[];
  enable_default_exclusions?: boolean;
}

export interface RestoreOptions {
  snapshot_id: string;
  destination_path: string;
  passphrase?: string;
  source_type: "local" | "google_drive";
  conflict_policy?: "overwrite" | "skip" | "rename";
}

export interface UploadSummary {
  snapshot_id: string;
  provider: string;
  files_uploaded: number;
  total_bytes_uploaded: number;
  vault_folder_id: string;
  snapshot_folder_id: string;
}
