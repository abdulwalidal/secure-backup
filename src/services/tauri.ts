import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import type {
  FolderInfo,
  BackupResult,
  StorageStats,
  CloudConnectionStatus,
  RemoteSnapshotSummary,
  RestoreResult,
  PassphraseVerificationResult,
  DatabaseSnapshot,
  DatabaseSnapshotFile,
  DatabaseStats,
  BackupOptions,
  RestoreOptions,
} from "../types";

export const tauriApi = {
  // Folder inspection
  async inspectFolder(path: string): Promise<FolderInfo> {
    return invoke<FolderInfo>("inspect_folder", { path });
  },

  // Directory picker dialog
  async selectDirectory(title = "Select Folder"): Promise<string | null> {
    const selected = await open({
      directory: true,
      multiple: false,
      title,
    });
    return (selected as string | null) || null;
  },

  // Reveal in system file explorer
  async revealInExplorer(path: string): Promise<void> {
    return revealItemInDir(path);
  },

  // Backup operations
  async startBackup(options: BackupOptions): Promise<BackupResult> {
    return invoke<BackupResult>("start_local_backup", {
      sourcePath: options.source_path,
      passphrase: options.passphrase || null,
      excludePatterns: options.exclude_patterns || [],
      enableDefaultExclusions: options.enable_default_exclusions ?? true,
    });
  },

  async getBackupHistory(): Promise<DatabaseSnapshot[]> {
    return invoke<DatabaseSnapshot[]>("get_database_snapshots");
  },

  async getSnapshotFiles(snapshotId: string): Promise<DatabaseSnapshotFile[]> {
    return invoke<DatabaseSnapshotFile[]>("get_database_snapshot_files", {
      snapshotId,
    });
  },

  async deleteBackupSnapshot(snapshotId: string): Promise<void> {
    return invoke<void>("delete_backup_snapshot", { snapshotId });
  },

  // Restore operations
  async verifySnapshotPassphrase(
    snapshotId: string,
    passphrase?: string
  ): Promise<PassphraseVerificationResult> {
    return invoke<PassphraseVerificationResult>("verify_snapshot_passphrase", {
      snapshotId,
      passphrase: passphrase || null,
    });
  },

  async restoreSnapshot(options: RestoreOptions): Promise<RestoreResult> {
    return invoke<RestoreResult>("restore_snapshot", {
      snapshotId: options.snapshot_id,
      destinationPath: options.destination_path,
      passphrase: options.passphrase || null,
      sourceType: options.source_type,
      conflictPolicy: options.conflict_policy || "overwrite",
    });
  },

  // Storage and Database stats
  async getStorageStats(): Promise<StorageStats> {
    return invoke<StorageStats>("get_storage_stats");
  },

  async getDatabaseStats(): Promise<DatabaseStats> {
    return invoke<DatabaseStats>("get_database_stats");
  },

  // Cloud operations
  async getCloudProviders(): Promise<CloudConnectionStatus[]> {
    return invoke<CloudConnectionStatus[]>("get_cloud_providers");
  },

  async connectGoogleDrive(): Promise<string> {
    return invoke<string>("connect_google_drive");
  },

  async disconnectCloudProvider(provider: string): Promise<void> {
    return invoke<void>("disconnect_cloud_provider", { provider });
  },

  async syncSnapshotToCloud(
    snapshotId: string,
    provider: string
  ): Promise<void> {
    return invoke<void>("sync_snapshot_to_cloud", { snapshotId, provider });
  },

  async discoverCloudSnapshots(
    provider: string
  ): Promise<RemoteSnapshotSummary[]> {
    return invoke<RemoteSnapshotSummary[]>("discover_cloud_snapshots", {
      provider,
    });
  },

  async rebuildDatabaseFromCloud(provider: string): Promise<number> {
    return invoke<number>("rebuild_database_from_cloud", { provider });
  },
};

export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

export function formatDate(isoDate: string): string {
  try {
    const d = new Date(isoDate);
    return d.toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return isoDate;
  }
}
