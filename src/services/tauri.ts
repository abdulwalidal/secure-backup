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
  CommandResult,
  UploadSummary,
} from "../types";

/**
 * Generic Tauri IPC wrapper that safely unwraps CommandResult<T>
 * and rejects with the backend error message if success is false.
 */
async function invokeCommand<T>(
  command: string,
  args?: Record<string, unknown>
): Promise<T> {
  const result = await invoke<CommandResult<T> | T>(command, args);

  if (result && typeof result === "object" && "success" in result) {
    const cmdRes = result as CommandResult<T>;
    if (cmdRes.success === false) {
      throw new Error(cmdRes.error || `Command "${command}" failed.`);
    }
    return cmdRes.data as T;
  }

  return result as T;
}

export const tauriApi = {
  // Folder inspection
  async inspectFolder(path: string, excludeCommon = true): Promise<FolderInfo> {
    return invokeCommand<FolderInfo>("inspect_folder", {
      path,
      excludeCommon,
    });
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
    return invokeCommand<BackupResult>("start_local_backup", {
      sourcePath: options.source_path,
      passphrase: options.passphrase || null,
      excludeCommon: options.enable_default_exclusions ?? true,
      customExclusions: options.exclude_patterns || [],
    });
  },

  async getBackupHistory(): Promise<DatabaseSnapshot[]> {
    try {
      const records = await invokeCommand<DatabaseSnapshot[]>(
        "get_database_snapshots"
      );
      if (Array.isArray(records) && records.length > 0) {
        return records;
      }
    } catch (e) {
      console.warn("get_database_snapshots failed, trying fallback:", e);
    }

    // Fallback to legacy filesystem manifest listing
    try {
      const manifests = await invokeCommand<
        Array<{
          id: string;
          source_path: string;
          source_name: string;
          created_at: string;
          total_files: number;
          total_size_bytes: number;
          is_encrypted: boolean;
          encryption_algorithm?: string;
        }>
      >("get_backup_history");
      return Array.isArray(manifests) ? (manifests as DatabaseSnapshot[]) : [];
    } catch {
      return [];
    }
  },

  async getSnapshotFiles(snapshotId: string): Promise<DatabaseSnapshotFile[]> {
    const files = await invokeCommand<DatabaseSnapshotFile[]>(
      "get_database_snapshot_files",
      { snapshotId }
    );
    return Array.isArray(files) ? files : [];
  },

  async deleteBackupSnapshot(snapshotId: string): Promise<boolean> {
    return invokeCommand<boolean>("delete_backup_snapshot", { snapshotId });
  },

  // Restore operations
  async verifySnapshotPassphrase(
    snapshotId: string,
    passphrase?: string
  ): Promise<PassphraseVerificationResult> {
    return invokeCommand<PassphraseVerificationResult>(
      "verify_snapshot_passphrase",
      {
        snapshotId,
        passphrase: passphrase || "",
      }
    );
  },

  async restoreSnapshot(options: RestoreOptions): Promise<RestoreResult> {
    return invokeCommand<RestoreResult>("restore_snapshot", {
      snapshotId: options.snapshot_id,
      destinationDir: options.destination_path,
      passphrase: options.passphrase || null,
      sourceType: options.source_type,
      conflictPolicy: options.conflict_policy || "overwrite",
    });
  },

  // Storage and Database stats
  async getStorageStats(): Promise<StorageStats> {
    return invokeCommand<StorageStats>("get_storage_stats");
  },

  async getDatabaseStats(): Promise<DatabaseStats> {
    const stats = await invokeCommand<DatabaseStats>("get_database_stats");
    return {
      total_snapshots: stats.total_snapshots ?? 0,
      total_files:
        stats.total_files ?? stats.total_files_indexed ?? 0,
      total_bytes:
        stats.total_bytes ?? stats.total_bytes_backed_up ?? 0,
    };
  },

  // Cloud operations
  async getCloudProviders(): Promise<CloudConnectionStatus[]> {
    const providers = await invokeCommand<CloudConnectionStatus[]>(
      "get_cloud_providers"
    );
    return Array.isArray(providers) ? providers : [];
  },

  async connectGoogleDrive(): Promise<CloudConnectionStatus> {
    return invokeCommand<CloudConnectionStatus>("connect_google_drive");
  },

  async disconnectCloudProvider(provider: string): Promise<boolean> {
    return invokeCommand<boolean>("disconnect_cloud_provider", {
      providerType: provider,
    });
  },

  async syncSnapshotToCloud(
    snapshotId: string,
    provider: string
  ): Promise<UploadSummary> {
    return invokeCommand<UploadSummary>("sync_snapshot_to_cloud", {
      snapshotId,
      providerType: provider,
    });
  },

  async discoverCloudSnapshots(
    provider: string
  ): Promise<RemoteSnapshotSummary[]> {
    const snapshots = await invokeCommand<RemoteSnapshotSummary[]>(
      "discover_cloud_snapshots",
      { providerType: provider }
    );
    return Array.isArray(snapshots) ? snapshots : [];
  },

  async rebuildDatabaseFromCloud(provider: string): Promise<number> {
    return invokeCommand<number>("rebuild_database_from_cloud", {
      providerType: provider,
    });
  },
};

export function formatBytes(bytes?: number | null): string {
  if (
    bytes === undefined ||
    bytes === null ||
    typeof bytes !== "number" ||
    isNaN(bytes) ||
    bytes <= 0
  ) {
    return "0 B";
  }
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  if (i < 0 || i >= sizes.length) return `${bytes} B`;
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

export function formatDate(isoDate?: string | null): string {
  if (!isoDate) return "N/A";
  try {
    const d = new Date(isoDate);
    if (isNaN(d.getTime())) return String(isoDate);
    return d.toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return String(isoDate);
  }
}
