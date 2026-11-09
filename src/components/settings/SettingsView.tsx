import React, { useState, useEffect } from "react";
import {
  HardDrive,
  Cloud,
  RefreshCw,
  ExternalLink,
  Unplug,
  DownloadCloud,
} from "lucide-react";
import { tauriApi, formatBytes } from "../../services/tauri";
import type { StorageStats, CloudConnectionStatus } from "../../types";
import { useToast } from "../common/Toast";

export const SettingsView: React.FC<{ onSettingsUpdated?: () => void }> = ({
  onSettingsUpdated,
}) => {
  const { success, error, info } = useToast();

  const [storageStats, setStorageStats] = useState<StorageStats | null>(null);
  const [providers, setProviders] = useState<CloudConnectionStatus[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isRebuilding, setIsRebuilding] = useState(false);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [storage, cloudProviders] = await Promise.all([
        tauriApi.getStorageStats().catch(() => null),
        tauriApi.getCloudProviders().catch(() => []),
      ]);

      if (storage) setStorageStats(storage);
      setProviders(cloudProviders || []);
    } catch (e: unknown) {
      error("Failed to load settings data", String(e));
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleConnectGoogleDrive = async () => {
    try {
      info("Initiating OAuth", "Opening Google Drive authorization...");
      const status = await tauriApi.connectGoogleDrive();
      if (status && status.is_connected) {
        success("Connected", `Connected to Google Drive (${status.account_email || "Active"}).`);
      }
      await loadData();
      if (onSettingsUpdated) onSettingsUpdated();
    } catch (e: unknown) {
      error("Google Drive connection failed", String(e));
    }
  };

  const handleDisconnect = async (provider: string) => {
    try {
      await tauriApi.disconnectCloudProvider(provider);
      success("Disconnected", `${provider} integration removed.`);
      await loadData();
      if (onSettingsUpdated) onSettingsUpdated();
    } catch (e: unknown) {
      error("Failed to disconnect", String(e));
    }
  };

  const handleRebuildCatalog = async (provider: string) => {
    setIsRebuilding(true);
    try {
      const count = await tauriApi.rebuildDatabaseFromCloud(provider);
      success("Disaster Recovery Complete", `Discovered and indexed ${count} cloud snapshots.`);
      await loadData();
      if (onSettingsUpdated) onSettingsUpdated();
    } catch (e: unknown) {
      error("Catalog rebuild failed", String(e));
    } finally {
      setIsRebuilding(false);
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Storage Disk Quota Card */}
      <div className="p-6 bg-zinc-900 border border-zinc-800 rounded-2xl shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-blue-500/10 text-blue-400 flex items-center justify-center border border-blue-500/20">
              <HardDrive className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-zinc-100">
                Local Storage Allocation
              </h3>
              <p className="text-xs text-zinc-400">
                Disk usage for local encrypted vaults and SQLite indexes
              </p>
            </div>
          </div>

          <button
            onClick={loadData}
            disabled={isLoading}
            className="p-2 bg-zinc-800 hover:bg-zinc-700 rounded-xl text-zinc-400 hover:text-zinc-200 cursor-pointer transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? "animate-spin text-blue-400" : ""}`} />
          </button>
        </div>

        {storageStats && (
          <div className="space-y-3 pt-2">
            <div className="flex items-center justify-between text-xs text-zinc-400">
              <span>Encrypted Vault Directory</span>
              <span className="font-mono text-zinc-300 truncate max-w-sm">
                {storageStats.backup_path}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-4 p-4 bg-zinc-950/60 rounded-xl border border-zinc-800/80">
              <div>
                <span className="text-[11px] text-zinc-500 block uppercase font-medium">
                  Used by Backups
                </span>
                <span className="font-mono text-zinc-200 font-semibold text-sm mt-0.5 block">
                  {formatBytes(storageStats.used_space_bytes)}
                </span>
              </div>
              <div>
                <span className="text-[11px] text-zinc-500 block uppercase font-medium">
                  Available Disk Capacity
                </span>
                <span className="font-mono text-emerald-400 font-semibold text-sm mt-0.5 block">
                  {formatBytes(storageStats.free_space_bytes)}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Cloud Integration Provider Cards */}
      <div className="p-6 bg-zinc-900 border border-zinc-800 rounded-2xl shadow-xl space-y-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-indigo-500/10 text-indigo-400 flex items-center justify-center border border-indigo-500/20">
            <Cloud className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-zinc-100">
              Cloud Storage Providers
            </h3>
            <p className="text-xs text-zinc-400">
              Zero-knowledge synchronization with secondary off-site targets
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
          {Array.isArray(providers) && providers.map((p) => (
            <div
              key={p.provider_type}
              className="p-5 bg-zinc-950/70 border border-zinc-800 rounded-xl flex flex-col justify-between gap-4"
            >
              <div className="flex items-start justify-between">
                <div>
                  <h4 className="text-sm font-semibold text-zinc-200">{p.name}</h4>
                  <div className="flex items-center gap-1.5 mt-1">
                    <span
                      className={`w-2 h-2 rounded-full ${
                        p.is_connected ? "bg-emerald-400" : "bg-zinc-600"
                      }`}
                    />
                    <span className="text-xs text-zinc-400">
                      {p.is_connected
                        ? p.account_email || "Connected"
                        : "Not Connected"}
                    </span>
                  </div>
                </div>

                <span
                  className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${
                    p.is_supported
                      ? "bg-blue-950 text-blue-400 border-blue-800"
                      : "bg-zinc-800 text-zinc-500 border-zinc-700"
                  }`}
                >
                  {p.is_supported ? "Active" : "Coming Soon"}
                </span>
              </div>

              {p.is_supported && (
                <div className="flex items-center justify-between pt-2 border-t border-zinc-800/60">
                  {p.is_connected ? (
                    <button
                      onClick={() => handleDisconnect(p.provider_type)}
                      className="flex items-center gap-1.5 text-xs text-rose-400 hover:text-rose-300 font-medium cursor-pointer"
                    >
                      <Unplug className="w-3.5 h-3.5" />
                      <span>Disconnect</span>
                    </button>
                  ) : (
                    <button
                      onClick={handleConnectGoogleDrive}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow-md shadow-blue-500/20 cursor-pointer"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                      <span>Authenticate Google Drive</span>
                    </button>
                  )}

                  {p.is_connected && (
                    <button
                      onClick={() => handleRebuildCatalog(p.provider_type)}
                      disabled={isRebuilding}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 rounded-lg text-xs font-medium cursor-pointer"
                    >
                      <DownloadCloud className="w-3.5 h-3.5" />
                      <span>{isRebuilding ? "Rebuilding..." : "Rebuild Catalog"}</span>
                    </button>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
