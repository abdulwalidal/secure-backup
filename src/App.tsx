import React, { useState, useEffect, useCallback } from "react";
import { Sidebar, type NavTab } from "./components/layout/Sidebar";
import { Header } from "./components/layout/Header";
import { ToastProvider } from "./components/common/Toast";
import { DashboardView } from "./components/dashboard/DashboardView";
import { BackupHistoryView } from "./components/backups/BackupHistoryView";
import { RestoreView } from "./components/restore/RestoreView";
import { SettingsView } from "./components/settings/SettingsView";
import { tauriApi } from "./services/tauri";
import type { StorageStats, DatabaseStats } from "./types";

const MainApp: React.FC = () => {
  const [activeTab, setActiveTab] = useState<NavTab>("dashboard");
  const [storageStats, setStorageStats] = useState<StorageStats | null>(null);
  const [dbStats, setDbStats] = useState<DatabaseStats | null>(null);
  const [restoreInitialSnapshotId, setRestoreInitialSnapshotId] = useState<string | undefined>(
    undefined
  );

  const loadGlobalStats = useCallback(async () => {
    try {
      const [storage, db] = await Promise.all([
        tauriApi.getStorageStats().catch(() => null),
        tauriApi.getDatabaseStats().catch(() => null),
      ]);
      if (storage) setStorageStats(storage);
      if (db) setDbStats(db);
    } catch (e: unknown) {
      console.warn("Could not load stats on launch", e);
    }
  }, []);

  useEffect(() => {
    loadGlobalStats();

    // Keyboard shortcut navigation (1-4)
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
        return;
      }
      if (e.key === "1") setActiveTab("dashboard");
      if (e.key === "2") setActiveTab("backups");
      if (e.key === "3") setActiveTab("restore");
      if (e.key === "4") setActiveTab("settings");
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [loadGlobalStats]);

  const handleSelectSnapshotForRestore = (snapshotId: string) => {
    setRestoreInitialSnapshotId(snapshotId);
    setActiveTab("restore");
  };

  const titles: Record<NavTab, { title: string; subtitle: string }> = {
    dashboard: {
      title: "Dashboard",
      subtitle: "Zero-knowledge encrypted backups for your personal files & projects.",
    },
    backups: {
      title: "Backup History",
      subtitle: "Inspect, manage, and verify previous snapshots and storage manifests.",
    },
    restore: {
      title: "Restore Files",
      subtitle: "Recover encrypted snapshots back to your local filesystem with collision safety.",
    },
    settings: {
      title: "Settings & Cloud Sync",
      subtitle: "Manage cloud providers, storage quotas, and disaster recovery tools.",
    },
  };

  return (
    <div className="flex h-screen w-screen bg-zinc-950 text-zinc-100 overflow-hidden font-sans">
      <Sidebar activeTab={activeTab} onTabChange={setActiveTab} />
      <div className="flex-1 flex flex-col min-w-0 h-full overflow-hidden">
        <Header
          title={titles[activeTab].title}
          subtitle={titles[activeTab].subtitle}
          storageStats={storageStats}
          dbStats={dbStats}
          onRefresh={loadGlobalStats}
        />
        <main className="flex-1 overflow-y-auto p-8 relative">
          <div className="max-w-6xl mx-auto h-full">
            {activeTab === "dashboard" && (
              <DashboardView onBackupCompleted={loadGlobalStats} />
            )}
            {activeTab === "backups" && (
              <BackupHistoryView
                onRestoreSelect={handleSelectSnapshotForRestore}
              />
            )}
            {activeTab === "restore" && (
              <RestoreView
                initialSnapshotId={restoreInitialSnapshotId}
                onRestoreComplete={loadGlobalStats}
              />
            )}
            {activeTab === "settings" && (
              <SettingsView onSettingsUpdated={loadGlobalStats} />
            )}
          </div>
        </main>
      </div>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <ToastProvider>
      <MainApp />
    </ToastProvider>
  );
};

export default App;
