import React from "react";
import { HardDrive, Cloud, Database } from "lucide-react";
import type { StorageStats, DatabaseStats } from "../../types";
import { formatBytes } from "../../services/tauri";

interface HeaderProps {
  title: string;
  subtitle: string;
  storageStats?: StorageStats | null;
  dbStats?: DatabaseStats | null;
  onRefresh?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  title,
  subtitle,
  storageStats,
  dbStats,
}) => {
  return (
    <header className="h-18 px-8 border-b border-zinc-800/80 bg-zinc-950/70 backdrop-blur-md flex items-center justify-between shrink-0 select-none">
      <div>
        <h2 className="text-lg font-semibold text-zinc-100 tracking-tight leading-none">
          {title}
        </h2>
        <p className="text-xs text-zinc-400 mt-1">{subtitle}</p>
      </div>

      <div className="flex items-center gap-3">
        {dbStats && (
          <div className="flex items-center gap-2 bg-zinc-900/80 border border-zinc-800/80 px-3 py-1.5 rounded-lg text-xs text-zinc-300">
            <Database className="w-3.5 h-3.5 text-blue-400" />
            <span className="text-zinc-400">Snapshots:</span>
            <span className="font-semibold text-zinc-200">
              {dbStats.total_snapshots}
            </span>
            <span className="text-zinc-600">|</span>
            <span className="font-mono text-zinc-300">
              {formatBytes(dbStats.total_bytes)}
            </span>
          </div>
        )}

        {storageStats && (
          <div className="flex items-center gap-2 bg-zinc-900/80 border border-zinc-800/80 px-3 py-1.5 rounded-lg text-xs text-zinc-300">
            <HardDrive className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-zinc-400">Free Space:</span>
            <span className="font-mono text-emerald-400 font-medium">
              {formatBytes(storageStats.free_space_bytes)}
            </span>
          </div>
        )}

        <div className="flex items-center gap-1.5 text-xs bg-zinc-900/50 border border-zinc-800/50 px-2.5 py-1.5 rounded-lg text-zinc-400">
          <Cloud className="w-3.5 h-3.5 text-indigo-400" />
          <span className="text-[11px]">Drive Ready</span>
        </div>
      </div>
    </header>
  );
};
