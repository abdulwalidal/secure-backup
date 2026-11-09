import React, { useState, useEffect, useMemo } from "react";
import {
  Search,
  Lock,
  Unlock,
  Trash2,
  FolderOpen,
  Calendar,
  FileText,
  Copy,
  Check,
  RefreshCw,
  X,
  FileCode,
} from "lucide-react";
import { tauriApi, formatBytes, formatDate } from "../../services/tauri";
import type { DatabaseSnapshot, DatabaseSnapshotFile } from "../../types";
import { useToast } from "../common/Toast";

interface BackupHistoryViewProps {
  onRestoreSelect?: (snapshotId: string) => void;
}

export const BackupHistoryView: React.FC<BackupHistoryViewProps> = ({
  onRestoreSelect,
}) => {
  const { success, error } = useToast();
  const [snapshots, setSnapshots] = useState<DatabaseSnapshot[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [filterType, setFilterType] = useState<"all" | "encrypted" | "unencrypted">("all");

  // Inspection modal state
  const [inspectingSnapshot, setInspectingSnapshot] = useState<DatabaseSnapshot | null>(null);
  const [snapshotFiles, setSnapshotFiles] = useState<DatabaseSnapshotFile[]>([]);
  const [isLoadingFiles, setIsLoadingFiles] = useState(false);
  const [fileSearch, setFileSearch] = useState("");

  // Delete confirmation modal state
  const [snapshotToDelete, setSnapshotToDelete] = useState<DatabaseSnapshot | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  // Copy helper state
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const loadSnapshots = async () => {
    setIsLoading(true);
    try {
      const data = await tauriApi.getBackupHistory();
      setSnapshots(data || []);
    } catch (e: unknown) {
      error("Failed to load snapshots", String(e));
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadSnapshots();
  }, []);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(text);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleInspect = async (snapshot: DatabaseSnapshot) => {
    setInspectingSnapshot(snapshot);
    setIsLoadingFiles(true);
    setFileSearch("");
    try {
      const files = await tauriApi.getSnapshotFiles(snapshot.id);
      setSnapshotFiles(files || []);
    } catch (e: unknown) {
      error("Failed to inspect snapshot files", String(e));
    } finally {
      setIsLoadingFiles(false);
    }
  };

  const handleDelete = async () => {
    if (!snapshotToDelete) return;
    setIsDeleting(true);
    try {
      await tauriApi.deleteBackupSnapshot(snapshotToDelete.id);
      success("Snapshot Deleted", `Removed snapshot ${snapshotToDelete.id}`);
      setSnapshotToDelete(null);
      await loadSnapshots();
    } catch (e: unknown) {
      error("Failed to delete snapshot", String(e));
    } finally {
      setIsDeleting(false);
    }
  };

  const filteredSnapshots = useMemo(() => {
    if (!Array.isArray(snapshots)) return [];
    return snapshots.filter((s) => {
      const id = s?.id || "";
      const sourceName = s?.source_name || "";
      const sourcePath = s?.source_path || "";
      const matchesSearch =
        id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        sourceName.toLowerCase().includes(searchQuery.toLowerCase()) ||
        sourcePath.toLowerCase().includes(searchQuery.toLowerCase());

      if (!matchesSearch) return false;

      if (filterType === "encrypted") return !!s.is_encrypted;
      if (filterType === "unencrypted") return !s.is_encrypted;
      return true;
    });
  }, [snapshots, searchQuery, filterType]);

  const filteredFiles = useMemo(() => {
    if (!Array.isArray(snapshotFiles)) return [];
    if (!fileSearch) return snapshotFiles;
    return snapshotFiles.filter((f) =>
      (f?.relative_path || "").toLowerCase().includes(fileSearch.toLowerCase())
    );
  }, [snapshotFiles, fileSearch]);

  return (
    <div className="space-y-6 pb-12">
      {/* Controls Bar: Search & Filter Pills */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-4 bg-zinc-900 border border-zinc-800 rounded-2xl shadow-xl">
        <div className="relative flex-1 w-full">
          <Search className="w-4 h-4 absolute left-3.5 top-3 text-zinc-500" />
          <input
            type="text"
            placeholder="Search snapshots by name, folder path, or UUID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-zinc-950/80 border border-zinc-800 rounded-xl pl-10 pr-4 py-2 text-xs text-zinc-200 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto justify-end">
          <div className="flex bg-zinc-950/80 border border-zinc-800 rounded-xl p-1 gap-1 text-xs">
            {(["all", "encrypted", "unencrypted"] as const).map((type) => (
              <button
                key={type}
                onClick={() => setFilterType(type)}
                className={`px-3 py-1 rounded-lg capitalize transition-colors cursor-pointer ${
                  filterType === type
                    ? "bg-zinc-800 text-zinc-100 font-medium"
                    : "text-zinc-400 hover:text-zinc-200"
                }`}
              >
                {type}
              </button>
            ))}
          </div>

          <button
            onClick={loadSnapshots}
            disabled={isLoading}
            className="p-2 bg-zinc-900 hover:bg-zinc-800 border border-zinc-700/80 rounded-xl text-zinc-400 hover:text-zinc-200 transition-colors cursor-pointer"
            title="Reload snapshots"
          >
            <RefreshCw
              className={`w-4 h-4 ${isLoading ? "animate-spin text-blue-400" : ""}`}
            />
          </button>
        </div>
      </div>

      {/* Snapshots Table / Grid */}
      {filteredSnapshots.length === 0 ? (
        <div className="border border-dashed border-zinc-800 rounded-2xl p-12 text-center bg-zinc-950/40">
          <FolderOpen className="w-10 h-10 text-zinc-600 mx-auto mb-3" />
          <p className="text-sm font-semibold text-zinc-300">
            {snapshots.length === 0 ? "No backups found" : "No matching snapshots"}
          </p>
          <p className="text-xs text-zinc-500 mt-1 max-w-sm mx-auto">
            {snapshots.length === 0
              ? "Create your first encrypted snapshot on the Dashboard."
              : "Try adjusting your search query or filter tags."}
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-3">
          {filteredSnapshots.map((snapshot) => (
            <div
              key={snapshot.id}
              className="p-5 bg-zinc-900/50 hover:bg-zinc-900/80 border border-zinc-800/80 hover:border-zinc-700/80 rounded-2xl transition-all shadow-md group flex flex-col md:flex-row md:items-center justify-between gap-4"
            >
              <div className="flex items-start gap-4">
                <div
                  className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 border ${
                    snapshot.is_encrypted
                      ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                      : "bg-zinc-800 text-zinc-400 border-zinc-700"
                  }`}
                >
                  {snapshot.is_encrypted ? (
                    <Lock className="w-5 h-5" />
                  ) : (
                    <Unlock className="w-5 h-5" />
                  )}
                </div>

                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <h4 className="text-sm font-semibold text-zinc-100 truncate">
                      {snapshot.source_name}
                    </h4>
                    <span
                      className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${
                        snapshot.is_encrypted
                          ? "bg-emerald-950/60 text-emerald-400 border-emerald-800/60"
                          : "bg-zinc-800 text-zinc-400 border-zinc-700"
                      }`}
                    >
                      {snapshot.is_encrypted ? "AES-256 GCM" : "Plaintext"}
                    </span>
                  </div>

                  <p className="text-xs text-zinc-400 font-mono truncate max-w-md">
                    {snapshot.source_path}
                  </p>

                  <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px] text-zinc-500">
                    <span className="flex items-center gap-1">
                      <Calendar className="w-3 h-3" />
                      {formatDate(snapshot.created_at)}
                    </span>
                    <span>•</span>
                    <span>
                      {snapshot.total_files}{" "}
                      {snapshot.total_files === 1 ? "file" : "files"}
                    </span>
                    <span>•</span>
                    <span className="font-mono text-zinc-400">
                      {formatBytes(snapshot.total_size_bytes)}
                    </span>
                  </div>
                </div>
              </div>

              {/* Action buttons */}
              <div className="flex items-center gap-2 self-end md:self-center shrink-0">
                <button
                  onClick={() => handleInspect(snapshot)}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-xl text-xs font-medium text-zinc-200 transition-colors cursor-pointer"
                >
                  <FileText className="w-3.5 h-3.5 text-blue-400" />
                  <span>Inspect</span>
                </button>

                {onRestoreSelect && (
                  <button
                    onClick={() => onRestoreSelect(snapshot.id)}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/30 rounded-xl text-xs font-semibold text-blue-400 transition-colors cursor-pointer"
                  >
                    <span>Restore</span>
                  </button>
                )}

                <button
                  onClick={() => setSnapshotToDelete(snapshot)}
                  className="p-1.5 text-zinc-500 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition-colors cursor-pointer"
                  title="Delete Snapshot"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Manifest Inspection Modal */}
      {inspectingSnapshot && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl max-w-3xl w-full max-h-[85vh] flex flex-col shadow-2xl animate-in fade-in zoom-in-95">
            <div className="flex items-center justify-between p-5 border-b border-zinc-800">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-blue-500/10 text-blue-400 flex items-center justify-center border border-blue-500/20">
                  <FileCode className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-zinc-100">
                    Snapshot Manifest Inspector
                  </h3>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-[11px] font-mono text-zinc-400">
                      ID: {inspectingSnapshot.id}
                    </span>
                    <button
                      onClick={() => handleCopy(inspectingSnapshot.id)}
                      className="text-zinc-500 hover:text-zinc-300 cursor-pointer"
                    >
                      {copiedId === inspectingSnapshot.id ? (
                        <Check className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                    </button>
                  </div>
                </div>
              </div>

              <button
                onClick={() => setInspectingSnapshot(null)}
                className="text-zinc-400 hover:text-zinc-200 p-1 rounded-lg"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Subheader & Search */}
            <div className="p-4 bg-zinc-950/50 border-b border-zinc-800/80 flex items-center justify-between gap-4">
              <div className="relative flex-1">
                <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-zinc-500" />
                <input
                  type="text"
                  placeholder="Filter files by relative path..."
                  value={fileSearch}
                  onChange={(e) => setFileSearch(e.target.value)}
                  className="w-full bg-zinc-900 border border-zinc-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-zinc-200 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="text-xs text-zinc-400 shrink-0">
                Total Files:{" "}
                <span className="font-semibold text-zinc-200">
                  {inspectingSnapshot.total_files}
                </span>{" "}
                ({formatBytes(inspectingSnapshot.total_size_bytes)})
              </div>
            </div>

            {/* Files List */}
            <div className="flex-1 overflow-y-auto p-4 space-y-2">
              {isLoadingFiles ? (
                <div className="text-center py-12 text-zinc-400 text-xs">
                  <span className="animate-spin inline-block w-4 h-4 border-2 border-blue-500 border-t-transparent rounded-full mb-2" />
                  <div>Loading file manifest records...</div>
                </div>
              ) : filteredFiles.length === 0 ? (
                <div className="text-center py-12 text-zinc-500 text-xs">
                  No files match your query.
                </div>
              ) : (
                filteredFiles.map((f, idx) => (
                  <div
                    key={idx}
                    className="p-3 bg-zinc-950/70 border border-zinc-800/60 rounded-xl flex items-center justify-between text-xs gap-3"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="font-mono text-zinc-200 truncate select-all">
                        {f.relative_path}
                      </div>
                      <div className="flex items-center gap-3 text-[10px] text-zinc-500 mt-1">
                        <span className="font-mono text-zinc-400">
                          {formatBytes(f.size_bytes)}
                        </span>
                        <span>•</span>
                        <span className="font-mono truncate select-all max-w-[200px]">
                          SHA: {f.sha256_hash.substring(0, 16)}...
                        </span>
                      </div>
                    </div>

                    <button
                      onClick={() => handleCopy(f.sha256_hash)}
                      className="text-zinc-500 hover:text-zinc-300 p-1 cursor-pointer shrink-0"
                      title="Copy full SHA-256 hash"
                    >
                      {copiedId === f.sha256_hash ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                ))
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-4 bg-zinc-950/80 border-t border-zinc-800 flex justify-end">
              <button
                onClick={() => setInspectingSnapshot(null)}
                className="px-4 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-semibold rounded-xl transition-colors cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {snapshotToDelete && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl max-w-md w-full p-6 shadow-2xl animate-in fade-in zoom-in-95 space-y-4">
            <div className="flex items-center gap-3 text-rose-400">
              <Trash2 className="w-6 h-6" />
              <h3 className="text-base font-semibold text-zinc-100">
                Delete Snapshot?
              </h3>
            </div>

            <p className="text-xs text-zinc-400 leading-relaxed">
              Are you sure you want to delete snapshot{" "}
              <span className="font-mono text-zinc-200">
                {snapshotToDelete.id}
              </span>
              ? This will remove all local encrypted payload files and cannot be
              undone.
            </p>

            <div className="flex justify-end gap-3 pt-3">
              <button
                onClick={() => setSnapshotToDelete(null)}
                disabled={isDeleting}
                className="px-4 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-semibold rounded-xl transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleDelete}
                disabled={isDeleting}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold rounded-xl shadow-lg shadow-rose-600/20 transition-colors cursor-pointer disabled:opacity-50"
              >
                {isDeleting ? "Deleting..." : "Permanently Delete"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
