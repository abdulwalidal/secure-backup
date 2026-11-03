import React, { useState, useEffect } from "react";
import {
  RotateCcw,
  FolderOpen,
  Eye,
  EyeOff,
  CheckCircle2,
  AlertTriangle,
  ShieldCheck,
  ExternalLink,
} from "lucide-react";
import { tauriApi, formatBytes } from "../../services/tauri";
import type { DatabaseSnapshot, RestoreResult, PassphraseVerificationResult } from "../../types";
import { useToast } from "../common/Toast";

interface RestoreViewProps {
  initialSnapshotId?: string;
  onRestoreComplete?: () => void;
}

export const RestoreView: React.FC<RestoreViewProps> = ({
  initialSnapshotId,
  onRestoreComplete,
}) => {
  const { success, error } = useToast();

  const [snapshots, setSnapshots] = useState<DatabaseSnapshot[]>([]);
  const [selectedSnapshotId, setSelectedSnapshotId] = useState<string>(
    initialSnapshotId || ""
  );
  const [destinationPath, setDestinationPath] = useState<string>("");
  const [passphrase, setPassphrase] = useState<string>("");
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [conflictPolicy, setConflictPolicy] = useState<"overwrite" | "skip" | "rename">(
    "overwrite"
  );

  // Passphrase verification state
  const [isVerifying, setIsVerifying] = useState(false);
  const [verificationResult, setVerificationResult] =
    useState<PassphraseVerificationResult | null>(null);

  // Restore execution state
  const [isRestoring, setIsRestoring] = useState(false);
  const [restoreResult, setRestoreResult] = useState<RestoreResult | null>(null);

  useEffect(() => {
    tauriApi.getBackupHistory().then((data) => {
      setSnapshots(data || []);
      if (!selectedSnapshotId && data && data.length > 0) {
        setSelectedSnapshotId(data[0].id);
      }
    }).catch((e) => console.error(e));
  }, []);

  const selectedSnapshot = snapshots.find((s) => s.id === selectedSnapshotId);

  // Verification handler
  const handleVerifyPassphrase = async () => {
    if (!selectedSnapshotId) {
      error("No snapshot selected", "Choose a snapshot to restore.");
      return;
    }
    setIsVerifying(true);
    setVerificationResult(null);
    try {
      const res = await tauriApi.verifySnapshotPassphrase(
        selectedSnapshotId,
        selectedSnapshot?.is_encrypted ? passphrase : undefined
      );
      setVerificationResult(res);
      if (res.success) {
        success("Passphrase Verified", "Key derivation and hash matched.");
      } else {
        error("Verification failed", res.message);
      }
    } catch (e: unknown) {
      error("Verification error", String(e));
    } finally {
      setIsVerifying(false);
    }
  };

  // Browse destination directory
  const handlePickDestination = async () => {
    try {
      const path = await tauriApi.selectDirectory("Select Restore Destination Directory");
      if (path) {
        setDestinationPath(path);
      }
    } catch (e: unknown) {
      error("Destination picker failed", String(e));
    }
  };

  // Start Restore
  const handleStartRestore = async () => {
    if (!selectedSnapshotId) {
      error("Validation", "Please select a snapshot.");
      return;
    }
    if (!destinationPath) {
      error("Validation", "Please choose a destination directory.");
      return;
    }
    if (selectedSnapshot?.is_encrypted && !passphrase) {
      error("Validation", "Please enter the decryption passphrase.");
      return;
    }

    setIsRestoring(true);
    setRestoreResult(null);

    try {
      const result = await tauriApi.restoreSnapshot({
        snapshot_id: selectedSnapshotId,
        destination_path: destinationPath,
        passphrase: selectedSnapshot?.is_encrypted ? passphrase : undefined,
        source_type: "local",
        conflict_policy: conflictPolicy,
      });

      setRestoreResult(result);
      success(
        "Restore Complete",
        `Restored ${result.files_restored} files to destination.`
      );
      if (onRestoreComplete) onRestoreComplete();
    } catch (e: unknown) {
      error("Restore failed", String(e));
    } finally {
      setIsRestoring(false);
    }
  };

  return (
    <div className="space-y-6 pb-12">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Configuration Form (2 cols) */}
        <div className="lg:col-span-2 space-y-6">
          {/* Step 1: Snapshot Selection */}
          <div className="p-6 bg-zinc-900/60 border border-zinc-800/80 rounded-2xl backdrop-blur-sm shadow-xl space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-blue-500/10 text-blue-400 flex items-center justify-center font-semibold text-xs border border-blue-500/20">
                1
              </div>
              <div>
                <h3 className="text-sm font-semibold text-zinc-100">
                  Select Backup Snapshot
                </h3>
                <p className="text-xs text-zinc-400">
                  Pick from local or synced cloud snapshot archives
                </p>
              </div>
            </div>

            <select
              value={selectedSnapshotId}
              onChange={(e) => {
                setSelectedSnapshotId(e.target.value);
                setVerificationResult(null);
              }}
              className="w-full bg-zinc-950/80 border border-zinc-800 rounded-xl px-3.5 py-2.5 text-xs text-zinc-200 focus:outline-none focus:border-blue-500"
            >
              {snapshots.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.source_name} ({s.is_encrypted ? "AES-256" : "Plaintext"}) — {s.id.substring(0, 8)}... ({formatBytes(s.total_size_bytes)})
                </option>
              ))}
            </select>

            {selectedSnapshot && (
              <div className="p-3 bg-zinc-950/60 border border-zinc-800/60 rounded-xl text-xs space-y-1">
                <div className="flex justify-between text-zinc-400">
                  <span>Source directory:</span>
                  <span className="font-mono text-zinc-200 truncate max-w-xs">{selectedSnapshot.source_path}</span>
                </div>
                <div className="flex justify-between text-zinc-400">
                  <span>Encryption:</span>
                  <span className={selectedSnapshot.is_encrypted ? "text-emerald-400 font-medium" : "text-zinc-400"}>
                    {selectedSnapshot.is_encrypted ? "AES-256 GCM Enabled" : "None"}
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* Step 2: Destination Directory */}
          <div className="p-6 bg-zinc-900/60 border border-zinc-800/80 rounded-2xl backdrop-blur-sm shadow-xl space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-blue-500/10 text-blue-400 flex items-center justify-center font-semibold text-xs border border-blue-500/20">
                  2
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-zinc-100">
                    Destination Directory
                  </h3>
                  <p className="text-xs text-zinc-400">
                    Where recovered files will be written
                  </p>
                </div>
              </div>

              <button
                type="button"
                onClick={handlePickDestination}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-semibold rounded-xl border border-zinc-700 transition-colors cursor-pointer"
              >
                <FolderOpen className="w-3.5 h-3.5" />
                <span>Browse</span>
              </button>
            </div>

            {destinationPath ? (
              <div className="p-3 bg-zinc-950/70 border border-zinc-800/80 rounded-xl font-mono text-xs text-zinc-300 break-all select-all">
                {destinationPath}
              </div>
            ) : (
              <div
                onClick={handlePickDestination}
                className="border border-dashed border-zinc-800 hover:border-zinc-700 bg-zinc-950/30 rounded-xl p-4 text-center cursor-pointer text-xs text-zinc-500 transition-colors"
              >
                Select or create a folder to unpack the restored files
              </div>
            )}

            {/* Conflict Policy selection */}
            <div className="pt-2">
              <label className="text-xs font-medium text-zinc-400 mb-2 block">
                File Collision Policy
              </label>
              <div className="grid grid-cols-3 gap-2">
                {(["overwrite", "skip", "rename"] as const).map((policy) => (
                  <button
                    key={policy}
                    type="button"
                    onClick={() => setConflictPolicy(policy)}
                    className={`py-2 px-3 rounded-xl text-xs font-medium border capitalize transition-all cursor-pointer ${
                      conflictPolicy === policy
                        ? "bg-blue-600/20 border-blue-500/50 text-blue-300 font-semibold"
                        : "bg-zinc-950/60 border-zinc-800 text-zinc-400 hover:text-zinc-200"
                    }`}
                  >
                    {policy}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Passphrase Verification & Restore Trigger (1 col) */}
        <div className="space-y-6">
          <div className="p-6 bg-zinc-900/60 border border-zinc-800/80 rounded-2xl backdrop-blur-sm shadow-xl space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-emerald-500/10 text-emerald-400 flex items-center justify-center font-semibold text-xs border border-emerald-500/20">
                3
              </div>
              <div>
                <h3 className="text-sm font-semibold text-zinc-100">
                  Decryption Passphrase
                </h3>
                <p className="text-xs text-zinc-400">
                  {selectedSnapshot?.is_encrypted
                    ? "Passphrase required to unlock payload"
                    : "Snapshot is unencrypted"}
                </p>
              </div>
            </div>

            {selectedSnapshot?.is_encrypted ? (
              <div className="space-y-3">
                <div className="relative">
                  <input
                    type={showPassphrase ? "text" : "password"}
                    placeholder="Enter backup passphrase"
                    value={passphrase}
                    onChange={(e) => {
                      setPassphrase(e.target.value);
                      setVerificationResult(null);
                    }}
                    className="w-full bg-zinc-950/80 border border-zinc-800 rounded-xl px-3.5 py-2.5 pr-10 text-xs text-zinc-200 focus:outline-none focus:border-emerald-500 font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassphrase(!showPassphrase)}
                    className="absolute right-3 top-2.5 text-zinc-500 hover:text-zinc-300"
                  >
                    {showPassphrase ? (
                      <EyeOff className="w-4 h-4" />
                    ) : (
                      <Eye className="w-4 h-4" />
                    )}
                  </button>
                </div>

                <button
                  type="button"
                  onClick={handleVerifyPassphrase}
                  disabled={isVerifying || !passphrase}
                  className="w-full py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-semibold rounded-xl border border-zinc-700 transition-colors cursor-pointer disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  {isVerifying ? (
                    <span className="animate-spin inline-block w-3 h-3 border-2 border-emerald-500 border-t-transparent rounded-full" />
                  ) : (
                    <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  )}
                  <span>Test Passphrase Integrity</span>
                </button>

                {verificationResult && (
                  <div
                    className={`p-3 rounded-xl border text-xs flex items-start gap-2 ${
                      verificationResult.success
                        ? "bg-emerald-950/30 border-emerald-500/40 text-emerald-300"
                        : "bg-rose-950/30 border-rose-500/40 text-rose-300"
                    }`}
                  >
                    {verificationResult.success ? (
                      <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-emerald-400" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-rose-400" />
                    )}
                    <div>
                      <div className="font-semibold">
                        {verificationResult.success
                          ? "Passphrase Valid"
                          : "Integrity Failed"}
                      </div>
                      <div className="text-[11px] opacity-80 mt-0.5">
                        {verificationResult.message}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="p-3 bg-zinc-950/70 border border-zinc-800 rounded-xl text-xs text-zinc-400 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>No passphrase required for this snapshot.</span>
              </div>
            )}

            <div className="pt-4 border-t border-zinc-800/80">
              <button
                type="button"
                onClick={handleStartRestore}
                disabled={isRestoring || !destinationPath}
                className="w-full py-3 px-4 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 active:from-emerald-700 active:to-teal-700 text-white text-xs font-semibold rounded-xl shadow-lg shadow-emerald-500/25 flex items-center justify-center gap-2 transition-all cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isRestoring ? (
                  <>
                    <span className="animate-spin inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full" />
                    <span>Restoring Files...</span>
                  </>
                ) : (
                  <>
                    <RotateCcw className="w-4 h-4" />
                    <span>Execute Restore</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Restore Results Audit Log */}
      {restoreResult && (
        <div className="p-6 bg-zinc-900/60 border border-zinc-800/80 rounded-2xl shadow-xl space-y-4 animate-in fade-in slide-in-from-bottom-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-emerald-500/10 text-emerald-400 flex items-center justify-center border border-emerald-500/20">
                <CheckCircle2 className="w-5 h-5" />
              </div>
              <div>
                <h4 className="text-sm font-semibold text-zinc-100">
                  Restore Completed Successfully
                </h4>
                <p className="text-xs text-zinc-400">
                  {restoreResult.files_restored} restored, {restoreResult.files_skipped} skipped, {restoreResult.files_failed} failed in {restoreResult.elapsed_millis}ms
                </p>
              </div>
            </div>

            <button
              onClick={() => tauriApi.revealInExplorer(restoreResult.destination_directory)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-xl text-xs font-medium text-zinc-300 cursor-pointer"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              <span>Open Destination</span>
            </button>
          </div>

          {/* Itemized file results */}
          <div className="max-h-60 overflow-y-auto space-y-1.5 bg-zinc-950/60 p-3 rounded-xl border border-zinc-800/80">
            {restoreResult.items.map((item, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between p-2 rounded-lg bg-zinc-900/60 text-xs border border-zinc-800/40"
              >
                <div className="font-mono text-zinc-300 truncate max-w-lg">
                  {item.relative_path}
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <span className="font-mono text-zinc-500 text-[11px]">
                    {formatBytes(item.size_bytes)}
                  </span>
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded-full uppercase font-semibold ${
                      item.status === "restored"
                        ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                        : item.status === "skipped"
                        ? "bg-amber-950 text-amber-400 border border-amber-800"
                        : "bg-rose-950 text-rose-400 border border-rose-800"
                    }`}
                  >
                    {item.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
