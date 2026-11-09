import React, { useState, useEffect } from "react";
import {
  Folder,
  FolderOpen,
  Lock,
  Eye,
  EyeOff,
  Play,
  CheckCircle2,
  AlertCircle,
  Shield,
  Layers,
  Sparkles,
  ExternalLink,
  Copy,
  Check,
  Cloud,
  Loader2,
} from "lucide-react";
import { tauriApi, formatBytes } from "../../services/tauri";
import type { FolderInfo, BackupResult } from "../../types";
import { useToast } from "../common/Toast";

const PRESET_EXCLUSIONS = [
  "node_modules",
  ".git",
  "target",
  "dist",
  "build",
  ".DS_Store",
  "*.tmp",
  "*.log",
];

export const DashboardView: React.FC<{ onBackupCompleted?: () => void }> = ({
  onBackupCompleted,
}) => {
  const { success, error, info } = useToast();

  // Folder selection state
  const [selectedPath, setSelectedPath] = useState<string>("");
  const [folderInfo, setFolderInfo] = useState<FolderInfo | null>(null);
  const [isInspecting, setIsInspecting] = useState(false);

  // Encryption state
  const [isEncrypted, setIsEncrypted] = useState(true);
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [showPassphrase, setShowPassphrase] = useState(false);

  // Exclusions state
  const [enableDefaultExclusions, setEnableDefaultExclusions] = useState(true);
  const [selectedPresets, setSelectedPresets] = useState<string[]>([
    "node_modules",
    ".git",
    "target",
    "dist",
  ]);
  const [customPattern, setCustomPattern] = useState("");
  const [customPatterns, setCustomPatterns] = useState<string[]>([]);

  // Execution state
  const [isBackingUp, setIsBackingUp] = useState(false);
  const [backupResult, setBackupResult] = useState<BackupResult | null>(null);
  const [hasCopiedId, setHasCopiedId] = useState(false);

  // Cloud sync state
  const [isGoogleDriveConnected, setIsGoogleDriveConnected] = useState(false);
  const [connectedEmail, setConnectedEmail] = useState<string | null>(null);
  const [autoSyncGoogleDrive, setAutoSyncGoogleDrive] = useState(false);
  const [isSyncingCloud, setIsSyncingCloud] = useState(false);

  useEffect(() => {
    tauriApi
      .getCloudProviders()
      .then((providers) => {
        if (Array.isArray(providers)) {
          const gdrive = providers.find(
            (p) => p.provider_type === "google_drive"
          );
          if (gdrive && gdrive.is_connected) {
            setIsGoogleDriveConnected(true);
            setConnectedEmail(gdrive.account_email || null);
            setAutoSyncGoogleDrive(true);
          }
        }
      })
      .catch(() => {});
  }, []);

  // Passphrase strength calculation
  const getPassphraseStrength = (pw: string) => {
    if (!pw) return { score: 0, label: "None", color: "bg-zinc-700" };
    let score = 0;
    if (pw.length >= 8) score += 1;
    if (pw.length >= 12) score += 1;
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score += 1;
    if (/[0-9]/.test(pw)) score += 1;
    if (/[^A-Za-z0-9]/.test(pw)) score += 1;

    if (score <= 2) return { score: 1, label: "Weak", color: "bg-rose-500" };
    if (score <= 4) return { score: 2, label: "Good", color: "bg-amber-500" };
    return { score: 3, label: "Strong", color: "bg-emerald-500" };
  };

  const strength = getPassphraseStrength(passphrase);

  // Directory picker handler
  const handlePickDirectory = async () => {
    try {
      const path = await tauriApi.selectDirectory("Select Folder to Backup");
      if (!path) return;
      setSelectedPath(path);
      setIsInspecting(true);

      const infoResult = await tauriApi.inspectFolder(path);
      setFolderInfo(infoResult);
      setIsInspecting(false);
    } catch (e: unknown) {
      setIsInspecting(false);
      error("Failed to inspect folder", String(e));
    }
  };

  // Toggle exclusion presets
  const togglePreset = (pattern: string) => {
    setSelectedPresets((prev) =>
      prev.includes(pattern)
        ? prev.filter((p) => p !== pattern)
        : [...prev, pattern]
    );
  };

  const handleAddCustomPattern = (e: React.KeyboardEvent | React.MouseEvent) => {
    if ("key" in e && e.key !== "Enter") return;
    if (!customPattern.trim()) return;
    if (!customPatterns.includes(customPattern.trim())) {
      setCustomPatterns((prev) => [...prev, customPattern.trim()]);
    }
    setCustomPattern("");
  };

  const handleRemoveCustomPattern = (pat: string) => {
    setCustomPatterns((prev) => prev.filter((p) => p !== pat));
  };

  const handleGeneratePassphrase = () => {
    const chars =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~=";
    let generated = "";
    for (let i = 0; i < 20; i++) {
      generated += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    setPassphrase(generated);
    setConfirmPassphrase(generated);
    setShowPassphrase(true);
    info("Passphrase generated", "Make sure to keep this safe!");
  };

  // Execute backup
  const handleStartBackup = async () => {
    if (!selectedPath) {
      error("No directory selected", "Please choose a directory to back up.");
      return;
    }

    if (isEncrypted) {
      if (!passphrase.trim()) {
        error("Passphrase required", "Enter an encryption passphrase.");
        return;
      }
      if (passphrase !== confirmPassphrase) {
        error("Passphrase mismatch", "Confirmation passphrase does not match.");
        return;
      }
    }

    setIsBackingUp(true);
    setBackupResult(null);

    const allExclusions = [...selectedPresets, ...customPatterns];

    try {
      const res = await tauriApi.startBackup({
        source_path: selectedPath,
        passphrase: isEncrypted ? passphrase : undefined,
        exclude_patterns: allExclusions,
        enable_default_exclusions: enableDefaultExclusions,
      });

      setBackupResult(res);
      setIsBackingUp(false);
      success("Backup Complete", `Snapshot ${res.backup_id} created successfully.`);

      // Auto-upload to Google Drive if enabled & connected
      if (autoSyncGoogleDrive && isGoogleDriveConnected) {
        setIsSyncingCloud(true);
        try {
          const summary = await tauriApi.syncSnapshotToCloud(
            res.backup_id,
            "google_drive"
          );
          success(
            "Uploaded to Google Drive",
            `Encrypted snapshot synced to Google Drive (${summary.files_uploaded} files, ${formatBytes(
              summary.total_bytes_uploaded
            )}).`
          );
        } catch (cloudErr: unknown) {
          error("Google Drive Upload Failed", String(cloudErr));
        } finally {
          setIsSyncingCloud(false);
        }
      }

      if (onBackupCompleted) onBackupCompleted();
    } catch (e: unknown) {
      setIsBackingUp(false);
      error("Backup failed", String(e));
    }
  };

  const copySnapshotId = (id: string) => {
    navigator.clipboard.writeText(id);
    setHasCopiedId(true);
    setTimeout(() => setHasCopiedId(false), 2000);
  };

  return (
    <div className="space-y-6 pb-12">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Source & Exclusions (2 cols) */}
        <div className="lg:col-span-2 space-y-6">
          {/* Source Selection Card */}
          <div className="p-6 bg-zinc-900 border border-zinc-800 rounded-2xl shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-blue-500/10 text-blue-400 flex items-center justify-center border border-blue-500/20">
                  <Folder className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-zinc-100">
                    Source Directory
                  </h3>
                  <p className="text-xs text-zinc-400">
                    Select local folder or project to snapshot
                  </p>
                </div>
              </div>
              <button
                onClick={handlePickDirectory}
                disabled={isBackingUp}
                className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 active:bg-blue-700 text-white text-xs font-semibold rounded-xl shadow-lg shadow-blue-600/20 transition-all cursor-pointer disabled:opacity-50"
              >
                <FolderOpen className="w-4 h-4" />
                <span>Browse Folder</span>
              </button>
            </div>

            {selectedPath ? (
              <div className="p-4 bg-zinc-950/70 border border-zinc-800/80 rounded-xl space-y-3">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs text-zinc-300 break-all select-all">
                    {selectedPath}
                  </span>
                </div>
                {isInspecting ? (
                  <div className="text-xs text-zinc-400 flex items-center gap-2">
                    <span className="animate-spin inline-block w-3 h-3 border-2 border-blue-500 border-t-transparent rounded-full" />
                    Scanning directory files...
                  </div>
                ) : folderInfo ? (
                  <div className="flex items-center gap-4 pt-2 border-t border-zinc-800/60 text-xs text-zinc-400">
                    <div>
                      Files:{" "}
                      <span className="text-zinc-200 font-semibold">
                        {folderInfo.file_count.toLocaleString()}
                      </span>
                    </div>
                    <span className="text-zinc-600">|</span>
                    <div>
                      Size:{" "}
                      <span className="text-zinc-200 font-semibold font-mono">
                        {formatBytes(folderInfo.total_size_bytes)}
                      </span>
                    </div>
                  </div>
                ) : null}
              </div>
            ) : (
              <div
                onClick={handlePickDirectory}
                className="border-2 border-dashed border-zinc-800 hover:border-zinc-700 bg-zinc-950/30 rounded-xl p-8 text-center cursor-pointer transition-colors"
              >
                <FolderOpen className="w-8 h-8 text-zinc-500 mx-auto mb-2" />
                <p className="text-xs text-zinc-400 font-medium">
                  Click here to select a folder for backup
                </p>
                <p className="text-[11px] text-zinc-600 mt-1">
                  Supports code repositories, documents, or entire workspaces
                </p>
              </div>
            )}
          </div>

          {/* Exclusions Card */}
          <div className="p-6 bg-zinc-900 border border-zinc-800 rounded-2xl shadow-xl space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-purple-500/10 text-purple-400 flex items-center justify-center border border-purple-500/20">
                  <Layers className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-zinc-100">
                    Exclusion Filters
                  </h3>
                  <p className="text-xs text-zinc-400">
                    Ignore temporary files, dependencies, and build caches
                  </p>
                </div>
              </div>
              <label className="flex items-center gap-2 cursor-pointer text-xs text-zinc-400">
                <input
                  type="checkbox"
                  checked={enableDefaultExclusions}
                  onChange={(e) => setEnableDefaultExclusions(e.target.checked)}
                  className="rounded bg-zinc-800 border-zinc-700 text-blue-600 focus:ring-0"
                />
                <span>Default rules</span>
              </label>
            </div>

            {/* Presets */}
            <div>
              <div className="text-[11px] font-semibold text-zinc-400 uppercase tracking-wider mb-2">
                Quick Preset Chips
              </div>
              <div className="flex flex-wrap gap-2">
                {PRESET_EXCLUSIONS.map((preset) => {
                  const active = selectedPresets.includes(preset);
                  return (
                    <button
                      key={preset}
                      type="button"
                      onClick={() => togglePreset(preset)}
                      className={`text-xs px-2.5 py-1 rounded-lg border font-mono transition-all cursor-pointer ${
                        active
                          ? "bg-purple-600/20 border-purple-500/40 text-purple-300"
                          : "bg-zinc-950/60 border-zinc-800 text-zinc-400 hover:text-zinc-200"
                      }`}
                    >
                      {active ? "✓ " : "+ "}
                      {preset}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Custom pattern input */}
            <div className="pt-2">
              <div className="text-[11px] font-semibold text-zinc-400 uppercase tracking-wider mb-2">
                Custom Patterns
              </div>
              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="e.g. *.tmp, secret.key, raw_videos"
                  value={customPattern}
                  onChange={(e) => setCustomPattern(e.target.value)}
                  onKeyDown={handleAddCustomPattern}
                  className="flex-1 bg-zinc-950/80 border border-zinc-800 rounded-xl px-3.5 py-2 text-xs text-zinc-200 focus:outline-none focus:border-blue-500 font-mono"
                />
                <button
                  type="button"
                  onClick={handleAddCustomPattern}
                  className="px-3.5 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-semibold rounded-xl transition-colors cursor-pointer"
                >
                  Add
                </button>
              </div>

              {customPatterns.length > 0 && (
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {customPatterns.map((pat) => (
                    <span
                      key={pat}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-zinc-800/80 border border-zinc-700/60 text-xs font-mono text-zinc-300"
                    >
                      {pat}
                      <button
                        onClick={() => handleRemoveCustomPattern(pat)}
                        className="text-zinc-400 hover:text-rose-400 ml-1 cursor-pointer"
                      >
                        ×
                      </button>
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Right Column: Encryption & Action (1 col) */}
        <div className="space-y-6">
          <div className="p-6 bg-zinc-900 border border-zinc-800 rounded-2xl shadow-xl space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-emerald-500/10 text-emerald-400 flex items-center justify-center border border-emerald-500/20">
                  <Shield className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-zinc-100">
                    AES-256 GCM
                  </h3>
                  <p className="text-xs text-zinc-400">Zero-knowledge cipher</p>
                </div>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={isEncrypted}
                  onChange={(e) => setIsEncrypted(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-zinc-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-zinc-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-emerald-600"></div>
              </label>
            </div>

            {isEncrypted ? (
              <div className="space-y-3 pt-2">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-medium text-zinc-300">
                    Passphrase
                  </label>
                  <button
                    type="button"
                    onClick={handleGeneratePassphrase}
                    className="text-[11px] text-blue-400 hover:text-blue-300 flex items-center gap-1 cursor-pointer"
                  >
                    <Sparkles className="w-3 h-3" />
                    <span>Generate</span>
                  </button>
                </div>

                <div className="relative">
                  <input
                    type={showPassphrase ? "text" : "password"}
                    placeholder="Enter strong encryption passphrase"
                    value={passphrase}
                    onChange={(e) => setPassphrase(e.target.value)}
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

                {/* Password strength meter */}
                {passphrase && (
                  <div className="space-y-1">
                    <div className="flex justify-between text-[10px] text-zinc-400">
                      <span>Entropy Strength</span>
                      <span className="font-semibold text-zinc-300">
                        {strength.label}
                      </span>
                    </div>
                    <div className="h-1.5 w-full bg-zinc-800 rounded-full overflow-hidden flex gap-1">
                      <div
                        className={`h-full transition-all duration-300 rounded-full ${strength.color} ${
                          strength.score >= 1 ? "w-1/3" : "w-0"
                        }`}
                      />
                      <div
                        className={`h-full transition-all duration-300 rounded-full ${strength.color} ${
                          strength.score >= 2 ? "w-1/3" : "w-0"
                        }`}
                      />
                      <div
                        className={`h-full transition-all duration-300 rounded-full ${strength.color} ${
                          strength.score >= 3 ? "w-1/3" : "w-0"
                        }`}
                      />
                    </div>
                  </div>
                )}

                <div>
                  <label className="text-xs font-medium text-zinc-300 mb-1 block">
                    Confirm Passphrase
                  </label>
                  <input
                    type={showPassphrase ? "text" : "password"}
                    placeholder="Repeat passphrase"
                    value={confirmPassphrase}
                    onChange={(e) => setConfirmPassphrase(e.target.value)}
                    className="w-full bg-zinc-950/80 border border-zinc-800 rounded-xl px-3.5 py-2.5 text-xs text-zinc-200 focus:outline-none focus:border-emerald-500 font-mono"
                  />
                </div>
              </div>
            ) : (
              <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-xl flex items-start gap-2.5 text-xs text-amber-300">
                <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
                <span>
                  Backup will be created unencrypted. Enable AES-256 for maximum
                  privacy and zero-knowledge protection.
                </span>
              </div>
            )}

            {/* Cloud Target: Google Drive */}
            <div className="p-4 bg-zinc-950/60 border border-zinc-800 rounded-xl space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="w-8 h-8 rounded-lg bg-indigo-500/10 text-indigo-400 flex items-center justify-center border border-indigo-500/20">
                    <Cloud className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-xs font-semibold text-zinc-200">
                      Google Drive Sync
                    </h4>
                    <p className="text-[11px] text-zinc-400">
                      {isGoogleDriveConnected
                        ? `Connected (${connectedEmail || "Google Account"})`
                        : "Not connected"}
                    </p>
                  </div>
                </div>

                {isGoogleDriveConnected ? (
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={autoSyncGoogleDrive}
                      onChange={(e) => setAutoSyncGoogleDrive(e.target.checked)}
                      className="sr-only peer"
                    />
                    <div className="w-9 h-5 bg-zinc-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-zinc-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-indigo-600"></div>
                  </label>
                ) : (
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-zinc-800 text-zinc-400 border border-zinc-700">
                    Offline
                  </span>
                )}
              </div>
              <p className="text-[11px] text-zinc-400 leading-relaxed">
                {isGoogleDriveConnected
                  ? autoSyncGoogleDrive
                    ? "Will automatically upload the encrypted snapshot to Google Drive upon completion."
                    : "Automatic upload to Google Drive is disabled."
                  : "Connect your Google Drive in Settings to automatically upload encrypted backups off-site."}
              </p>
            </div>

            {/* Execute Button */}
            <div className="pt-4">
              <button
                type="button"
                onClick={handleStartBackup}
                disabled={isBackingUp || isSyncingCloud || !selectedPath}
                className="w-full py-3 px-4 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 active:from-blue-700 active:to-indigo-700 text-white text-xs font-semibold rounded-xl shadow-lg shadow-blue-500/25 flex items-center justify-center gap-2 transition-all cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isBackingUp ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin text-white" />
                    <span>Encrypting & Storing...</span>
                  </>
                ) : isSyncingCloud ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin text-white" />
                    <span>Uploading to Google Drive...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 fill-white" />
                    <span>Create Snapshot</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Backup Result Summary Modal/Card */}
      {backupResult && (
        <div className="p-6 bg-emerald-950/20 border border-emerald-500/30 rounded-2xl animate-in fade-in slide-in-from-bottom-3 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-emerald-500/20 text-emerald-400 flex items-center justify-center">
                <CheckCircle2 className="w-5 h-5" />
              </div>
              <div>
                <h4 className="text-sm font-semibold text-emerald-300">
                  Snapshot Created Successfully
                </h4>
                <p className="text-xs text-zinc-400">
                  Completed in {backupResult.elapsed_millis}ms
                </p>
              </div>
            </div>

            <button
              onClick={() =>
                tauriApi.revealInExplorer(backupResult.target_directory)
              }
              className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 rounded-lg text-xs font-medium text-zinc-300 cursor-pointer"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              <span>Reveal in Explorer</span>
            </button>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 bg-zinc-950/60 rounded-xl border border-zinc-800/80 text-xs">
            <div>
              <span className="text-zinc-500 block">Snapshot ID</span>
              <div className="flex items-center gap-1.5 mt-0.5">
                <span className="font-mono text-zinc-200 font-medium truncate">
                  {backupResult.backup_id}
                </span>
                <button
                  onClick={() => copySnapshotId(backupResult.backup_id)}
                  className="text-zinc-400 hover:text-zinc-200 cursor-pointer"
                >
                  {hasCopiedId ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                </button>
              </div>
            </div>

            <div>
              <span className="text-zinc-500 block">Files Saved</span>
              <span className="font-semibold text-zinc-200 text-sm mt-0.5 block">
                {backupResult.manifest.total_files}
              </span>
            </div>

            <div>
              <span className="text-zinc-500 block">Encrypted Size</span>
              <span className="font-mono text-zinc-200 font-semibold text-sm mt-0.5 block">
                {formatBytes(backupResult.manifest.total_size_bytes)}
              </span>
            </div>

            <div>
              <span className="text-zinc-500 block">Cipher Status</span>
              <span className="inline-flex items-center gap-1 mt-1 text-[11px] font-medium text-emerald-400">
                <Lock className="w-3 h-3" />
                {backupResult.is_encrypted ? "AES-256 (Argon2id)" : "Plaintext"}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
