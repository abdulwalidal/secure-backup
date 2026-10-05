import { invoke } from "@tauri-apps/api/core";
import { ask, open } from "@tauri-apps/plugin-dialog";
import { revealItemInDir } from "@tauri-apps/plugin-opener";

interface FolderInfo {
  path: string;
  name: string;
  exists: boolean;
  is_dir: boolean;
  file_count: number;
  total_size_bytes: number;
}

interface FileMetadata {
  relative_path: string;
  absolute_path: string;
  size_bytes: number;
  sha256_hash: string;
  modified_timestamp: number;
}

interface BackupManifest {
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

interface BackupResult {
  backup_id: string;
  manifest: BackupManifest;
  target_directory: string;
  is_encrypted: boolean;
  elapsed_millis: number;
}

interface CommandResult<T> {
  success: boolean;
  data?: T;
  error?: string;
}

interface StorageStats {
  backup_path: string;
  free_space_bytes: number;
  used_space_bytes: number;
}

interface CloudConnectionStatus {
  provider_type: string;
  name: string;
  is_connected: boolean;
  is_supported: boolean;
  account_email?: string;
  storage_used_bytes?: number;
  storage_total_bytes?: number;
}

interface RemoteSnapshotSummary {
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

interface RestoreFileItem {
  relative_path: string;
  status: "restored" | "skipped" | "failed";
  size_bytes: number;
  error?: string;
}

interface RestoreResult {
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

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

async function loadStorageStats(): Promise<void> {
  const backupPathElement = document.getElementById("storage-backup-path");
  const freeSpaceElement = document.getElementById("storage-free-space");
  const usedSpaceElement = document.getElementById("storage-used-space");

  if (!backupPathElement || !freeSpaceElement || !usedSpaceElement) {
    return;
  }

  try {
    const result = await invoke<CommandResult<StorageStats>>("get_storage_stats");

    if (!result.success || !result.data) {
      throw new Error(result.error || "Failed to load storage statistics.");
    }

    backupPathElement.textContent = result.data.backup_path;
    freeSpaceElement.textContent = formatBytes(result.data.free_space_bytes);
    usedSpaceElement.textContent = formatBytes(result.data.used_space_bytes);
  } catch (error) {
    console.error("Failed to load storage statistics:", error);
    backupPathElement.textContent = "Unavailable";
    freeSpaceElement.textContent = "Unavailable";
    usedSpaceElement.textContent = "Unavailable";
  }
}
function formatDate(isoStr: string): string {
  try {
    const d = new Date(isoStr);
    return d.toLocaleString();
  } catch {
    return isoStr;
  }
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

let currentSelectedPath: string | null = null;

function initializeApp() {
  // Navigation handling
  const navItems = document.querySelectorAll<HTMLButtonElement>(".nav-item");
  const tabPanes = document.querySelectorAll<HTMLElement>(".tab-pane");

  navItems.forEach((item) => {
    item.addEventListener("click", () => {
      const tabId = item.getAttribute("data-tab");
      if (!tabId) return;

      navItems.forEach((btn) => btn.classList.remove("active"));
      tabPanes.forEach((pane) => pane.classList.remove("active"));

      item.classList.add("active");
      const targetPane = document.getElementById(`tab-${tabId}`);
      if (targetPane) {
        targetPane.classList.add("active");
      }

      if (tabId === "backups") {
        loadBackupHistory();
      } else if (tabId === "settings") {
        loadCloudProviders();
        loadStorageStats();
      } else if (tabId === "restore") {
        scanCloudSnapshots();
      }
    });
  });

  const btnOpenBackupFolder = document.getElementById(
    "btn-open-backup-folder"
  ) as HTMLButtonElement | null;

  btnOpenBackupFolder?.addEventListener("click", async () => {
    try {
      const result = await invoke<CommandResult<StorageStats>>("get_storage_stats");

      if (!result.success || !result.data) {
        throw new Error(result.error || "Could not get the backup folder path.");
      }

      await revealItemInDir(result.data.backup_path);
    } catch (error) {
      console.error("Failed to open backup folder:", error);
      alert("Could not open the backup folder. Please make sure the folder exists.");
    }
  });
  // UI elements
  const btnSelectFolder = document.getElementById("btn-select-folder") as HTMLButtonElement | null;
  const btnClearSelection = document.getElementById("btn-clear-selection") as HTMLButtonElement | null;
  const btnStartBackup = document.getElementById("btn-start-backup") as HTMLButtonElement | null;
  const backupSpinner = document.getElementById("backup-spinner") as HTMLElement | null;
  const folderDisplay = document.getElementById("selected-folder-display") as HTMLElement | null;
  const folderMetaCard = document.getElementById("folder-meta-card") as HTMLElement | null;
  const backupResultBanner = document.getElementById("backup-result-banner") as HTMLElement | null;

  const btnScanCloud = document.getElementById("btn-scan-cloud") as HTMLButtonElement | null;
  const btnRebuildCatalog = document.getElementById("btn-rebuild-catalog") as HTMLButtonElement | null;
  const drSnapshotsContainer = document.getElementById("dr-snapshots-container") as HTMLElement | null;
  const drStatusMessage = document.getElementById("dr-status-message") as HTMLElement | null;

  const passphraseInput = document.getElementById("backup-passphrase") as HTMLInputElement | null;
  const btnTogglePass = document.getElementById("btn-toggle-pass") as HTMLButtonElement | null;
  const passphraseConfirmInput = document.getElementById("backup-passphrase-confirm") as HTMLInputElement | null;
  const btnToggleConfirmPass = document.getElementById("btn-toggle-confirm-pass") as HTMLButtonElement | null;
  const passphraseStrengthContainer = document.getElementById("passphrase-strength-container") as HTMLElement | null;
  const strengthMeterFill = document.getElementById("strength-meter-fill") as HTMLElement | null;
  const strengthText = document.getElementById("strength-text") as HTMLElement | null;
  const strengthHint = document.getElementById("strength-hint") as HTMLElement | null;
  const passphraseMatchFeedback = document.getElementById("passphrase-match-feedback") as HTMLElement | null;
  const btnGeneratePass = document.getElementById("btn-generate-pass") as HTMLButtonElement | null;
  const btnCopyPass = document.getElementById("btn-copy-pass") as HTMLButtonElement | null;
  const copyTooltip = document.getElementById("copy-tooltip") as HTMLElement | null;

  const metaName = document.getElementById("meta-name") as HTMLElement | null;
  const metaPath = document.getElementById("meta-path") as HTMLElement | null;
  const metaCount = document.getElementById("meta-count") as HTMLElement | null;
  const metaSize = document.getElementById("meta-size") as HTMLElement | null;

  const resultElapsed = document.getElementById("result-elapsed") as HTMLElement | null;
  const resultId = document.getElementById("result-id") as HTMLElement | null;
  const resultSecurity = document.getElementById("result-security") as HTMLElement | null;
  const resultFiles = document.getElementById("result-files") as HTMLElement | null;
  const resultSize = document.getElementById("result-size") as HTMLElement | null;
  const resultLocation = document.getElementById("result-location") as HTMLElement | null;

  const historyContainer = document.getElementById("history-container") as HTMLElement | null;
  const btnRefreshHistory = document.getElementById("btn-refresh-history") as HTMLButtonElement | null;

  // Restore Modal elements
  const restoreModal = document.getElementById("restore-modal") as HTMLElement | null;
  const btnCloseRestoreModal = document.getElementById("btn-close-restore-modal") as HTMLButtonElement | null;
  const btnCancelRestore = document.getElementById("btn-cancel-restore") as HTMLButtonElement | null;
  const btnExecuteRestore = document.getElementById("btn-execute-restore") as HTMLButtonElement | null;
  const btnChooseRestoreDest = document.getElementById("btn-choose-restore-dest") as HTMLButtonElement | null;
  const restoreDestinationDisplay = document.getElementById("restore-destination-display") as HTMLElement | null;
  const restorePassphrase = document.getElementById("restore-passphrase") as HTMLInputElement | null;
  const btnToggleRestorePass = document.getElementById("btn-toggle-restore-pass") as HTMLButtonElement | null;
  const restorePassphraseContainer = document.getElementById("restore-passphrase-container") as HTMLElement | null;
  const modalSnapshotId = document.getElementById("modal-snapshot-id") as HTMLElement | null;
  const modalSnapshotSource = document.getElementById("modal-snapshot-source") as HTMLElement | null;
  const modalSnapshotFiles = document.getElementById("modal-snapshot-files") as HTMLElement | null;
  const modalSnapshotSize = document.getElementById("modal-snapshot-size") as HTMLElement | null;
  const modalSnapshotEnc = document.getElementById("modal-snapshot-enc") as HTMLElement | null;
  const restoreProgressContainer = document.getElementById("restore-progress-container") as HTMLElement | null;
  const restoreProgressBar = document.getElementById("restore-progress-bar") as HTMLElement | null;
  const restoreProgressStatus = document.getElementById("restore-progress-status") as HTMLElement | null;
  const restoreProgressPercent = document.getElementById("restore-progress-percent") as HTMLElement | null;
  const restoreResultReport = document.getElementById("restore-result-report") as HTMLElement | null;

  let activeRestoreSnapshotId: string | null = null;
  let activeRestoreSource: "local" | "google_drive" = "local";
  let activeRestoreDestination: string | null = null;
  let activeRestoreEncrypted: boolean = false;

  // --- Passphrase visibility, generation & clipboard helpers ---

  const EYE_OPEN_SVG = `
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
      <circle cx="12" cy="12" r="3"/>
    </svg>
  `;

  const EYE_OFF_SVG = `
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
      <line x1="1" y1="1" x2="23" y2="23"/>
    </svg>
  `;

  function setPassphraseVisible(visible: boolean) {
    if (!passphraseInput) return;
    passphraseInput.type = visible ? "text" : "password";
    if (btnTogglePass) btnTogglePass.innerHTML = visible ? EYE_OFF_SVG : EYE_OPEN_SVG;
  }

  function setConfirmPassphraseVisible(visible: boolean) {
    if (!passphraseConfirmInput) return;
    passphraseConfirmInput.type = visible ? "text" : "password";
    if (btnToggleConfirmPass) btnToggleConfirmPass.innerHTML = visible ? EYE_OFF_SVG : EYE_OPEN_SVG;
  }

  // Toggle passphrase visibility
  btnTogglePass?.addEventListener("click", () => {
    if (!passphraseInput) return;
    setPassphraseVisible(passphraseInput.type === "password");
  });

  // Toggle confirm passphrase visibility
  btnToggleConfirmPass?.addEventListener("click", () => {
    if (!passphraseConfirmInput) return;
    setConfirmPassphraseVisible(passphraseConfirmInput.type === "password");
  });

  interface PassphraseStrength {
    score: number;
    label: string;
    color: string;
    width: string;
    hint: string;
  }

  function evaluatePassphraseStrength(passphrase: string): PassphraseStrength {
    if (passphrase.length === 0) {
      return {
        score: 0,
        label: "None",
        color: "var(--card-border)",
        width: "0%",
        hint: "Enter at least 8 characters",
      };
    }

    let score = 0;
    if (passphrase.length >= 8) score += 1;
    if (passphrase.length >= 14) score += 1;
    if (passphrase.length >= 24) score += 1;

    const hasLower = /[a-z]/.test(passphrase);
    const hasUpper = /[A-Z]/.test(passphrase);
    const hasNumber = /[0-9]/.test(passphrase);
    const hasSpecial = /[^a-zA-Z0-9]/.test(passphrase);

    const varietyCount = (hasLower ? 1 : 0) + (hasUpper ? 1 : 0) + (hasNumber ? 1 : 0) + (hasSpecial ? 1 : 0);
    if (varietyCount >= 3) score += 1;
    if (varietyCount === 4 && passphrase.length >= 12) score += 1;

    if (score <= 1) {
      return {
        score: 1,
        label: "Weak",
        color: "var(--danger)",
        width: "25%",
        hint: "Use 12+ characters with symbols, uppercase, and numbers",
      };
    } else if (score === 2) {
      return {
        score: 2,
        label: "Fair",
        color: "var(--warning)",
        width: "50%",
        hint: "Add numbers or special characters to increase strength",
      };
    } else if (score === 3) {
      return {
        score: 3,
        label: "Strong",
        color: "var(--accent-color)",
        width: "75%",
        hint: "Great passphrase for AES-256-GCM encryption",
      };
    } else {
      return {
        score: 4,
        label: "Very Strong",
        color: "var(--success)",
        width: "100%",
        hint: "Excellent entropy for zero-knowledge encryption",
      };
    }
  }

  function updatePassphraseStrengthUI() {
    const pass = passphraseInput?.value ?? "";
    if (!passphraseStrengthContainer || !strengthMeterFill || !strengthText || !strengthHint) return;

    if (pass.length === 0) {
      passphraseStrengthContainer.style.display = "none";
    } else {
      passphraseStrengthContainer.style.display = "flex";
      const res = evaluatePassphraseStrength(pass);
      strengthMeterFill.style.width = res.width;
      strengthMeterFill.style.backgroundColor = res.color;
      strengthText.textContent = `Strength: ${res.label}`;
      strengthText.style.color = res.color;
      strengthHint.textContent = res.hint;
    }

    updatePassphraseMatchUI();
  }

  function updatePassphraseMatchUI() {
    if (!passphraseMatchFeedback || !passphraseInput || !passphraseConfirmInput) return;
    const pass = passphraseInput.value;
    const confirm = passphraseConfirmInput.value;

    if (pass.length === 0 && confirm.length === 0) {
      passphraseMatchFeedback.style.display = "none";
      passphraseMatchFeedback.textContent = "";
      passphraseMatchFeedback.className = "passphrase-match-feedback";
      return;
    }

    passphraseMatchFeedback.style.display = "flex";

    if (confirm.length === 0) {
      passphraseMatchFeedback.textContent = "Please confirm your passphrase";
      passphraseMatchFeedback.className = "passphrase-match-feedback mismatched";
    } else if (pass === confirm) {
      passphraseMatchFeedback.innerHTML = `
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <path d="M20 6L9 17l-5-5"/>
        </svg>
        <span>Passphrases match</span>
      `;
      passphraseMatchFeedback.className = "passphrase-match-feedback matched";
    } else {
      passphraseMatchFeedback.innerHTML = `
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <line x1="18" y1="6" x2="6" y2="18"/>
          <line x1="6" y1="6" x2="18" y2="18"/>
        </svg>
        <span>Passphrases do not match</span>
      `;
      passphraseMatchFeedback.className = "passphrase-match-feedback mismatched";
    }
  }

  passphraseInput?.addEventListener("input", updatePassphraseStrengthUI);
  passphraseConfirmInput?.addEventListener("input", updatePassphraseMatchUI);

  const PASSPHRASE_BYTES = 32;

  // Generates a 256-bit high-entropy passphrase as an unpadded base64url string.
  // Uses the platform CSPRNG (Web Crypto); no secret is ever persisted.
  function generateSecurePassphrase(): string {
    const bytes = new Uint8Array(PASSPHRASE_BYTES);
    crypto.getRandomValues(bytes);
    let binary = "";
    for (const byte of bytes) {
      binary += String.fromCharCode(byte);
    }
    return btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  let copyTooltipTimer: number | undefined;

  function showCopyTooltip(message: string, isError = false) {
    if (!copyTooltip) return;
    copyTooltip.textContent = message;
    copyTooltip.classList.toggle("error", isError);
    copyTooltip.classList.add("visible");
    if (copyTooltipTimer !== undefined) window.clearTimeout(copyTooltipTimer);
    copyTooltipTimer = window.setTimeout(() => {
      copyTooltip.classList.remove("visible");
      copyTooltip.classList.remove("error");
      copyTooltip.textContent = "";
    }, 1500);
  }

  async function copyToClipboard(text: string): Promise<boolean> {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch {
      // Clipboard API unavailable or blocked — fall back to the legacy path below.
    }

    try {
      const helper = document.createElement("textarea");
      helper.value = text;
      helper.setAttribute("readonly", "");
      helper.style.position = "fixed";
      helper.style.opacity = "0";
      document.body.appendChild(helper);
      helper.select();
      const succeeded = document.execCommand("copy");
      document.body.removeChild(helper);
      return succeeded;
    } catch {
      return false;
    }
  }

  function handleGeneratePassphrase() {
    if (!passphraseInput) return;
    if (
      passphraseInput.value.length > 0 &&
      !confirm(
        "Replace the current passphrase with a newly generated key? The existing one will be lost."
      )
    ) {
      return;
    }
    const newKey = generateSecurePassphrase();
    passphraseInput.value = newKey;
    if (passphraseConfirmInput) {
      passphraseConfirmInput.value = newKey;
    }
    setPassphraseVisible(true);
    setConfirmPassphraseVisible(true);
    updatePassphraseStrengthUI();
  }

  async function handleCopyPassphrase() {
    const value = passphraseInput?.value.trim() ?? "";
    if (value.length === 0) {
      showCopyTooltip("Nothing to copy", true);
      return;
    }
    const copied = await copyToClipboard(value);
    showCopyTooltip(copied ? "Copied!" : "Copy failed", !copied);
  }

  async function handleSelectFolder() {
    try {
      const selected = await open({
        directory: true,
        multiple: false,
        title: "Select Backup Target Folder",
      });

      if (!selected) return;

      const folderPath = typeof selected === "string" ? selected : selected[0];
      if (!folderPath) return;

      const result = await invoke<CommandResult<FolderInfo>>("inspect_folder", {
        path: folderPath,
      });

      if (result.success && result.data) {
        currentSelectedPath = folderPath;
        renderSelectedFolder(result.data);
      } else {
        alert(result.error || "Failed to inspect selected folder.");
      }
    } catch (err) {
      console.error("Error selecting folder:", err);
      alert("An error occurred while opening the folder picker.");
    }
  }

  function renderSelectedFolder(info: FolderInfo) {
    if (folderDisplay) {
      folderDisplay.className = "folder-selected-state";
      folderDisplay.innerHTML = `
        <span class="folder-selected-label">Selected Target</span>
        <div class="folder-path-display">${escapeHtml(info.path)}</div>
      `;
    }

    if (folderMetaCard) {
      folderMetaCard.style.display = "flex";
      if (metaName) metaName.textContent = info.name;
      if (metaPath) {
        metaPath.textContent = info.path;
        metaPath.title = info.path;
      }
      if (metaCount) metaCount.textContent = `${info.file_count} item(s)`;
      if (metaSize) metaSize.textContent = formatBytes(info.total_size_bytes);
    }

    if (btnClearSelection) {
      btnClearSelection.style.display = "inline-flex";
    }

    if (backupResultBanner) {
      backupResultBanner.style.display = "none";
    }
  }

  function handleClearSelection() {
    currentSelectedPath = null;
    if (folderDisplay) {
      folderDisplay.className = "folder-empty-state";
      folderDisplay.innerHTML = `
        <span class="empty-state-icon" aria-hidden="true">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
            <path d="M12 11v6m-3-3h6"/>
          </svg>
        </span>
        <p class="empty-state-title">Choose a folder to protect</p>
        <span class="empty-state-description">Select a directory to review its contents and prepare an encrypted backup.</span>
      `;
    }
    if (folderMetaCard) {
      folderMetaCard.style.display = "none";
    }
    if (btnClearSelection) {
      btnClearSelection.style.display = "none";
    }
    if (backupResultBanner) {
      backupResultBanner.style.display = "none";
    }
    if (passphraseInput) {
      passphraseInput.value = "";
    }
    if (passphraseConfirmInput) {
      passphraseConfirmInput.value = "";
    }
    updatePassphraseStrengthUI();
  }

  async function handleStartBackup() {
    if (!currentSelectedPath) {
      alert("Please select a target folder first.");
      return;
    }

    const passphrase = passphraseInput?.value.trim() ?? "";
    const passphraseConfirm = passphraseConfirmInput?.value.trim() ?? "";

    if (passphrase.length > 0) {
      if (passphrase !== passphraseConfirm) {
        alert("Passphrases do not match. Please verify your passphrase confirmation before encrypting.");
        passphraseConfirmInput?.focus();
        return;
      }
    } else {
      const confirmPlain = confirm(
        "No passphrase entered. Do you want to proceed with unencrypted backup? (Recommended: enter a passphrase for AES-256-GCM encryption)"
      );
      if (!confirmPlain) return;
    }

    if (btnStartBackup) btnStartBackup.disabled = true;
    if (backupSpinner) backupSpinner.style.display = "inline-block";
    if (backupResultBanner) backupResultBanner.style.display = "none";

    try {
      const res = await invoke<CommandResult<BackupResult>>("start_local_backup", {
        sourcePath: currentSelectedPath,
        passphrase: passphrase || null,
      });

      if (res.success && res.data) {
        const data = res.data;
        if (backupResultBanner) {
          backupResultBanner.style.display = "flex";
          if (resultElapsed) resultElapsed.textContent = `Completed in ${data.elapsed_millis}ms`;
          if (resultId) resultId.textContent = data.backup_id;
          if (resultSecurity) {
            resultSecurity.className = data.is_encrypted ? "badge-enc" : "badge-plain";
            resultSecurity.textContent = data.is_encrypted
              ? "AES-256-GCM (Encrypted)"
              : "Plaintext (Unencrypted)";
          }
          if (resultFiles) resultFiles.textContent = `${data.manifest.total_files} file(s)`;
          if (resultSize) resultSize.textContent = formatBytes(data.manifest.total_size_bytes);
          if (resultLocation) resultLocation.textContent = data.target_directory;
        }
      } else {
        alert(res.error || "Backup failed.");
      }
    } catch (err) {
      console.error("Backup execution error:", err);
      alert("Error occurred during backup execution.");
    } finally {
      if (btnStartBackup) btnStartBackup.disabled = false;
      if (backupSpinner) backupSpinner.style.display = "none";
    }
  }

  async function loadBackupHistory() {
    if (!historyContainer) return;
    historyContainer.innerHTML = '<div class="placeholder-box">Loading backup history...</div>';

    try {
      const res = await invoke<CommandResult<BackupManifest[]>>("get_backup_history");
      if (res.success && res.data) {
        renderHistoryList(res.data);
      } else {
        historyContainer.innerHTML = `<div class="placeholder-box">${escapeHtml(res.error || "Failed to load history.")}</div>`;
      }
    } catch (err) {
      console.error("Error loading backup history:", err);
      historyContainer.innerHTML = '<div class="placeholder-box">Failed to load backup history.</div>';
    }
  }

  function renderHistoryList(manifests: BackupManifest[]) {
    if (!historyContainer) return;

    if (manifests.length === 0) {
      historyContainer.innerHTML = `
        <div class="empty-state">
          <span class="empty-state-icon" aria-hidden="true">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M21 8v13H3V8"/>
              <path d="M1 3h22v5H1zM10 12h4"/>
            </svg>
          </span>
          <h2 class="empty-state-title">No backups yet</h2>
          <p class="empty-state-description">Choose a folder from the Dashboard and create an encrypted backup to start your history.</p>
        </div>
      `;
      return;
    }

    historyContainer.innerHTML = manifests
      .map((m) => {
        const securityBadge = m.is_encrypted
          ? `<span class="badge-enc">AES-256-GCM</span>`
          : `<span class="badge-plain">Plaintext</span>`;

        const fileListHtml = m.files
          .slice(0, 5)
          .map(
            (f) => `
              <div class="history-file-line">
                <span>${escapeHtml(f.relative_path)}${m.is_encrypted ? ".enc" : ""} (${formatBytes(f.size_bytes)})</span>
                <span class="history-file-hash">SHA256: ${escapeHtml(f.sha256_hash.substring(0, 16))}...</span>
              </div>
            `
          )
          .join("");

        const moreFilesCount =
          m.files.length > 5
            ? `<div style="color: var(--text-dim); font-size: 10px;">+ ${m.files.length - 5} more files</div>`
            : "";

        return `
          <div class="history-card">
            <div class="history-card-header">
              <div class="history-title-group">
                <span class="history-source-name">${escapeHtml(m.source_name)}</span>
                ${securityBadge}
                <span class="version-tag">${escapeHtml(m.id)}</span>
              </div>
              <span class="history-date">${escapeHtml(formatDate(m.created_at))}</span>
            </div>
            <div class="history-meta-row">
              <span>Files: <strong>${m.total_files}</strong></span>
              <span>Total Size: <strong>${formatBytes(m.total_size_bytes)}</strong></span>
              <span>Source: <strong class="mono" style="font-size: 11px;">${escapeHtml(m.source_path)}</strong></span>
            </div>
            <div class="history-files-preview">
              ${fileListHtml}
              ${moreFilesCount}
            </div>
            <div class="history-card-footer" style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 6px;">
              <button class="btn btn-primary btn-sm btn-restore-snapshot" data-snapshot-id="${escapeHtml(m.id)}" data-source="local" data-name="${escapeHtml(m.source_name)}" data-path="${escapeHtml(m.source_path)}" data-files="${m.total_files}" data-size="${m.total_size_bytes}" data-encrypted="${m.is_encrypted}">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 4px;">
                  <polyline points="7 10 12 15 17 10"/>
                  <line x1="12" y1="15" x2="12" y2="3"/>
                  <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/>
                </svg>
                Restore
              </button>
              <button class="btn btn-secondary btn-sm btn-sync-snapshot" data-snapshot-id="${escapeHtml(m.id)}">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 4px;">
                  <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>
                </svg>
                Sync to Google Drive
              </button>
              <button class="btn btn-danger btn-sm btn-delete-snapshot" data-snapshot-id="${escapeHtml(m.id)}" data-name="${escapeHtml(m.source_name)}" title="Delete Snapshot">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 4px;">
                  <polyline points="3 6 5 6 21 6"/>
                  <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                  <line x1="10" y1="11" x2="10" y2="17"/>
                  <line x1="14" y1="11" x2="14" y2="17"/>
                </svg>
                Delete
              </button>
            </div>
          </div>
        `;
      })
      .join("");

    // Attach restore button handlers
    historyContainer.querySelectorAll<HTMLButtonElement>(".btn-restore-snapshot").forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = btn.getAttribute("data-snapshot-id") || "";
        const source = "local";
        const name = btn.getAttribute("data-name") || "Backup";
        const path = btn.getAttribute("data-path") || "";
        const files = parseInt(btn.getAttribute("data-files") || "0", 10);
        const size = parseInt(btn.getAttribute("data-size") || "0", 10);
        const isEncrypted = btn.getAttribute("data-encrypted") === "true";
        openRestoreModal(id, source, name, path, files, size, isEncrypted);
      });
    });

    // Attach sync button handlers
    historyContainer.querySelectorAll<HTMLButtonElement>(".btn-sync-snapshot").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const snapshotId = btn.getAttribute("data-snapshot-id");
        if (!snapshotId) return;

        btn.disabled = true;
        btn.textContent = "Uploading to Cloud...";

        try {
          const res = await invoke<CommandResult<any>>("sync_snapshot_to_cloud", {
            snapshotId,
            providerType: "google_drive",
          });

          if (res.success && res.data) {
            btn.textContent = "Cloud Synced";
            btn.style.borderColor = "var(--success-color)";
            btn.style.color = "var(--success-color)";
            alert(`Snapshot '${snapshotId}' uploaded successfully to Google Drive (Vault ID: ${res.data.vault_folder_id})!`);
          } else {
            alert(res.error || "Upload failed. Please ensure Google Drive is connected in Settings.");
            btn.disabled = false;
            btn.textContent = "Sync to Google Drive";
          }
        } catch (err) {
          console.error("Cloud sync error:", err);
          alert("Network or authorization error while uploading to Google Drive.");
          btn.disabled = false;
          btn.textContent = "Sync to Google Drive";
        }
      });
    });

    // Attach delete button handlers
    historyContainer.querySelectorAll<HTMLButtonElement>(".btn-delete-snapshot").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const snapshotId = btn.getAttribute("data-snapshot-id");
        const snapshotName = btn.getAttribute("data-name") || snapshotId || "this backup";
        if (!snapshotId) return;

        const confirmed = await ask(
          `Are you sure you want to permanently delete backup snapshot '${snapshotName}' (${snapshotId})?\n\nThis will remove all local encrypted archive files and cannot be undone.`,
          {
            title: "Delete Backup Snapshot",
            kind: "warning",
          }
        );

        if (!confirmed) return;

        btn.disabled = true;
        btn.textContent = "Deleting...";

        try {
          const res = await invoke<CommandResult<boolean>>("delete_backup_snapshot", {
            snapshotId,
          });

          if (res.success) {
            await loadBackupHistory();
            loadStorageStats();
          } else {
            alert(res.error || "Failed to delete snapshot.");
            btn.disabled = false;
            btn.textContent = "Delete";
          }
        } catch (err) {
          console.error("Delete snapshot error:", err);
          alert("An unexpected error occurred while deleting the snapshot.");
          btn.disabled = false;
          btn.textContent = "Delete";
        }
      });
    });
  }

  // Cloud Providers Handling
  const cloudProvidersList = document.getElementById("cloud-providers-list");

  async function loadCloudProviders() {
    if (!cloudProvidersList) return;
    cloudProvidersList.innerHTML = '<div class="placeholder-box">Loading cloud providers...</div>';

    try {
      const res = await invoke<CommandResult<CloudConnectionStatus[]>>("get_cloud_providers");
      if (res.success && res.data) {
        renderCloudProviders(res.data);
      } else {
        cloudProvidersList.innerHTML = `<div class="placeholder-box">${escapeHtml(res.error || "Failed to load cloud providers.")}</div>`;
      }
    } catch (err) {
      console.error("Error loading cloud providers:", err);
      cloudProvidersList.innerHTML = '<div class="placeholder-box">Failed to load cloud provider status.</div>';
    }
  }

  function renderCloudProviders(providers: CloudConnectionStatus[]) {
    if (!cloudProvidersList) return;

    cloudProvidersList.innerHTML = providers
      .map((p) => {
        let statusBadge = "";
        let actionBtn = "";
        let bodyText = "";

        if (!p.is_supported) {
          statusBadge = `<span class="cloud-status-badge roadmap">Roadmap</span>`;
          bodyText = `<span>Support coming in future milestone.</span>`;
          actionBtn = `<button class="btn btn-secondary btn-sm" disabled style="opacity: 0.5;">Coming Soon</button>`;
        } else if (p.is_connected) {
          statusBadge = `<span class="cloud-status-badge connected">Connected</span>`;
          bodyText = `<div>Connected: <strong class="cloud-account-email">${escapeHtml(p.account_email || "Active")}</strong></div>`;
          actionBtn = `<button class="btn btn-secondary btn-sm btn-disconnect-cloud" data-provider="${escapeHtml(p.provider_type)}">Disconnect</button>`;
        } else {
          statusBadge = `<span class="cloud-status-badge disconnected">Not Connected</span>`;
          bodyText = `<span>Zero-knowledge client-side encrypted sync.</span>`;
          actionBtn = `<button class="btn btn-primary btn-sm btn-connect-cloud" data-provider="${escapeHtml(p.provider_type)}">Connect</button>`;
        }

        const quotaDisplay = p.storage_total_bytes
          ? `<span class="cloud-quota-badge">${formatBytes(p.storage_total_bytes)} Baseline</span>`
          : "";

        return `
          <div class="cloud-card ${!p.is_supported ? "disabled" : ""}">
            <div class="cloud-header">
              <div class="cloud-title-group">
                <span class="cloud-name">${escapeHtml(p.name)}</span>
                ${quotaDisplay}
              </div>
              ${statusBadge}
            </div>
            <div class="cloud-body">
              ${bodyText}
            </div>
            <div class="cloud-actions">
              ${actionBtn}
            </div>
          </div>
        `;
      })
      .join("");

    // Attach button listeners
    cloudProvidersList.querySelectorAll<HTMLButtonElement>(".btn-connect-cloud").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const provider = btn.getAttribute("data-provider");
        if (provider === "google_drive" || provider === "GoogleDrive") {
          btn.disabled = true;
          btn.textContent = "Connecting (Browser)...";
          try {
            const res = await invoke<CommandResult<CloudConnectionStatus>>("connect_google_drive");
            if (res.success && res.data) {
              await loadCloudProviders();
            } else {
              alert(res.error || "Google Drive connection failed.");
              btn.disabled = false;
              btn.textContent = "Connect";
            }
          } catch (e) {
            console.error("Connection error:", e);
            alert("Failed to complete Google Drive authentication.");
            btn.disabled = false;
            btn.textContent = "Connect";
          }
        }
      });
    });

    cloudProvidersList.querySelectorAll<HTMLButtonElement>(".btn-disconnect-cloud").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const provider = btn.getAttribute("data-provider");
        if (!provider) return;

        if (confirm("Disconnect this cloud provider? Uploaded backups on the cloud will not be deleted.")) {
          btn.disabled = true;
          btn.textContent = "Disconnecting...";
          try {
            const res = await invoke<CommandResult<boolean>>("disconnect_cloud_provider", {
              providerType: provider,
            });
            if (res.success) {
              await loadCloudProviders();
            } else {
              alert(res.error || "Failed to disconnect.");
              btn.disabled = false;
              btn.textContent = "Disconnect";
            }
          } catch (e) {
            console.error("Disconnect error:", e);
            btn.disabled = false;
            btn.textContent = "Disconnect";
          }
        }
      });
    });
  }

  // --- Disaster Recovery & Cloud Discovery ---

  function showDrStatus(message: string, type: "info" | "success" | "error") {
    if (!drStatusMessage) return;
    drStatusMessage.className = `dr-status-box ${type}`;
    drStatusMessage.textContent = message;
    drStatusMessage.style.display = "flex";
  }

  function hideDrStatus() {
    if (!drStatusMessage) return;
    drStatusMessage.style.display = "none";
    drStatusMessage.textContent = "";
  }

  async function scanCloudSnapshots() {
    if (!drSnapshotsContainer) return;

    if (btnScanCloud) {
      btnScanCloud.disabled = true;
      btnScanCloud.innerHTML = `
        <svg class="spin" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10" stroke-opacity="0.25"/>
          <path d="M12 2a10 10 0 0 1 10 10"/>
        </svg>
        <span>Scanning...</span>
      `;
    }

    drSnapshotsContainer.innerHTML = `
      <div class="placeholder-box">
        <p>Scanning Google Drive vault for snapshots...</p>
      </div>
    `;

    try {
      const res = await invoke<CommandResult<RemoteSnapshotSummary[]>>("discover_cloud_snapshots", {
        providerType: "google_drive",
      });

      if (!res.success || !res.data) {
        showDrStatus(res.error || "Failed to discover remote snapshots. Ensure Google Drive is connected in Settings.", "error");
        drSnapshotsContainer.innerHTML = `
          <div class="placeholder-box">
            <p>Could not discover remote snapshots: ${escapeHtml(res.error || "Unknown error")}</p>
          </div>
        `;
        return;
      }

      const snapshots = res.data;
      if (snapshots.length === 0) {
        hideDrStatus();
        drSnapshotsContainer.innerHTML = `
          <div class="empty-state">
            <span class="empty-state-icon" aria-hidden="true">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                <path d="M20 16.2A4.5 4.5 0 0 0 18 7.5a6 6 0 0 0-11.7 1.8A4 4 0 0 0 7 17h2"/>
                <path d="M12 12v9m-3-3 3 3 3-3"/>
              </svg>
            </span>
            <h3 class="empty-state-title">No cloud snapshots found</h3>
            <p class="empty-state-description">Once you sync a local backup to Google Drive, scan again to discover it here.</p>
          </div>
        `;
        return;
      }

      const missingCount = snapshots.filter((s) => !s.is_imported).length;
      if (missingCount > 0) {
        showDrStatus(`Discovered ${snapshots.length} remote snapshot(s). ${missingCount} snapshot(s) are missing from your local catalog. Click "Rebuild Local Catalog" to import them.`, "info");
      } else {
        showDrStatus(`All ${snapshots.length} remote snapshot(s) are recorded in your local catalog.`, "success");
      }

      drSnapshotsContainer.innerHTML = snapshots
        .map((snap) => {
          const encBadge = snap.is_encrypted
            ? `<span class="badge-enc">${escapeHtml(snap.encryption_algorithm || "AES-256-GCM")}</span>`
            : `<span class="badge-plain">Plain</span>`;

          const importedBadge = snap.is_imported
            ? `<span class="cloud-status-badge connected">Cataloged</span>`
            : `<span class="cloud-status-badge roadmap">Cloud Only</span>`;

          return `
            <div class="dr-snapshot-card">
              <div class="dr-snapshot-header">
                <div class="dr-snapshot-title-group">
                  <span class="dr-snapshot-source-name">${escapeHtml(snap.source_name)}</span>
                  <div class="dr-snapshot-badges">
                    ${encBadge}
                    ${importedBadge}
                  </div>
                </div>
                <span class="dr-snapshot-id mono">${escapeHtml(snap.snapshot_id)}</span>
              </div>
              <div class="dr-snapshot-meta">
                <span>Created: <strong>${formatDate(snap.created_at)}</strong></span>
                <span>Files: <strong>${snap.total_files}</strong></span>
                <span>Total Size: <strong>${formatBytes(snap.total_size_bytes)}</strong></span>
                <span>Destination: <strong>${escapeHtml(snap.provider)}</strong></span>
              </div>
              <div class="dr-snapshot-footer" style="display: flex; justify-content: flex-end; margin-top: 8px;">
                <button class="btn btn-primary btn-sm btn-restore-cloud-snapshot" data-snapshot-id="${escapeHtml(snap.snapshot_id)}" data-source="google_drive" data-name="${escapeHtml(snap.source_name)}" data-path="Google Drive Vault" data-files="${snap.total_files}" data-size="${snap.total_size_bytes}" data-encrypted="${snap.is_encrypted}">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 4px;">
                    <polyline points="7 10 12 15 17 10"/>
                    <line x1="12" y1="15" x2="12" y2="3"/>
                    <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/>
                  </svg>
                  Restore from Cloud
                </button>
              </div>
            </div>
          `;
        })
        .join("");

      // Attach DR restore handlers
      drSnapshotsContainer.querySelectorAll<HTMLButtonElement>(".btn-restore-cloud-snapshot").forEach((btn) => {
        btn.addEventListener("click", () => {
          const id = btn.getAttribute("data-snapshot-id") || "";
          const source = "google_drive";
          const name = btn.getAttribute("data-name") || "Cloud Backup";
          const path = btn.getAttribute("data-path") || "Google Drive Vault";
          const files = parseInt(btn.getAttribute("data-files") || "0", 10);
          const size = parseInt(btn.getAttribute("data-size") || "0", 10);
          const isEncrypted = btn.getAttribute("data-encrypted") === "true";
          openRestoreModal(id, source, name, path, files, size, isEncrypted);
        });
      });
    } catch (e) {
      console.error("Cloud discovery error:", e);
      showDrStatus("An error occurred while querying remote cloud snapshots.", "error");
      drSnapshotsContainer.innerHTML = `
        <div class="placeholder-box">
          <p>Failed to query cloud storage. Check connection settings.</p>
        </div>
      `;
    } finally {
      if (btnScanCloud) {
        btnScanCloud.disabled = false;
        btnScanCloud.innerHTML = `
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="7 10 12 15 17 10"/>
            <line x1="12" y1="15" x2="12" y2="3"/>
          </svg>
          <span>Scan Cloud</span>
        `;
      }
    }
  }

  async function handleRebuildCatalog() {
    if (!btnRebuildCatalog) return;

    btnRebuildCatalog.disabled = true;
    btnRebuildCatalog.innerHTML = `
      <svg class="spin" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10" stroke-opacity="0.25"/>
        <path d="M12 2a10 10 0 0 1 10 10"/>
      </svg>
      <span>Rebuilding Catalog...</span>
    `;

    try {
      const res = await invoke<CommandResult<number>>("rebuild_database_from_cloud", {
        providerType: "google_drive",
      });

      if (res.success) {
        const count = res.data ?? 0;
        showDrStatus(`Successfully recovered local catalog! Imported ${count} snapshot(s) from Google Drive.`, "success");
        await scanCloudSnapshots();
        loadBackupHistory();
      } else {
        showDrStatus(res.error || "Failed to rebuild database catalog from cloud.", "error");
      }
    } catch (e) {
      console.error("Rebuild catalog error:", e);
      showDrStatus("Unexpected error while rebuilding database catalog.", "error");
    } finally {
      btnRebuildCatalog.disabled = false;
      btnRebuildCatalog.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="23 4 23 10 17 10"/>
          <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
        </svg>
        <span>Rebuild Local Catalog</span>
      `;
    }
  }

  // --- Restore Modal Controller ---

  function openRestoreModal(
    snapshotId: string,
    source: "local" | "google_drive",
    name: string,
    path: string,
    files: number,
    size: number,
    isEncrypted: boolean
  ) {
    activeRestoreSnapshotId = snapshotId;
    activeRestoreSource = source;
    activeRestoreDestination = null;
    activeRestoreEncrypted = isEncrypted;

    if (modalSnapshotId) modalSnapshotId.textContent = snapshotId;
    if (modalSnapshotSource) modalSnapshotSource.textContent = `${name} (${path})`;
    if (modalSnapshotFiles) modalSnapshotFiles.textContent = `${files} file(s)`;
    if (modalSnapshotSize) modalSnapshotSize.textContent = formatBytes(size);
    if (modalSnapshotEnc) {
      modalSnapshotEnc.textContent = isEncrypted ? "AES-256-GCM" : "Plaintext";
      modalSnapshotEnc.className = isEncrypted ? "badge-enc" : "badge-plain";
    }

    if (restoreDestinationDisplay) {
      restoreDestinationDisplay.textContent = "No destination folder selected";
      restoreDestinationDisplay.style.color = "var(--text-muted)";
    }
    if (restorePassphrase) restorePassphrase.value = "";
    if (restorePassphraseContainer) {
      restorePassphraseContainer.style.display = isEncrypted ? "block" : "none";
    }
    if (restoreProgressContainer) restoreProgressContainer.style.display = "none";
    if (restoreResultReport) {
      restoreResultReport.style.display = "none";
      restoreResultReport.innerHTML = "";
    }
    if (btnExecuteRestore) {
      btnExecuteRestore.disabled = false;
      btnExecuteRestore.innerHTML = `
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="7 10 12 15 17 10"/>
          <line x1="12" y1="15" x2="12" y2="3"/>
          <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/>
        </svg>
        <span>Start Restoration</span>
      `;
    }

    if (restoreModal) restoreModal.style.display = "flex";
  }

  function closeRestoreModal() {
    if (restoreModal) restoreModal.style.display = "none";
    activeRestoreSnapshotId = null;
    activeRestoreDestination = null;
  }

  btnCloseRestoreModal?.addEventListener("click", closeRestoreModal);
  btnCancelRestore?.addEventListener("click", closeRestoreModal);

  btnToggleRestorePass?.addEventListener("click", () => {
    if (!restorePassphrase) return;
    const isPass = restorePassphrase.type === "password";
    restorePassphrase.type = isPass ? "text" : "password";
    btnToggleRestorePass.innerHTML = isPass ? EYE_OFF_SVG : EYE_OPEN_SVG;
  });

  btnChooseRestoreDest?.addEventListener("click", async () => {
    try {
      const selected = await open({
        directory: true,
        multiple: false,
        title: "Select Restore Destination Directory",
      });
      if (typeof selected === "string" && selected) {
        activeRestoreDestination = selected;
        if (restoreDestinationDisplay) {
          restoreDestinationDisplay.textContent = selected;
          restoreDestinationDisplay.style.color = "var(--text-main)";
        }
      }
    } catch (e) {
      console.error("Failed to select restore folder:", e);
    }
  });

  btnExecuteRestore?.addEventListener("click", async () => {
    if (!activeRestoreSnapshotId) {
      alert("No snapshot selected.");
      return;
    }
    if (!activeRestoreDestination) {
      alert("Please select a destination directory for restoration.");
      return;
    }

    const passphrase = restorePassphrase?.value.trim() || null;
    if (activeRestoreEncrypted && !passphrase) {
      alert("Please enter the decryption passphrase for this encrypted snapshot.");
      return;
    }

    const conflictPolicyEl = document.querySelector<HTMLInputElement>(
      'input[name="conflict-policy"]:checked'
    );
    const conflictPolicy = conflictPolicyEl?.value || "skip";

    if (btnExecuteRestore) {
      btnExecuteRestore.disabled = true;
      btnExecuteRestore.innerHTML = `
        <svg class="spin" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10" stroke-opacity="0.25"/>
          <path d="M12 2a10 10 0 0 1 10 10"/>
        </svg>
        <span>Restoring...</span>
      `;
    }

    if (restoreProgressContainer) restoreProgressContainer.style.display = "block";
    if (restoreProgressBar) restoreProgressBar.style.width = "40%";
    if (restoreProgressStatus) {
      restoreProgressStatus.textContent =
        activeRestoreSource === "google_drive"
          ? "Downloading encrypted objects from Google Drive..."
          : "Reading archive and verifying cryptographic integrity...";
    }
    if (restoreProgressPercent) restoreProgressPercent.textContent = "40%";

    try {
      const res = await invoke<CommandResult<RestoreResult>>("restore_snapshot", {
        snapshotId: activeRestoreSnapshotId,
        destinationDir: activeRestoreDestination,
        passphrase,
        conflictPolicy,
        sourceType: activeRestoreSource,
      });

      if (restoreProgressBar) restoreProgressBar.style.width = "100%";
      if (restoreProgressPercent) restoreProgressPercent.textContent = "100%";

      if (res.success && res.data) {
        const d = res.data;
        if (restoreProgressStatus) restoreProgressStatus.textContent = "Restoration Complete";

        let errorDetails = "";
        if (d.files_failed > 0) {
          const failedItems = d.items
            .filter((i) => i.status === "failed")
            .map(
              (i) =>
                `<li><strong>${escapeHtml(i.relative_path)}:</strong> ${escapeHtml(i.error || "Unknown error")}</li>`
            )
            .join("");
          errorDetails = `<ul style="margin-top: 8px; padding-left: 20px; font-size: 11px;">${failedItems}</ul>`;
        }

        if (restoreResultReport) {
          restoreResultReport.style.display = "block";
          restoreResultReport.className =
            d.files_failed === 0 ? "restore-result-box success" : "restore-result-box error";
          restoreResultReport.innerHTML = `
            <div><strong>${d.files_failed === 0 ? "Success!" : "Restored with issues"}</strong> Snapshot restoration completed in ${d.elapsed_millis}ms.</div>
            <div style="margin-top: 6px; font-size: 12px;">
              <span>Restored: <strong>${d.files_restored}</strong></span> |
              <span>Skipped: <strong>${d.files_skipped}</strong></span> |
              <span>Failed: <strong>${d.files_failed}</strong></span> |
              <span>Total Restored: <strong>${formatBytes(d.total_bytes_restored)}</strong></span>
            </div>
            ${errorDetails}
          `;
        }
      } else {
        if (restoreProgressStatus) restoreProgressStatus.textContent = "Restoration Failed";
        if (restoreResultReport) {
          restoreResultReport.style.display = "block";
          restoreResultReport.className = "restore-result-box error";
          restoreResultReport.innerHTML = `<div><strong>Restoration Failed:</strong> ${escapeHtml(res.error || "Unknown error occurred.")}</div>`;
        }
      }
    } catch (err: any) {
      console.error("Restore error:", err);
      if (restoreProgressStatus) restoreProgressStatus.textContent = "Restoration Error";
      if (restoreResultReport) {
        restoreResultReport.style.display = "block";
        restoreResultReport.className = "restore-result-box error";
        restoreResultReport.innerHTML = `<div><strong>Unexpected Error:</strong> ${escapeHtml(String(err))}</div>`;
      }
    } finally {
      if (btnExecuteRestore) {
        btnExecuteRestore.disabled = false;
        btnExecuteRestore.innerHTML = `
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="7 10 12 15 17 10"/>
            <line x1="12" y1="15" x2="12" y2="3"/>
            <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/>
          </svg>
          <span>Done</span>
        `;
      }
    }
  });

  btnSelectFolder?.addEventListener("click", handleSelectFolder);
  btnClearSelection?.addEventListener("click", handleClearSelection);
  btnStartBackup?.addEventListener("click", handleStartBackup);
  btnRefreshHistory?.addEventListener("click", loadBackupHistory);
  btnGeneratePass?.addEventListener("click", handleGeneratePassphrase);
  btnCopyPass?.addEventListener("click", handleCopyPassphrase);
  btnScanCloud?.addEventListener("click", scanCloudSnapshots);
  btnRebuildCatalog?.addEventListener("click", handleRebuildCatalog);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initializeApp, { once: true });
} else {
  initializeApp();
}

