import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

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

interface CloudConnectionStatus {
  provider_type: string;
  name: string;
  is_connected: boolean;
  is_supported: boolean;
  account_email?: string;
  storage_used_bytes?: number;
  storage_total_bytes?: number;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
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

window.addEventListener("DOMContentLoaded", () => {
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
      }
    });
  });

  // UI elements
  const btnSelectFolder = document.getElementById("btn-select-folder") as HTMLButtonElement | null;
  const btnClearSelection = document.getElementById("btn-clear-selection") as HTMLButtonElement | null;
  const btnStartBackup = document.getElementById("btn-start-backup") as HTMLButtonElement | null;
  const backupSpinner = document.getElementById("backup-spinner") as HTMLElement | null;
  const folderDisplay = document.getElementById("selected-folder-display") as HTMLElement | null;
  const folderMetaCard = document.getElementById("folder-meta-card") as HTMLElement | null;
  const backupResultBanner = document.getElementById("backup-result-banner") as HTMLElement | null;

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
        <p>No folder selected yet.</p>
        <span>Select a directory to begin.</span>
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
        <div class="placeholder-box">
          <p>No backups recorded yet.</p>
          <p style="font-size: 12px; margin-top: 6px;">Select a folder in Dashboard, enter a passphrase, and click "Start Encrypted Backup".</p>
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
            <div class="history-card-footer" style="display: flex; justify-content: flex-end; margin-top: 6px;">
              <button class="btn btn-secondary btn-sm btn-sync-snapshot" data-snapshot-id="${escapeHtml(m.id)}">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 4px;">
                  <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>
                </svg>
                Sync to Google Drive
              </button>
            </div>
          </div>
        `;
      })
      .join("");

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

  btnSelectFolder?.addEventListener("click", handleSelectFolder);
  btnClearSelection?.addEventListener("click", handleClearSelection);
  btnStartBackup?.addEventListener("click", handleStartBackup);
  btnRefreshHistory?.addEventListener("click", loadBackupHistory);
  btnGeneratePass?.addEventListener("click", handleGeneratePassphrase);
  btnCopyPass?.addEventListener("click", handleCopyPassphrase);
});
