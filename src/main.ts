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

  // Toggle passphrase visibility
  btnTogglePass?.addEventListener("click", () => {
    if (!passphraseInput) return;
    if (passphraseInput.type === "password") {
      passphraseInput.type = "text";
      btnTogglePass.textContent = "🙈";
    } else {
      passphraseInput.type = "password";
      btnTogglePass.textContent = "👁️";
    }
  });

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
  }

  async function handleStartBackup() {
    if (!currentSelectedPath) {
      alert("Please select a target folder first.");
      return;
    }

    const passphrase = passphraseInput?.value.trim();
    if (!passphrase) {
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
          ? `<span class="badge-enc">🔒 AES-256-GCM</span>`
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
          </div>
        `;
      })
      .join("");
  }

  btnSelectFolder?.addEventListener("click", handleSelectFolder);
  btnClearSelection?.addEventListener("click", handleClearSelection);
  btnStartBackup?.addEventListener("click", handleStartBackup);
  btnRefreshHistory?.addEventListener("click", loadBackupHistory);
});
