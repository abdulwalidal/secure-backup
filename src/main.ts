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
      btnTogglePass.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
          <line x1="1" y1="1" x2="23" y2="23"/>
        </svg>
      `;
    } else {
      passphraseInput.type = "password";
      btnTogglePass.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
          <circle cx="12" cy="12" r="3"/>
        </svg>
      `;
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
});
