use super::{CloudConnectionStatus, CloudProvider, CloudProviderType};
use crate::db::{delete_setting, get_setting, set_setting};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::TcpListener;
use std::time::Duration;
use url::Url;

pub const GDRIVE_SETTING_ACCESS_TOKEN: &str = "gdrive_access_token";
pub const GDRIVE_SETTING_REFRESH_TOKEN: &str = "gdrive_refresh_token";
pub const GDRIVE_SETTING_USER_EMAIL: &str = "gdrive_user_email";
pub const GDRIVE_SETTING_CLIENT_ID: &str = "gdrive_client_id";
pub const GDRIVE_SETTING_CLIENT_SECRET: &str = "gdrive_client_secret";

// Public OAuth client identifier for Secure Backup desktop app.
// Users can optionally override this in SQLite app_settings for custom GCP quotas.
pub const DEFAULT_GDRIVE_CLIENT_ID: &str =
    "852174391280-9t7n43f8u8g7q1p9r0m8k3a1v9c4b7x.apps.googleusercontent.com";

const GOOGLE_AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_ENDPOINT: &str = "https://www.googleapis.com/oauth2/v3/userinfo";
const GOOGLE_DRIVE_SCOPE: &str =
    "https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/userinfo.email";

#[derive(Default)]
pub struct GoogleDriveProvider;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    token_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UserInfoResponse {
    email: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

pub fn generate_pkce() -> PkcePair {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let verifier = URL_SAFE_NO_PAD.encode(bytes);

    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    let challenge = URL_SAFE_NO_PAD.encode(hash);

    PkcePair {
        verifier,
        challenge,
    }
}

impl GoogleDriveProvider {
    pub fn get_client_id(conn: &Connection) -> String {
        get_setting(conn, GDRIVE_SETTING_CLIENT_ID)
            .ok()
            .flatten()
            .unwrap_or_else(|| DEFAULT_GDRIVE_CLIENT_ID.to_string())
    }

    pub fn get_client_secret(conn: &Connection) -> Option<String> {
        get_setting(conn, GDRIVE_SETTING_CLIENT_SECRET)
            .ok()
            .flatten()
    }

    /// Starts an OAuth 2.0 PKCE flow by creating a local loopback server,
    /// returning the Google authorization URL and listening port.
    pub fn build_auth_url(
        client_id: &str,
        redirect_uri: &str,
        pkce: &PkcePair,
    ) -> Result<String, String> {
        let mut url = Url::parse(GOOGLE_AUTH_ENDPOINT)
            .map_err(|e| format!("Invalid auth endpoint URL: {}", e))?;

        url.query_pairs_mut()
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", GOOGLE_DRIVE_SCOPE)
            .append_pair("code_challenge", &pkce.challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("access_type", "offline")
            .append_pair("prompt", "consent");

        Ok(url.to_string())
    }

    /// Performs the full loopback authorization flow:
    /// 1. Binds an ephemeral local TCP port on 127.0.0.1.
    /// 2. Builds the Google consent URL with PKCE and the loopback redirect URI.
    /// 3. Opens the URL in the system browser.
    /// 4. Waits for the browser callback, extracts code, and exchanges for tokens.
    pub fn perform_oauth_flow(conn: &mut Connection) -> Result<CloudConnectionStatus, String> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| format!("Failed to bind loopback TCP port: {}", e))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("Failed to read local port: {}", e))?
            .port();

        let redirect_uri = format!("http://127.0.0.1:{}", port);
        let pkce = generate_pkce();
        let client_id = Self::get_client_id(conn);

        let auth_url = Self::build_auth_url(&client_id, &redirect_uri, &pkce)?;

        // Open the browser to Google Login
        if let Err(e) = open::that(&auth_url) {
            eprintln!("Could not automatically open browser: {}", e);
        }

        // Wait for incoming HTTP request (with a 90 second timeout)
        let server = tiny_http::Server::from_listener(listener, None)
            .map_err(|e| format!("Failed to initialize HTTP loopback server: {}", e))?;

        let request = server
            .recv_timeout(Duration::from_secs(90))
            .map_err(|e| format!("HTTP receive error: {}", e))?
            .ok_or_else(|| "OAuth authorization timed out. Please try again.".to_string())?;

        let req_url = format!("http://localhost{}", request.url());
        let parsed_url =
            Url::parse(&req_url).map_err(|e| format!("Failed to parse callback request: {}", e))?;

        let mut auth_code = None;
        let mut error_msg = None;

        for (k, v) in parsed_url.query_pairs() {
            if k == "code" {
                auth_code = Some(v.to_string());
            } else if k == "error" {
                error_msg = Some(v.to_string());
            }
        }

        if let Some(err) = error_msg {
            let response = tiny_http::Response::from_string(format!(
                "<html><body style='font-family: sans-serif; text-align: center; padding: 40px;'>\
                <h2>Google Authorization Failed</h2><p>Error: {}</p>\
                <p>You can close this tab and return to Secure Backup.</p></body></html>",
                err
            ))
            .with_header(
                tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/html"[..]).unwrap(),
            );
            let _ = request.respond(response);
            return Err(format!("Google authorization denied: {}", err));
        }

        let code = auth_code
            .ok_or_else(|| "No authorization code found in callback query.".to_string())?;

        // Respond with a clean success page to the user's browser
        let success_html = "<html><body style='font-family: sans-serif; text-align: center; padding: 50px; background: #0f172a; color: #f8fafc;'>\
            <h2 style='color: #10b981;'>✓ Secure Backup Connected!</h2>\
            <p>Google Drive authorization was successful.</p>\
            <p style='color: #94a3b8;'>You can safely close this browser window and return to the application.</p>\
            </body></html>";

        let response = tiny_http::Response::from_string(success_html).with_header(
            tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/html"[..]).unwrap(),
        );
        let _ = request.respond(response);

        // Exchange the code for tokens
        let client_secret = Self::get_client_secret(conn);
        let tokens = Self::exchange_code_for_tokens(
            &code,
            &redirect_uri,
            &client_id,
            client_secret.as_deref(),
            &pkce.verifier,
        )?;

        // Fetch user email
        let email = Self::fetch_user_email(&tokens.access_token)
            .unwrap_or_else(|_| "Google Drive User".to_string());

        // Save tokens into SQLite app_settings
        set_setting(conn, GDRIVE_SETTING_ACCESS_TOKEN, &tokens.access_token)?;
        if let Some(refresh_token) = tokens.refresh_token {
            set_setting(conn, GDRIVE_SETTING_REFRESH_TOKEN, &refresh_token)?;
        }
        set_setting(conn, GDRIVE_SETTING_USER_EMAIL, &email)?;

        Ok(CloudConnectionStatus {
            provider_type: CloudProviderType::GoogleDrive,
            name: CloudProviderType::GoogleDrive.display_name().to_string(),
            is_connected: true,
            is_supported: true,
            account_email: Some(email),
            storage_used_bytes: None,
            storage_total_bytes: Some(15 * 1024 * 1024 * 1024), // 15 GB free tier baseline
        })
    }

    fn exchange_code_for_tokens(
        code: &str,
        redirect_uri: &str,
        client_id: &str,
        client_secret: Option<&str>,
        code_verifier: &str,
    ) -> Result<TokenResponse, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let mut form_params = vec![
            ("code", code),
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("grant_type", "authorization_code"),
            ("code_verifier", code_verifier),
        ];

        if let Some(sec) = client_secret {
            form_params.push(("client_secret", sec));
        }

        let res = client
            .post(GOOGLE_TOKEN_ENDPOINT)
            .form(&form_params)
            .send()
            .map_err(|e| format!("Network request to Google token endpoint failed: {}", e))?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().unwrap_or_default();
            return Err(format!("Token exchange failed ({}): {}", status, body));
        }

        let token_data: TokenResponse = res
            .json()
            .map_err(|e| format!("Failed to parse Google token JSON: {}", e))?;

        Ok(token_data)
    }

    fn fetch_user_email(access_token: &str) -> Result<String, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("HTTP client init failed: {}", e))?;

        let res = client
            .get(GOOGLE_USERINFO_ENDPOINT)
            .bearer_auth(access_token)
            .send()
            .map_err(|e| format!("Failed to contact Google userinfo: {}", e))?;

        if !res.status().is_success() {
            return Err(format!(
                "Userinfo query failed with status {}",
                res.status()
            ));
        }

        let user_info: UserInfoResponse = res
            .json()
            .map_err(|e| format!("Failed to parse userinfo response: {}", e))?;

        user_info
            .email
            .ok_or_else(|| "No email address found in Google profile".to_string())
    }

    /// Refreshes the Google OAuth access token using the stored refresh_token.
    pub fn refresh_access_token(conn: &Connection) -> Result<String, String> {
        let refresh_token = get_setting(conn, GDRIVE_SETTING_REFRESH_TOKEN)?
            .ok_or_else(|| "No refresh token available to renew session.".to_string())?;

        let client_id = Self::get_client_id(conn);
        let client_secret = Self::get_client_secret(conn);

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let mut form_params = vec![
            ("client_id", client_id.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
        ];

        if let Some(ref sec) = client_secret {
            form_params.push(("client_secret", sec.as_str()));
        }

        let res = client
            .post(GOOGLE_TOKEN_ENDPOINT)
            .form(&form_params)
            .send()
            .map_err(|e| format!("Token refresh network request failed: {}", e))?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().unwrap_or_default();
            return Err(format!("Token refresh rejected ({}): {}", status, body));
        }

        let token_data: TokenResponse = res
            .json()
            .map_err(|e| format!("Failed to parse refreshed token JSON: {}", e))?;

        set_setting(conn, GDRIVE_SETTING_ACCESS_TOKEN, &token_data.access_token)?;

        if let Some(new_rt) = token_data.refresh_token {
            set_setting(conn, GDRIVE_SETTING_REFRESH_TOKEN, &new_rt)?;
        }

        Ok(token_data.access_token)
    }

    /// Retrieves the current access token, or automatically refreshes it using the refresh token.
    pub fn get_valid_access_token(conn: &Connection) -> Result<String, String> {
        if let Some(token) = get_setting(conn, GDRIVE_SETTING_ACCESS_TOKEN)? {
            return Ok(token);
        }

        if get_setting(conn, GDRIVE_SETTING_REFRESH_TOKEN)?.is_some() {
            return Self::refresh_access_token(conn);
        }

        Err("Google Drive is not connected. Please connect in Settings first.".to_string())
    }

    /// Finds an existing folder by name inside a parent folder, or creates it.
    pub fn find_or_create_folder(
        access_token: &str,
        folder_name: &str,
        parent_id: Option<&str>,
    ) -> Result<String, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| format!("HTTP client init failed: {}", e))?;

        // 1. Search for existing folder
        let mut query = format!(
            "name = '{}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false",
            folder_name.replace('\'', "\\'")
        );
        if let Some(pid) = parent_id {
            query.push_str(&format!(" and '{}' in parents", pid));
        }

        let search_res = client
            .get("https://www.googleapis.com/drive/v3/files")
            .bearer_auth(access_token)
            .query(&[("q", &query), ("fields", &"files(id, name)".to_string())])
            .send()
            .map_err(|e| format!("Search request to Drive API failed: {}", e))?;

        if search_res.status().is_success() {
            #[derive(Deserialize)]
            struct FileList {
                files: Vec<DriveFileEntry>,
            }
            #[derive(Deserialize)]
            struct DriveFileEntry {
                id: String,
            }

            if let Ok(list) = search_res.json::<FileList>() {
                if let Some(first) = list.files.first() {
                    return Ok(first.id.clone());
                }
            }
        }

        // 2. Folder does not exist, create it
        #[derive(Serialize)]
        struct CreateFolderReq<'a> {
            name: &'a str,
            #[serde(rename = "mimeType")]
            mime_type: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            parents: Option<Vec<&'a str>>,
        }

        let body = CreateFolderReq {
            name: folder_name,
            mime_type: "application/vnd.google-apps.folder",
            parents: parent_id.map(|p| vec![p]),
        };

        let create_res = client
            .post("https://www.googleapis.com/drive/v3/files")
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .map_err(|e| format!("Create folder request failed: {}", e))?;

        if !create_res.status().is_success() {
            let status = create_res.status();
            let err_body = create_res.text().unwrap_or_default();
            return Err(format!(
                "Failed to create folder '{}': {} - {}",
                folder_name, status, err_body
            ));
        }

        #[derive(Deserialize)]
        struct CreatedItem {
            id: String,
        }

        let created: CreatedItem = create_res
            .json()
            .map_err(|e| format!("Failed to parse created folder response: {}", e))?;

        Ok(created.id)
    }

    /// Uploads a single file using Google Drive REST API v3 Multipart Upload.
    pub fn upload_file_multipart(
        access_token: &str,
        parent_id: &str,
        file_name: &str,
        file_bytes: &[u8],
        mime_type: &str,
    ) -> Result<String, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| format!("HTTP client init failed: {}", e))?;

        let boundary = "-------SecureBackupBoundary123456789";

        #[derive(Serialize)]
        struct MetadataReq<'a> {
            name: &'a str,
            parents: Vec<&'a str>,
        }

        let meta = MetadataReq {
            name: file_name,
            parents: vec![parent_id],
        };
        let meta_json =
            serde_json::to_string(&meta).map_err(|e| format!("Serialization error: {}", e))?;

        let mut body: Vec<u8> = Vec::new();
        // Part 1: Metadata
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(b"Content-Type: application/json; charset=UTF-8\r\n\r\n");
        body.extend_from_slice(meta_json.as_bytes());
        body.extend_from_slice(b"\r\n");

        // Part 2: Media payload
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(format!("Content-Type: {}\r\n\r\n", mime_type).as_bytes());
        body.extend_from_slice(file_bytes);
        body.extend_from_slice(b"\r\n");

        // End boundary
        body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

        let res = client
            .post("https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart")
            .bearer_auth(access_token)
            .header(
                "Content-Type",
                format!("multipart/related; boundary={}", boundary),
            )
            .body(body)
            .send()
            .map_err(|e| format!("Upload request to Drive failed: {}", e))?;

        if !res.status().is_success() {
            let status = res.status();
            let err_body = res.text().unwrap_or_default();
            return Err(format!(
                "Drive file upload failed ({}): {}",
                status, err_body
            ));
        }

        #[derive(Deserialize)]
        struct UploadedFileRes {
            id: String,
        }

        let file_res: UploadedFileRes = res
            .json()
            .map_err(|e| format!("Failed to parse upload response JSON: {}", e))?;

        Ok(file_res.id)
    }
}

impl CloudProvider for GoogleDriveProvider {
    fn provider_type(&self) -> CloudProviderType {
        CloudProviderType::GoogleDrive
    }

    fn get_status(&self, conn: &Connection) -> Result<CloudConnectionStatus, String> {
        let access_token = get_setting(conn, GDRIVE_SETTING_ACCESS_TOKEN)?;
        let email = get_setting(conn, GDRIVE_SETTING_USER_EMAIL)?;

        let is_connected = access_token.is_some();

        Ok(CloudConnectionStatus {
            provider_type: CloudProviderType::GoogleDrive,
            name: CloudProviderType::GoogleDrive.display_name().to_string(),
            is_connected,
            is_supported: true,
            account_email: if is_connected { email } else { None },
            storage_used_bytes: None,
            storage_total_bytes: Some(15 * 1024 * 1024 * 1024),
        })
    }

    fn disconnect(&self, conn: &Connection) -> Result<(), String> {
        delete_setting(conn, GDRIVE_SETTING_ACCESS_TOKEN)?;
        delete_setting(conn, GDRIVE_SETTING_REFRESH_TOKEN)?;
        delete_setting(conn, GDRIVE_SETTING_USER_EMAIL)?;
        Ok(())
    }

    fn upload_snapshot(
        &self,
        conn: &Connection,
        snapshot_id: &str,
    ) -> Result<super::UploadSummary, String> {
        let access_token = Self::get_valid_access_token(conn)?;

        // 1. Locate local snapshot folder
        let snapshot_dir = crate::backup::get_backups_dir().join(snapshot_id);
        if !snapshot_dir.exists() {
            return Err(format!(
                "Snapshot directory does not exist locally: {:?}",
                snapshot_dir
            ));
        }

        // 2. Find or create root vault folder: "Secure Backup Vault"
        let vault_id = Self::find_or_create_folder(&access_token, "Secure Backup Vault", None)?;

        // 3. Find or create snapshot subfolder
        let snapshot_folder_id =
            Self::find_or_create_folder(&access_token, snapshot_id, Some(&vault_id))?;

        // 4. Query files from SQLite for this snapshot
        let file_records = crate::db::get_snapshot_files(conn, snapshot_id)?;
        let mut files_uploaded = 0;
        let mut total_bytes_uploaded = 0u64;

        let data_dir = snapshot_dir.join("data");

        for file in &file_records {
            let file_path = if data_dir.join(&file.stored_filename).exists() {
                data_dir.join(&file.stored_filename)
            } else if snapshot_dir.join(&file.relative_path).exists() {
                snapshot_dir.join(&file.relative_path)
            } else {
                continue;
            };

            let bytes = std::fs::read(&file_path)
                .map_err(|e| format!("Failed to read file {:?}: {}", file_path, e))?;

            let remote_id = Self::upload_file_multipart(
                &access_token,
                &snapshot_folder_id,
                &file.stored_filename,
                &bytes,
                "application/octet-stream",
            )?;

            // Update SQLite ledger immediately
            crate::db::mark_file_synced(conn, snapshot_id, &file.relative_path, &remote_id)?;
            files_uploaded += 1;
            total_bytes_uploaded += bytes.len() as u64;
        }

        // 5. Upload manifest.json
        let manifest_path = snapshot_dir.join("manifest.json");
        if manifest_path.exists() {
            if let Ok(manifest_bytes) = std::fs::read(&manifest_path) {
                let _ = Self::upload_file_multipart(
                    &access_token,
                    &snapshot_folder_id,
                    "manifest.json",
                    &manifest_bytes,
                    "application/json",
                );
            }
        }

        // 6. Mark snapshot as cloud synced in SQLite
        crate::db::mark_snapshot_synced(conn, snapshot_id)?;

        Ok(super::UploadSummary {
            snapshot_id: snapshot_id.to_string(),
            provider: "Google Drive".to_string(),
            files_uploaded,
            total_bytes_uploaded,
            vault_folder_id: vault_id,
            snapshot_folder_id,
        })
    }
}
