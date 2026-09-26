use crate::models::{BackupManifest, DbStats, FileRecord, SnapshotRecord};
use rusqlite::{params, Connection, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub fn get_db_path() -> Result<PathBuf, String> {
    let data_dir = dirs::data_dir()
        .ok_or_else(|| "Could not determine system local data directory".to_string())?;
    let app_dir = data_dir.join("secure-backup");

    if !app_dir.exists() {
        fs::create_dir_all(&app_dir)
            .map_err(|e| format!("Failed to create database directory: {}", e))?;
    }

    Ok(app_dir.join("backup.db"))
}

pub fn get_connection() -> Result<Connection, String> {
    let db_path = get_db_path()?;
    let conn = Connection::open(&db_path)
        .map_err(|e| format!("Failed to open SQLite database at {:?}: {}", db_path, e))?;

    init_db(&conn).map_err(|e| format!("Failed to initialize database schema: {}", e))?;
    Ok(conn)
}

pub fn init_db(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS snapshots (
            id TEXT PRIMARY KEY,
            source_path TEXT NOT NULL,
            source_name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            total_files INTEGER NOT NULL,
            total_size_bytes INTEGER NOT NULL,
            is_encrypted INTEGER NOT NULL,
            encryption_algorithm TEXT,
            salt_hex TEXT,
            status TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_snapshots_created_at ON snapshots(created_at DESC);

        CREATE TABLE IF NOT EXISTS snapshot_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id TEXT NOT NULL,
            relative_path TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            sha256_hash TEXT NOT NULL,
            modified_timestamp INTEGER NOT NULL,
            stored_filename TEXT NOT NULL,
            FOREIGN KEY (snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_snapshot_files_snapshot_id ON snapshot_files(snapshot_id);
        CREATE INDEX IF NOT EXISTS idx_snapshot_files_sha256 ON snapshot_files(sha256_hash);

        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        "#,
    )?;

    Ok(())
}

pub fn insert_snapshot(
    conn: &mut Connection,
    manifest: &BackupManifest,
    status: &str,
) -> Result<(), String> {
    let tx = conn
        .transaction()
        .map_err(|e| format!("Failed to start database transaction: {}", e))?;

    let is_encrypted_int = if manifest.is_encrypted { 1 } else { 0 };
    let created_at_str = manifest.created_at.to_rfc3339();

    tx.execute(
        r#"
        INSERT INTO snapshots (
            id, source_path, source_name, created_at,
            total_files, total_size_bytes, is_encrypted,
            encryption_algorithm, salt_hex, status
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        "#,
        params![
            manifest.id,
            manifest.source_path,
            manifest.source_name,
            created_at_str,
            manifest.total_files as i64,
            manifest.total_size_bytes as i64,
            is_encrypted_int,
            manifest.encryption_algorithm,
            manifest.salt_hex,
            status
        ],
    )
    .map_err(|e| format!("Failed to insert snapshot header: {}", e))?;

    {
        let mut stmt = tx
            .prepare(
                r#"
                INSERT INTO snapshot_files (
                    snapshot_id, relative_path, size_bytes,
                    sha256_hash, modified_timestamp, stored_filename
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                "#,
            )
            .map_err(|e| format!("Failed to prepare file insert statement: {}", e))?;

        for file in &manifest.files {
            let original_name = Path::new(&file.relative_path)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "file".to_string());

            let stored_filename = if manifest.is_encrypted {
                format!("{}.enc", original_name)
            } else {
                original_name
            };

            stmt.execute(params![
                manifest.id,
                file.relative_path,
                file.size_bytes as i64,
                file.sha256_hash,
                file.modified_timestamp as i64,
                stored_filename
            ])
            .map_err(|e| format!("Failed to insert file entry {:?}: {}", file.relative_path, e))?;
        }
    }

    tx.commit()
        .map_err(|e| format!("Failed to commit database transaction: {}", e))?;

    Ok(())
}

pub fn get_snapshots(conn: &Connection) -> Result<Vec<SnapshotRecord>, String> {
    let mut stmt = conn
        .prepare(
            r#"
            SELECT
                id, source_path, source_name, created_at,
                total_files, total_size_bytes, is_encrypted,
                encryption_algorithm, salt_hex, status
            FROM snapshots
            ORDER BY created_at DESC
            "#,
        )
        .map_err(|e| format!("Failed to prepare select query: {}", e))?;

    let rows = stmt
        .query_map([], |row| {
            let is_encrypted_int: i64 = row.get(6)?;
            Ok(SnapshotRecord {
                id: row.get(0)?,
                source_path: row.get(1)?,
                source_name: row.get(2)?,
                created_at: row.get(3)?,
                total_files: row.get::<_, i64>(4)? as usize,
                total_size_bytes: row.get::<_, i64>(5)? as u64,
                is_encrypted: is_encrypted_int != 0,
                encryption_algorithm: row.get(7)?,
                salt_hex: row.get(8)?,
                status: row.get(9)?,
            })
        })
        .map_err(|e| format!("Failed to execute query: {}", e))?;

    let mut snapshots = Vec::new();
    for snapshot in rows {
        snapshots.push(snapshot.map_err(|e| format!("Error reading row: {}", e))?);
    }

    Ok(snapshots)
}

pub fn get_snapshot_files(conn: &Connection, snapshot_id: &str) -> Result<Vec<FileRecord>, String> {
    let mut stmt = conn
        .prepare(
            r#"
            SELECT
                id, snapshot_id, relative_path, size_bytes,
                sha256_hash, modified_timestamp, stored_filename
            FROM snapshot_files
            WHERE snapshot_id = ?1
            ORDER BY relative_path ASC
            "#,
        )
        .map_err(|e| format!("Failed to prepare file query: {}", e))?;

    let rows = stmt
        .query_map(params![snapshot_id], |row| {
            Ok(FileRecord {
                id: Some(row.get(0)?),
                snapshot_id: row.get(1)?,
                relative_path: row.get(2)?,
                size_bytes: row.get::<_, i64>(3)? as u64,
                sha256_hash: row.get(4)?,
                modified_timestamp: row.get::<_, i64>(5)? as u64,
                stored_filename: row.get(6)?,
            })
        })
        .map_err(|e| format!("Failed to query snapshot files: {}", e))?;

    let mut files = Vec::new();
    for file in rows {
        files.push(file.map_err(|e| format!("Error reading file row: {}", e))?);
    }

    Ok(files)
}

pub fn get_db_stats(conn: &Connection) -> Result<DbStats, String> {
    let total_snapshots: i64 = conn
        .query_row("SELECT COUNT(*) FROM snapshots", [], |row| row.get(0))
        .map_err(|e| format!("Failed to count snapshots: {}", e))?;

    let total_files_indexed: i64 = conn
        .query_row("SELECT COUNT(*) FROM snapshot_files", [], |row| row.get(0))
        .map_err(|e| format!("Failed to count indexed files: {}", e))?;

    let total_bytes: Option<i64> = conn
        .query_row(
            "SELECT SUM(total_size_bytes) FROM snapshots WHERE status = 'completed'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| format!("Failed to sum backup bytes: {}", e))?;

    Ok(DbStats {
        total_snapshots: total_snapshots as usize,
        total_files_indexed: total_files_indexed as usize,
        total_bytes_backed_up: total_bytes.unwrap_or(0) as u64,
    })
}

#[cfg(test)]
mod tests;
