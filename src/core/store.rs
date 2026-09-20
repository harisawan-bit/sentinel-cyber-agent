// src/core/store.rs - Findings database
use super::orchestrator::Finding;
use anyhow::Result;
use rusqlite::{Connection, params};
use std::path::Path;

pub struct FindingsStore {
    conn: Connection,
}

impl FindingsStore {
    pub fn new(data_dir: &Path) -> Result<Self> {
        let db_path = data_dir.join("findings.db");
        let conn = Connection::open(db_path)?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                tool TEXT NOT NULL,
                finding_type TEXT NOT NULL,
                value TEXT NOT NULL,
                target TEXT NOT NULL,
                severity TEXT NOT NULL,
                detail TEXT,
                metadata TEXT,
                timestamp TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_severity ON findings(severity)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_target ON findings(target)",
            [],
        )?;

        Ok(Self { conn })
    }

    pub fn insert(&self, finding: &Finding) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO findings (id, tool, finding_type, value, target, severity, detail, metadata, timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                finding.id.clone(),
                finding.tool.clone(),
                finding.finding_type.clone(),
                finding.value.clone(),
                finding.target.clone(),
                finding.severity.clone(),
                finding.detail.clone(),
                finding.metadata.as_ref().map(|m| m.to_string()),
                finding.timestamp.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn list(&self, severity: Option<&str>, limit: usize) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let query: String;
        let params: Vec<Box<dyn rusqlite::ToSql>>;

        if let Some(sev) = severity {
            query = "SELECT id, tool, finding_type, value, target, severity, detail, metadata, timestamp FROM findings WHERE severity = ?1 ORDER BY created_at DESC LIMIT ?2".to_string();
            params = vec![Box::new(sev.to_string()), Box::new(limit as i64)];
        } else {
            query = "SELECT id, tool, finding_type, value, target, severity, detail, metadata, timestamp FROM findings ORDER BY created_at DESC LIMIT ?1".to_string();
            params = vec![Box::new(limit as i64)];
        }

        let mut stmt = self.conn.prepare(&query)?;
        let refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let rows = stmt.query_map(refs.as_slice(), |row| {
            Ok(Finding {
                id: row.get(0)?,
                tool: row.get(1)?,
                finding_type: row.get(2)?,
                value: row.get(3)?,
                target: row.get(4)?,
                severity: row.get(5)?,
                detail: row.get(6)?,
                metadata: row
                    .get(7)
                    .ok()
                    .and_then(|s: String| serde_json::from_str(&s).ok()),
                timestamp: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .unwrap_or_default()
                    .with_timezone(&chrono::Utc),
            })
        })?;

        for row in rows {
            findings.push(row?);
        }

        Ok(findings)
    }

    pub fn get_by_id(&self, id: &str) -> Result<Option<Finding>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, tool, finding_type, value, target, severity, detail, metadata, timestamp FROM findings WHERE id = ?1"
        )?;

        let result = stmt.query_row([id], |row| {
            Ok(Finding {
                id: row.get(0)?,
                tool: row.get(1)?,
                finding_type: row.get(2)?,
                value: row.get(3)?,
                target: row.get(4)?,
                severity: row.get(5)?,
                detail: row.get(6)?,
                metadata: row
                    .get(7)
                    .ok()
                    .and_then(|s: String| serde_json::from_str(&s).ok()),
                timestamp: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .unwrap_or_default()
                    .with_timezone(&chrono::Utc),
            })
        });

        match result {
            Ok(f) => Ok(Some(f)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn count(&self) -> Result<i64> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM findings", [], |row| row.get(0))?;
        Ok(count)
    }

    pub fn delete(&self, id: &str) -> Result<bool> {
        let affected = self
            .conn
            .execute("DELETE FROM findings WHERE id = ?1", [id])?;
        Ok(affected > 0)
    }

    pub fn clear(&self) -> Result<usize> {
        let affected = self.conn.execute("DELETE FROM findings", [])?;
        Ok(affected)
    }
}
