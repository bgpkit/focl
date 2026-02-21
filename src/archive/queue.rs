use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection};

#[derive(Debug, Clone)]
pub struct ReplicationQueue {
    db_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ReplicationJob {
    pub id: i64,
    pub segment_path: PathBuf,
    pub manifest_path: PathBuf,
    pub destination_key: String,
    pub attempts: u32,
    pub max_retries: u32,
}

impl ReplicationQueue {
    pub fn new(root: &Path) -> Result<Self> {
        let db_path = root.join(".replication").join("queue.sqlite");
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed creating replication dir {}", parent.display()))?;
        }

        let queue = Self { db_path };
        queue.init()?;
        Ok(queue)
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    fn open(&self) -> Result<Connection> {
        let conn = Connection::open(&self.db_path)
            .with_context(|| format!("failed opening queue db {}", self.db_path.display()))?;
        Ok(conn)
    }

    fn init(&self) -> Result<()> {
        let conn = self.open()?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS replication_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                segment_path TEXT NOT NULL,
                manifest_path TEXT NOT NULL,
                destination_key TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                max_retries INTEGER NOT NULL DEFAULT 0,
                next_retry_ts INTEGER NOT NULL,
                status TEXT NOT NULL,
                last_error TEXT,
                created_ts INTEGER NOT NULL,
                updated_ts INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_replication_queue_ready
            ON replication_queue(status, next_retry_ts);
            ",
        )?;
        Ok(())
    }

    pub fn enqueue(
        &self,
        segment_path: &Path,
        manifest_path: &Path,
        destination_key: &str,
        max_retries: u32,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        let conn = self.open()?;
        conn.execute(
            "
            INSERT INTO replication_queue (
                segment_path, manifest_path, destination_key, attempts, max_retries,
                next_retry_ts, status, created_ts, updated_ts
            ) VALUES (?, ?, ?, 0, ?, ?, 'pending', ?, ?)
            ",
            params![
                segment_path.display().to_string(),
                manifest_path.display().to_string(),
                destination_key,
                max_retries,
                now,
                now,
                now
            ],
        )?;
        Ok(())
    }

    pub fn claim_ready(&self, limit: usize) -> Result<Vec<ReplicationJob>> {
        let now = Utc::now().timestamp();
        let conn = self.open()?;
        let tx = conn.unchecked_transaction()?;

        let jobs: Vec<ReplicationJob> = {
            let mut stmt = tx.prepare(
                "
                SELECT id, segment_path, manifest_path, destination_key, attempts, max_retries
                FROM replication_queue
                WHERE status = 'pending' AND next_retry_ts <= ?
                ORDER BY id ASC
                LIMIT ?
                ",
            )?;

            let rows = stmt.query_map(params![now, limit as i64], |row| {
                Ok(ReplicationJob {
                    id: row.get(0)?,
                    segment_path: PathBuf::from(row.get::<_, String>(1)?),
                    manifest_path: PathBuf::from(row.get::<_, String>(2)?),
                    destination_key: row.get(3)?,
                    attempts: row.get::<_, u32>(4)?,
                    max_retries: row.get::<_, u32>(5)?,
                })
            })?;

            rows.collect::<Result<Vec<_>, _>>()?
        };

        for job in &jobs {
            tx.execute(
                "UPDATE replication_queue SET status = 'in_progress', updated_ts = ? WHERE id = ?",
                params![now, job.id],
            )?;
        }

        tx.commit()?;
        Ok(jobs)
    }

    pub fn mark_success(&self, job_id: i64) -> Result<()> {
        let conn = self.open()?;
        conn.execute(
            "DELETE FROM replication_queue WHERE id = ?",
            params![job_id],
        )?;
        Ok(())
    }

    pub fn mark_failed(
        &self,
        job: &ReplicationJob,
        error: &str,
        retry_backoff_secs: u64,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        let conn = self.open()?;
        let next_attempt = job.attempts.saturating_add(1);

        let exhausted = job.max_retries > 0 && next_attempt >= job.max_retries;
        if exhausted {
            conn.execute(
                "
                UPDATE replication_queue
                SET attempts = ?, status = 'failed', last_error = ?, updated_ts = ?
                WHERE id = ?
                ",
                params![next_attempt, error, now, job.id],
            )?;
        } else {
            let next_retry = now + retry_backoff_secs as i64;
            conn.execute(
                "
                UPDATE replication_queue
                SET attempts = ?, status = 'pending', next_retry_ts = ?, last_error = ?, updated_ts = ?
                WHERE id = ?
                ",
                params![next_attempt, next_retry, error, now, job.id],
            )?;
        }

        Ok(())
    }

    pub fn pending_count(&self) -> Result<usize> {
        let conn = self.open()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM replication_queue WHERE status IN ('pending', 'in_progress')",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    pub fn failed_count(&self) -> Result<usize> {
        let conn = self.open()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM replication_queue WHERE status = 'failed'",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    pub fn retry_failed(&self) -> Result<usize> {
        let now = Utc::now().timestamp();
        let conn = self.open()?;
        let updated = conn.execute(
            "
            UPDATE replication_queue
            SET status = 'pending', next_retry_ts = ?, updated_ts = ?
            WHERE status = 'failed'
            ",
            params![now, now],
        )?;
        Ok(updated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_persists_jobs() {
        let tmp = tempfile::tempdir().unwrap();
        let queue = ReplicationQueue::new(tmp.path()).unwrap();

        queue
            .enqueue(
                Path::new("/tmp/segment.gz"),
                Path::new("/tmp/segment.gz.json"),
                "local:/tmp/archive",
                0,
            )
            .unwrap();

        assert_eq!(queue.pending_count().unwrap(), 1);

        let jobs = queue.claim_ready(10).unwrap();
        assert_eq!(jobs.len(), 1);

        queue.mark_success(jobs[0].id).unwrap();
        assert_eq!(queue.pending_count().unwrap(), 0);
    }
}
