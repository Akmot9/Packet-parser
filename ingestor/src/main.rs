use anyhow::{Context, Result};
use glob::glob;
use serde::Deserialize;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

use tokio_postgres::{Client, NoTls};

#[derive(Debug, Deserialize)]
struct JsonlEvent {
    ts: u64,
    run_id: String,
    crate_version: String,
    pcap: String,
    idx: u64,
    len: u32,
    hash: String,
    ok: bool,
    duration_ns: u64,

    // optionnels (feature parse_timing)
    l2_ns: Option<u64>,
    l3_ns: Option<u64>,
    l4_ns: Option<u64>,
    l7_ns: Option<u64>,
    parse_total_ns: Option<u64>,

    error: Option<String>,
}

#[derive(Debug)]
struct FileState {
    offset_bytes: u64,
    // on pourrait stocker inode/mtime si besoin; MVP: offset + reset si truncate
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn env_string(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

async fn connect_pg() -> Result<Client> {
    let host = env_string("PG_HOST", "localhost");
    let port = env_string("PG_PORT", "5432");
    let db = env_string("PG_DB", "benchdb");
    let user = env_string("PG_USER", "bench");
    let password = env_string("PG_PASSWORD", "benchpass");

    let conn_str = format!(
        "host={} port={} dbname={} user={} password={}",
        host, port, db, user, password
    );

    let (client, connection) = tokio_postgres::connect(&conn_str, NoTls)
        .await
        .context("pg connect failed")?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("pg connection error: {e}");
        }
    });

    Ok(client)
}

async fn ensure_schema(client: &Client) -> Result<()> {
    let sql = r#"
CREATE TABLE IF NOT EXISTS packet_parse_events (
  id              BIGSERIAL PRIMARY KEY,
  ts_ms           BIGINT NOT NULL,
  run_id          TEXT NOT NULL,
  crate_version   TEXT NOT NULL,
  pcap            TEXT NOT NULL,
  idx             BIGINT NOT NULL,
  len             INT NOT NULL,
  hash            TEXT NOT NULL,
  ok              BOOLEAN NOT NULL,
  duration_ns     BIGINT NOT NULL,
  l2_ns           BIGINT,
  l3_ns           BIGINT,
  l4_ns           BIGINT,
  l7_ns           BIGINT,
  parse_total_ns  BIGINT,
  error           TEXT,
  inserted_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_packet_event
  ON packet_parse_events (run_id, pcap, idx);

CREATE INDEX IF NOT EXISTS ix_by_hash ON packet_parse_events (hash);
CREATE INDEX IF NOT EXISTS ix_by_version ON packet_parse_events (crate_version);
CREATE INDEX IF NOT EXISTS ix_by_pcap ON packet_parse_events (pcap);
CREATE INDEX IF NOT EXISTS ix_by_ts ON packet_parse_events (ts_ms);
"#;

    client.batch_execute(sql).await.context("ensure schema failed")?;
    Ok(())
}

async fn insert_batch(client: &Client, batch: &[JsonlEvent]) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }

    // Prépare une seule fois par appel (MVP). Optimisation plus tard: préparer une fois au démarrage.
    let stmt = client
        .prepare(
            r#"
INSERT INTO packet_parse_events (
  ts_ms, run_id, crate_version, pcap, idx, len, hash, ok, duration_ns,
  l2_ns, l3_ns, l4_ns, l7_ns, parse_total_ns, error
) VALUES (
  $1,$2,$3,$4,$5,$6,$7,$8,$9,
  $10,$11,$12,$13,$14,$15
)
ON CONFLICT (run_id, pcap, idx) DO NOTHING
"#,
        )
        .await?;

    for e in batch {
        client
            .execute(
                &stmt,
                &[
                    &(e.ts as i64),
                    &e.run_id,
                    &e.crate_version,
                    &e.pcap,
                    &(e.idx as i64),
                    &(e.len as i32),
                    &e.hash,
                    &e.ok,
                    &(e.duration_ns as i64),
                    &e.l2_ns.map(|v| v as i64),
                    &e.l3_ns.map(|v| v as i64),
                    &e.l4_ns.map(|v| v as i64),
                    &e.l7_ns.map(|v| v as i64),
                    &e.parse_total_ns.map(|v| v as i64),
                    &e.error,
                ],
            )
            .await?;
    }

    Ok(())
}


fn list_jsonl_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let pattern = dir.join("*.jsonl");
    let pattern = pattern.to_string_lossy().to_string();

    let mut out = Vec::new();
    for entry in glob(&pattern).context("glob failed")? {
        if let Ok(path) = entry {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn file_len(path: &Path) -> Result<u64> {
    Ok(std::fs::metadata(path)?.len())
}

/// Lit toutes les nouvelles lignes depuis `offset_bytes` jusqu'à EOF.
/// Retourne le nouvel offset et les events parsés.
fn read_new_lines(path: &Path, offset_bytes: u64) -> Result<(u64, Vec<JsonlEvent>)> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;

    // Si fichier a été tronqué, on reset offset
    let len = file.metadata()?.len();
    let mut offset = offset_bytes.min(len);

    use std::io::Seek;
    file.seek(std::io::SeekFrom::Start(offset))?;

    let mut reader = BufReader::new(file);
    let mut buf = String::new();

    let mut events = Vec::new();
    loop {
        buf.clear();
        let n = reader.read_line(&mut buf)?;
        if n == 0 {
            break;
        }
        offset += n as u64;

        let line = buf.trim_end();
        if line.is_empty() {
            continue;
        }

        match serde_json::from_str::<JsonlEvent>(line) {
            Ok(ev) => events.push(ev),
            Err(e) => {
                eprintln!("json parse error in {}: {e} | line={}", path.display(), line);
            }
        }
    }

    Ok((offset, events))
}

#[tokio::main]
async fn main() -> Result<()> {
    let jsonl_dir = env_string("JSONL_DIR", "/data/jsonl");
    let scan_interval_ms = env_u64("SCAN_INTERVAL_MS", 500);
    let batch_size = env_usize("BATCH_SIZE", 1000);

    let jsonl_dir = PathBuf::from(jsonl_dir);

    let client = connect_pg().await?;
    ensure_schema(&client).await?;

    let mut states: HashMap<PathBuf, FileState> = HashMap::new();

    loop {
        let files = match list_jsonl_files(&jsonl_dir) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("list files error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(scan_interval_ms)).await;
                continue;
            }
        };

        for path in files {
            // init state si absent
            states.entry(path.clone()).or_insert(FileState { offset_bytes: 0 });

            // si truncate: reset
            if let (Ok(len), Some(st)) = (file_len(&path), states.get_mut(&path)) {
                if len < st.offset_bytes {
                    st.offset_bytes = 0;
                }
            }

            let offset = states.get(&path).unwrap().offset_bytes;

            let (new_offset, events) = match read_new_lines(&path, offset) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("read error {}: {e}", path.display());
                    continue;
                }
            };

            if let Some(st) = states.get_mut(&path) {
                st.offset_bytes = new_offset;
            }

            if events.is_empty() {
                continue;
            }

            // insert en batches
            let mut start = 0usize;
            while start < events.len() {
                let end = (start + batch_size).min(events.len());
                if let Err(e) = insert_batch(&client, &events[start..end]).await {
                    eprintln!("insert batch error: {e}");
                    // si PG down temporaire : on ne perd pas les lignes (elles restent dans le fichier)
                    // mais on risque de réinsérer au prochain scan; ON CONFLICT DO NOTHING protège.
                    break;
                }
                start = end;
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(scan_interval_ms)).await;
    }
}
