use packet_parser::parse::PacketFlow;
#[cfg(feature = "parse_timing")]
use packet_parser::timing::ParseTiming;

use std::{
    fs::{self, File},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum PacketCaptureError {
    #[error(transparent)]
    PcapOpenError(#[from] pcap::Error),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

#[derive(Debug)]
struct Stats {
    ok: u64,
    err: u64,
    durations_ns: Vec<u128>,
}

impl Stats {
    fn new() -> Self {
        Self {
            ok: 0,
            err: 0,
            durations_ns: Vec::new(),
        }
    }

    fn push(&mut self, ok: bool, duration_ns: u128) {
        if ok {
            self.ok += 1;
            self.durations_ns.push(duration_ns);
        } else {
            self.err += 1;
        }
    }

    fn merge_from(&mut self, other: &Stats) {
        self.ok += other.ok;
        self.err += other.err;
        self.durations_ns.extend(other.durations_ns.iter().copied());
    }

    fn report(&mut self, label: &str) {
        println!("--- {} ---", label);
        println!("OK: {}, ERR: {}", self.ok, self.err);

        if self.durations_ns.is_empty() {
            println!("Aucune mesure (0 paquet OK).");
            return;
        }

        self.durations_ns.sort_unstable();
        let n = self.durations_ns.len();
        let min = self.durations_ns[0];
        let max = self.durations_ns[n - 1];
        let sum: u128 = self.durations_ns.iter().copied().sum();
        let avg = sum / (n as u128);

        let p50 = quantile_type7_u128(&self.durations_ns, 0.50);
        let p95 = quantile_type7_u128(&self.durations_ns, 0.95);
        let p99 = quantile_type7_u128(&self.durations_ns, 0.99);

        println!(
            "durations(ns): min={} avg={} p50={} p95={} p99={} max={}",
            min, avg, p50, p95, p99, max
        );
    }
}

// Quantile "type 7" (R/NumPy default-like) sur slice triée
fn quantile_type7_u128(sorted: &[u128], q: f64) -> u128 {
    let n = sorted.len();
    if n == 0 {
        return 0;
    }
    if n == 1 {
        return sorted[0];
    }

    let q = q.clamp(0.0, 1.0);
    // p = 1 + (n - 1) * q
    let p = 1.0 + ((n - 1) as f64) * q;
    let k = p.floor(); // 1..n
    let d = p - k;

    let k_usize = k as usize; // 1..n
    if k_usize <= 1 {
        return sorted[0];
    }
    if k_usize >= n {
        return sorted[n - 1];
    }

    let x0 = sorted[k_usize - 1] as f64;
    let x1 = sorted[k_usize] as f64;
    (x0 + d * (x1 - x0)).round() as u128
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u128
}

fn escape_json_string(s: &str) -> String {
    // minimal+ : échappe \, ", et retours ligne
    let s = s.replace('\\', "\\\\").replace('"', "\\\"");
    let s = s
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    s
}

fn packet_hash_hex(data: &[u8]) -> String {
    // blake3 hex
    blake3::hash(data).to_hex().to_string()
}

fn write_jsonl_line(
    w: &mut BufWriter<File>,
    run_id: &str,
    crate_version: &str,
    pcap: &Path,
    idx: u64,
    len: usize,
    hash_hex: &str,
    duration_ns: u128,
    #[cfg(feature = "parse_timing")] timing: Option<&ParseTiming>,
    err: Option<&str>,
) -> std::io::Result<()> {
    let ts = now_unix_ms();
    let pcap_str = pcap.to_string_lossy();

    // timings (optionnel)
    #[cfg(feature = "parse_timing")]
    let timing_fields = if let Some(t) = timing {
        format!(
            ",\"l2_ns\":{},\"l3_ns\":{},\"l4_ns\":{},\"l7_ns\":{},\"parse_total_ns\":{}",
            t.l2_ns, t.l3_ns, t.l4_ns, t.l7_ns, t.total_ns
        )
    } else {
        String::new()
    };

    #[cfg(not(feature = "parse_timing"))]
    let timing_fields = "";

    if let Some(e) = err {
        writeln!(
            w,
            "{{\"ts\":{},\"run_id\":\"{}\",\"crate_version\":\"{}\",\"pcap\":\"{}\",\"idx\":{},\"len\":{},\"hash\":\"{}\",\"ok\":false,\"duration_ns\":{},\"error\":\"{}\"{}}}",
            ts,
            escape_json_string(run_id),
            escape_json_string(crate_version),
            escape_json_string(&pcap_str),
            idx,
            len,
            escape_json_string(hash_hex),
            duration_ns,
            escape_json_string(e),
            timing_fields
        )
    } else {
        writeln!(
            w,
            "{{\"ts\":{},\"run_id\":\"{}\",\"crate_version\":\"{}\",\"pcap\":\"{}\",\"idx\":{},\"len\":{},\"hash\":\"{}\",\"ok\":true,\"duration_ns\":{}{}}}",
            ts,
            escape_json_string(run_id),
            escape_json_string(crate_version),
            escape_json_string(&pcap_str),
            idx,
            len,
            escape_json_string(hash_hex),
            duration_ns,
            timing_fields
        )
    }
}

fn log_path_for(pcap_path: &Path) -> PathBuf {
    let fname = pcap_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown.pcap");

    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let dir = PathBuf::from(format!("{}/.local/share/packet_parser_bench/jsonl", home));
    let _ = std::fs::create_dir_all(&dir);

    dir.join(format!("bench_{}.jsonl", fname))
}


fn make_run_id() -> String {
    // minimal: timestamp ms + pid
    let ts = now_unix_ms();
    let pid = std::process::id();
    format!("run-{}-{}", ts, pid)
}

fn main() -> Result<(), PacketCaptureError> {
    let run_id = make_run_id();
    let crate_version = env!("CARGO_PKG_VERSION");

    let pcap_dir = Path::new("/home/erdt-cyber/rust/ICS-Security-Tools/pcaps/ModbusTCP");

    let mut global_stats = Stats::new();

    for entry in fs::read_dir(pcap_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) != Some("pcap") {
            continue;
        }

        let mut cap = pcap::Capture::from_file(&path)?;

        let out_path = log_path_for(&path);
        let file = File::create(&out_path)?;
        let mut w = BufWriter::new(file);

        let mut stats = Stats::new();
        let mut idx: u64 = 0;

        let file_start = Instant::now();

        loop {
            let packet = match cap.next_packet() {
                Ok(p) => p,
                Err(pcap::Error::NoMorePackets) => break,
                Err(_) => {
                    idx += 1;
                    stats.err += 1;
                    let _ = write_jsonl_line(
                        &mut w,
                        &run_id,
                        crate_version,
                        &path,
                        idx,
                        0,
                        "nohash",
                        0,
                        #[cfg(feature = "parse_timing")]
                        None,
                        Some("pcap_read_error"),
                    );
                    continue;
                }
            };

            idx += 1;
            let len = packet.data.len();
            let hash_hex = packet_hash_hex(packet.data);

            // pipeline complet : try_from/try_from_timed + to_owned + write_jsonl_line
            let start = Instant::now();

            let mut ok = false;
            let mut err_msg: Option<String> = None;

            #[cfg(feature = "parse_timing")]
            let mut timing = ParseTiming::default();

            #[cfg(feature = "parse_timing")]
            let parsed = PacketFlow::try_from_timed(packet.data, &mut timing);

            match parsed {
                Ok(p) => {
                    let owned = p.to_owned();
                    std::hint::black_box(&owned);
                    ok = true;
                }
                Err(e) => {
                    err_msg = Some(e.to_string());
                }
            }

            let duration_ns = start.elapsed().as_nanos();

            // JSONL
            if ok {
                stats.push(true, duration_ns);
                write_jsonl_line(
                    &mut w,
                    &run_id,
                    crate_version,
                    &path,
                    idx,
                    len,
                    &hash_hex,
                    duration_ns,
                    #[cfg(feature = "parse_timing")]
                    Some(&timing),
                    None,
                )?;
            } else {
                stats.push(false, duration_ns);
                write_jsonl_line(
                    &mut w,
                    &run_id,
                    crate_version,
                    &path,
                    idx,
                    len,
                    &hash_hex,
                    duration_ns,
                    #[cfg(feature = "parse_timing")]
                    Some(&timing),
                    err_msg.as_deref(),
                )?;
            }

            // flush promtail
            if idx % 10_000 == 0 {
                w.flush()?;
            }
        }

        w.flush()?;

        let elapsed = file_start.elapsed();
        let total = stats.ok + stats.err;
        let pps = (total as f64) / elapsed.as_secs_f64().max(1e-9);

        println!("===============================");
        println!("PCAP: {}", path.display());
        println!("JSONL: {}", out_path.display());
        println!(
            "Total: {} packets, time: {:.3}s, rate: {:.1} pkt/s",
            total,
            elapsed.as_secs_f64(),
            pps
        );
        stats.report("Pipeline: parse + to_owned + jsonl");

        global_stats.merge_from(&stats);
    }

    println!("===============================");
    println!("GLOBAL TOTAL");
    global_stats.report("Pipeline: parse + to_owned + jsonl (all pcaps)");

    Ok(())
}
