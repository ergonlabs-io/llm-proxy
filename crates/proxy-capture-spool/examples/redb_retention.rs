use proxy_capture_spool::{EncryptionKey, MetadataSpool, SpoolConfig};
use serde_json::Value;
use std::{
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

const RECORD_LIMIT: usize = 524_288;
const DISK_LIMIT: u64 = 1_073_741_824;
const CACHE_BYTES: usize = 4 * 1024 * 1024;
const BATCH_SIZE: usize = 8;
const REPLAY_ROWS: usize = 64;
const REPLAY_BYTES: usize = 32 * 1024 * 1024;

struct Args {
    root: PathBuf,
    fixture: PathBuf,
    key: PathBuf,
    records: usize,
    rate: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut values = env::args().skip(1);
    let mut root = None;
    let mut fixture = None;
    let mut key = None;
    let mut records = None;
    let mut rate = None;
    while let Some(flag) = values.next() {
        let value = values
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--root" => root = Some(PathBuf::from(value)),
            "--fixture" => fixture = Some(PathBuf::from(value)),
            "--key" => key = Some(PathBuf::from(value)),
            "--records" => records = Some(value.parse::<usize>().map_err(|e| e.to_string())?),
            "--rate" => rate = Some(value.parse::<u64>().map_err(|e| e.to_string())?),
            _ => return Err(format!("unknown argument {flag}")),
        }
    }
    let args = Args {
        root: root.ok_or("--root is required")?,
        fixture: fixture.ok_or("--fixture is required")?,
        key: key.ok_or("--key is required")?,
        records: records.ok_or("--records is required")?,
        rate: rate.ok_or("--rate is required")?,
    };
    if args.records == 0 || args.records > 100_000 || args.rate > 500 {
        return Err("records must be 1..=100000 and rate must be <=500".into());
    }
    Ok(args)
}

fn read_key(path: &Path) -> io::Result<[u8; 32]> {
    let bytes = fs::read(path)?;
    bytes
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "key must contain 32 bytes"))
}

fn spool_config(root: &Path) -> SpoolConfig {
    SpoolConfig {
        directory: root.join("spool"),
        node_id: "retention-qualification-node".into(),
        max_record_bytes: RECORD_LIMIT,
        max_disk_bytes: DISK_LIMIT,
        cache_bytes: CACHE_BYTES,
        max_pending_records: BATCH_SIZE,
    }
}

fn key(path: &Path) -> EncryptionKey {
    EncryptionKey::new("qualification-key", read_key(path).unwrap()).unwrap()
}

fn make_payload(source: &Value, index: usize) -> Vec<u8> {
    let mut value = source.clone();
    let id = format!("retention-{index:08}");
    value["event_id"] = format!("{id}:terminal").into();
    value["request_id"] = id.clone().into();
    if let Some(attempts) = value["attempts"].as_array_mut() {
        for (attempt_index, attempt) in attempts.iter_mut().enumerate() {
            attempt["event_id"] = format!("{id}:attempt:{attempt_index}").into();
            attempt["request_id"] = id.clone().into();
            attempt["attempt_id"] = format!("{id}:attempt:{attempt_index}").into();
        }
    }
    serde_json::to_vec(&value).expect("fixture serialization")
}

fn percentile(values: &[f64], fraction: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let index = ((sorted.len() as f64 * fraction).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    Some(sorted[index])
}

fn stats_json(stats: &proxy_capture_spool::SpoolStats) -> Value {
    serde_json::json!({
        "next_sequence": stats.next_sequence,
        "durable_through_sequence": stats.durable_through_sequence,
        "acknowledged_through_sequence": stats.acknowledged_through_sequence,
        "pending_records": stats.pending_records,
        "retained_records": stats.retained_records,
        "database_bytes": stats.database_bytes,
        "disk_bytes": stats.disk_bytes,
        "quarantine_bytes": stats.quarantine_bytes,
        "poisoned": stats.poisoned,
    })
}

fn write_result(value: &Value) {
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    serde_json::to_writer_pretty(&mut stdout, value).expect("serialize result");
    writeln!(stdout).expect("write result newline");
}

fn main() {
    let args = parse_args().unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(2);
    });
    let start = Instant::now();
    let fixture: Value = serde_json::from_slice(&fs::read(&args.fixture).unwrap()).unwrap();
    let initial_open_started = Instant::now();
    let mut spool = MetadataSpool::open(spool_config(&args.root), key(&args.key), []).unwrap();
    let initial_open_ms = initial_open_started.elapsed().as_secs_f64() * 1000.0;
    let initial_stats = spool.stats().unwrap();
    let mut batches = Vec::new();
    let mut growth = vec![serde_json::json!({
        "batch": 0,
        "records": 0,
        "stats": stats_json(&initial_stats),
    })];
    let mut confirmed = 0usize;
    let mut stopped: Option<String> = None;
    let run_started = Instant::now();
    let mut batch_index = 0usize;
    let mut next_deadline = run_started;

    while confirmed < args.records {
        let batch_len = BATCH_SIZE.min(args.records - confirmed);
        let payloads: Vec<Vec<u8>> = (confirmed..confirmed + batch_len)
            .map(|index| make_payload(&fixture, index))
            .collect();
        let payload_refs: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
        let reserve_started = Instant::now();
        let appended = match spool.append_batch(&payload_refs) {
            Ok(results) => results,
            Err(error) => {
                stopped = Some(error.to_string());
                break;
            }
        };
        let reserve_encrypt_ms = reserve_started.elapsed().as_secs_f64() * 1000.0;
        if let Some(error) = appended.iter().find_map(|result| result.as_ref().err()) {
            stopped = Some(error.to_string());
            break;
        }
        let commit_started = Instant::now();
        let durable = match spool.commit() {
            Ok(receipt) => receipt,
            Err(error) => {
                stopped = Some(error.to_string());
                break;
            }
        };
        let commit_ms = commit_started.elapsed().as_secs_f64() * 1000.0;
        confirmed += batch_len;
        batch_index += 1;
        batches.push(serde_json::json!({
            "batch": batch_index,
            "first_sequence": durable.through_sequence + 1 - batch_len as u64,
            "through_sequence": durable.through_sequence,
            "records": batch_len,
            "reserve_encrypt_ms": reserve_encrypt_ms,
            "commit_ms": commit_ms,
            "durable_batch_ms": reserve_encrypt_ms + commit_ms,
        }));
        if batch_index % 128 == 0 || confirmed == args.records {
            growth.push(serde_json::json!({
                "batch": batch_index,
                "records": confirmed,
                "stats": stats_json(&spool.stats().unwrap()),
            }));
        }
        if args.rate > 0 {
            next_deadline += Duration::from_secs_f64(batch_len as f64 / args.rate as f64);
            if let Some(delay) = next_deadline.checked_duration_since(Instant::now()) {
                thread::sleep(delay);
            }
        }
    }
    let run_duration_ms = run_started.elapsed().as_secs_f64() * 1000.0;
    let final_stats = spool.stats().unwrap();
    drop(spool);

    let recovery_started = Instant::now();
    let recovered = MetadataSpool::open(spool_config(&args.root), key(&args.key), []).unwrap();
    let recovery_open_ms = recovery_started.elapsed().as_secs_f64() * 1000.0;
    let mut cursor = 0u64;
    let mut replayed = 0usize;
    let mut verified = 0usize;
    let replay_started = Instant::now();
    loop {
        let page = recovered.replay(cursor, REPLAY_ROWS, REPLAY_BYTES).unwrap();
        if page.is_empty() {
            break;
        }
        for record in &page {
            let expected_payload = make_payload(&fixture, (record.sequence - 1) as usize);
            if expected_payload == record.payload {
                verified += 1;
            } else {
                stopped.get_or_insert_with(|| {
                    format!("replay payload mismatch at sequence {}", record.sequence)
                });
            }
            cursor = record.sequence;
            replayed += 1;
        }
    }
    let replay_ms = replay_started.elapsed().as_secs_f64() * 1000.0;
    let recovery_stats = recovered.stats().unwrap();
    let recovery_duration_ms = recovery_open_ms + replay_ms;
    drop(recovered);

    let latency = |field: &str| {
        let values: Vec<f64> = batches
            .iter()
            .filter_map(|batch| batch[field].as_f64())
            .collect();
        serde_json::json!({
            "p50": percentile(&values, 0.50),
            "p95": percentile(&values, 0.95),
            "p99": percentile(&values, 0.99),
        })
    };
    write_result(&serde_json::json!({
        "requested_records": args.records,
        "confirmed_records": confirmed,
        "stopped": stopped,
        "rate_records_per_second": args.rate,
        "max_disk_bytes": DISK_LIMIT,
        "max_record_bytes": RECORD_LIMIT,
        "pending_batch_records": BATCH_SIZE,
        "cache_bytes": CACHE_BYTES,
        "initial_open_ms": initial_open_ms,
        "run_duration_ms": run_duration_ms,
        "recovery_open_ms": recovery_open_ms,
        "replay_ms": replay_ms,
        "recovery_duration_ms": recovery_duration_ms,
        "elapsed_ms": start.elapsed().as_secs_f64() * 1000.0,
        "initial_stats": stats_json(&initial_stats),
        "final_stats": stats_json(&final_stats),
        "recovery_stats": stats_json(&recovery_stats),
        "replay": {
            "records": replayed,
            "verified_records": verified,
            "acknowledged_prefix_present": replayed == confirmed && verified == confirmed,
            "cursor_rows": REPLAY_ROWS,
            "cursor_bytes": REPLAY_BYTES,
        },
        "latency_ms": {
            "reserve_encrypt": latency("reserve_encrypt_ms"),
            "commit": latency("commit_ms"),
            "durable_batch": latency("durable_batch_ms"),
        },
        "growth": growth,
        "batches": batches,
        "limits": {
            "format": "redb production metadata spool",
            "logical_disk_cap": DISK_LIMIT,
            "record_cap": RECORD_LIMIT,
            "pending_batch": BATCH_SIZE,
            "cache_bytes": CACHE_BYTES,
            "automatic_eviction": false,
        }
    }));
}
