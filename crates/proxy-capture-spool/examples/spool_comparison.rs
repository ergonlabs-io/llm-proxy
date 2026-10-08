//! Isolated v1 reference versus redb prototype, separate from production redb.
//! Run through scripts/spool-comparison.py; production uses redb_retention.

#[allow(dead_code)] // Fault hooks are exercised by integration tests, not this driver.
#[path = "../tests/support/redb_spool.rs"]
mod redb_spool;

#[allow(dead_code)]
#[path = "../tests/support/v1_spool.rs"]
mod v1_spool;
use serde_json::{json, Value};
use std::time::Duration;
use std::{collections::BTreeMap, error::Error, fs, path::PathBuf, time::Instant};
use v1_spool::{EncryptionKey, MetadataSpool, SpoolConfig};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const REPLAY_BYTES: usize = 64 * 1024 * 1024;

struct Options {
    root: PathBuf,
    fixture: PathBuf,
    key: PathBuf,
    backend: String,
    mode: String,
    records: usize,
    batch: usize,
    rate: f64,
    disk: u64,
    cache: usize,
    stage: String,
}

impl Options {
    fn parse() -> Result<Self> {
        let mut args = std::env::args().skip(1);
        let mut values = BTreeMap::new();
        while let Some(flag) = args.next() {
            if !matches!(
                flag.as_str(),
                "--root"
                    | "--fixture"
                    | "--key"
                    | "--backend"
                    | "--mode"
                    | "--records"
                    | "--batch"
                    | "--rate"
                    | "--disk"
                    | "--cache"
                    | "--stage"
            ) {
                return Err(format!("unknown option {flag}").into());
            }
            let value = args.next().ok_or("missing option value")?;
            if values.insert(flag, value).is_some() {
                return Err("duplicate option".into());
            }
        }
        let required = |name: &str| {
            values
                .get(name)
                .cloned()
                .ok_or_else(|| format!("missing {name}"))
        };
        let opt = Self {
            root: required("--root")?.into(),
            fixture: required("--fixture")?.into(),
            key: required("--key")?.into(),
            backend: required("--backend")?,
            mode: values
                .get("--mode")
                .cloned()
                .unwrap_or_else(|| "bench".into()),
            records: values
                .get("--records")
                .map_or("1600", String::as_str)
                .parse()?,
            batch: values.get("--batch").map_or("8", String::as_str).parse()?,
            rate: values.get("--rate").map_or("0", String::as_str).parse()?,
            disk: values
                .get("--disk")
                .map_or("1073741824", String::as_str)
                .parse()?,
            cache: values
                .get("--cache")
                .map_or("8388608", String::as_str)
                .parse()?,
            stage: values.get("--stage").cloned().unwrap_or_default(),
        };
        if !matches!(opt.backend.as_str(), "v1" | "redb")
            || !matches!(opt.mode.as_str(), "bench" | "crash" | "recover")
            || !(1..=8).contains(&opt.batch)
            || !(1..=20000).contains(&opt.records)
            || !opt.rate.is_finite()
            || opt.rate < 0.0
            || opt.rate > 10000.0
            || opt.cache > 16 * 1024 * 1024
        {
            return Err("invalid experiment options".into());
        }
        Ok(opt)
    }
}

enum Backend {
    V1(MetadataSpool),
    Redb(redb_spool::Prototype),
}

impl Backend {
    fn open(o: &Options, key: [u8; 32]) -> Result<Self> {
        let directory = o.root.join("spool");
        Ok(if o.backend == "v1" {
            Self::V1(MetadataSpool::open(
                SpoolConfig {
                    directory,
                    node_id: "comparison-node".into(),
                    max_record_bytes: 524288,
                    max_segment_bytes: 64 * 1024 * 1024,
                    max_disk_bytes: o.disk,
                    max_segments: 1024,
                    max_segment_age: Duration::from_secs(60),
                },
                EncryptionKey::new("comparison-key", key)?,
                [],
            )?)
        } else {
            Self::Redb(redb_spool::Prototype::open(
                redb_spool::Config {
                    directory,
                    node_id: "comparison-node".into(),
                    max_record_bytes: 524288,
                    max_disk_bytes: o.disk,
                    cache_bytes: o.cache,
                },
                key,
            )?)
        })
    }
    fn append(&mut self, bytes: &[&[u8]]) -> Result<Vec<u64>> {
        Ok(match self {
            Self::V1(s) => s
                .append_batch(bytes)?
                .into_iter()
                .collect::<std::result::Result<Vec<_>, _>>()?
                .into_iter()
                .map(|r| r.sequence)
                .collect(),
            Self::Redb(s) => s.append_batch(bytes)?,
        })
    }
    fn commit(&mut self) -> Result<u64> {
        Ok(match self {
            Self::V1(s) => s.commit()?.through_sequence,
            Self::Redb(s) => s.commit()?,
        })
    }
    fn replay(&mut self, limit: usize) -> Result<Vec<(u64, Vec<u8>)>> {
        Ok(match self {
            Self::V1(s) => s
                .replay(0, limit, REPLAY_BYTES)?
                .into_iter()
                .map(|r| (r.sequence, r.payload))
                .collect(),
            Self::Redb(s) => s.replay(limit, REPLAY_BYTES)?,
        })
    }
    fn stats(&self) -> Result<Value> {
        Ok(match self {
            Self::V1(s) => {
                let v = s.stats()?;
                json!({"next_sequence":v.next_sequence,
                "durable":v.durable_through_sequence,"disk_bytes":v.disk_bytes,
                "segments":v.committed_segments,"poisoned":v.poisoned})
            }
            Self::Redb(s) => {
                let v = s.stats();
                json!({"next_sequence":v.next_sequence,
                "durable":v.durable,"disk_bytes":v.disk_bytes,"records":v.count,"poisoned":v.poisoned})
            }
        })
    }
}

fn payload(template: &Value, index: usize) -> Result<Vec<u8>> {
    let mut value = template.clone();
    let request = format!("comparison:{index:08}");
    value["request_id"] = json!(request);
    value["event_id"] = json!(format!("{request}:terminal"));
    if let Some(attempts) = value["attempts"].as_array_mut() {
        for (n, attempt) in attempts.iter_mut().enumerate() {
            attempt["request_id"] = json!(request);
            attempt["attempt_id"] = json!(format!("{request}:attempt:{n}"));
            attempt["event_id"] = json!(format!("{request}:attempt:{n}:terminal"));
        }
    }
    Ok(serde_json::to_vec(&value)?)
}

fn pause(o: &Options) -> Result<()> {
    fs::write(
        o.root.join("ready.json"),
        serde_json::to_vec(&json!({"stage":o.stage}))?,
    )?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    Err("crash driver was not killed before its bounded deadline".into())
}

fn verify(backend: &mut Backend, template: &Value, expected: usize, limit: usize) -> Result<Value> {
    let start = Instant::now();
    let rows = backend.replay(limit)?;
    let matches = rows.iter().enumerate().all(|(index, (_, bytes))| {
        payload(template, index).is_ok_and(|expected| expected == *bytes)
    });
    Ok(
        json!({"records":rows.len(),"expected_records":expected,"matches_expected_prefix":matches,
        "acknowledged_prefix_present":rows.len() >= expected && matches,
        "elapsed_ms":start.elapsed().as_secs_f64()*1000.0}),
    )
}

fn run(o: Options) -> Result<Value> {
    let key: [u8; 32] = fs::read(&o.key)?
        .try_into()
        .map_err(|_| "key must contain 32 bytes")?;
    let template: Value = serde_json::from_slice(&fs::read(&o.fixture)?)?;
    let sample_bytes = payload(&template, o.records)?.len();
    if sample_bytes > 524288
        || sample_bytes
            .checked_mul(o.records)
            .map_or(true, |n| n > REPLAY_BYTES)
    {
        return Err("workload exceeds bounded record/replay profile".into());
    }
    let open_start = Instant::now();
    let mut backend = Backend::open(&o, key)?;
    let open_ms = open_start.elapsed().as_secs_f64() * 1000.0;
    if o.mode == "recover" {
        let verify = verify(&mut backend, &template, o.batch, o.records)?;
        let before = backend.stats()?;
        let bytes = payload(&template, o.records)?;
        let next = backend.append(&[&bytes])?;
        return Ok(
            json!({"backend":o.backend,"open_ms":open_ms,"replay":verify,
            "stats_before_probe":before,"next_probe_sequence":next[0]}),
        );
    }
    if o.mode == "crash" {
        if !matches!(
            o.stage.as_str(),
            "after_append" | "after_commit" | "before_sync" | "after_sync"
        ) {
            return Err("invalid crash stage".into());
        }
        let first = (0..o.batch)
            .map(|i| payload(&template, i))
            .collect::<Result<Vec<_>>>()?;
        backend.append(&first.iter().map(Vec::as_slice).collect::<Vec<_>>())?;
        let ack = backend.commit()?;
        // This external receipt ledger belongs to the harness, not the spool's quota.
        let ledger = o.root.join("acknowledged.json");
        fs::write(
            &ledger,
            serde_json::to_vec(&json!({"records":o.batch,"through_sequence":ack}))?,
        )?;
        fs::File::open(&ledger)?.sync_all()?;
        let second = (o.batch..2 * o.batch)
            .map(|i| payload(&template, i))
            .collect::<Result<Vec<_>>>()?;
        backend.append(&second.iter().map(Vec::as_slice).collect::<Vec<_>>())?;
        if matches!(o.stage.as_str(), "before_sync" | "after_sync") {
            let Backend::Redb(spool) = &backend else {
                return Err("barrier hooks are redb-only".into());
            };
            spool.pause_next_sync(o.root.join("ready.json"), o.stage == "after_sync");
            backend.commit()?;
            return Err("sync hook unexpectedly returned".into());
        }
        if o.stage == "after_commit" {
            backend.commit()?;
        }
        return pause(&o).map(|_| Value::Null);
    }
    let start = Instant::now();
    let mut times = Vec::new();
    let mut growth = Vec::new();
    let mut confirmed = 0;
    let mut stopped = None;
    while confirmed < o.records {
        if o.rate > 0.0 {
            let target = Duration::from_secs_f64(confirmed as f64 / o.rate);
            if let Some(wait) = target.checked_sub(start.elapsed()) {
                std::thread::sleep(wait);
            }
        }
        let count = o.batch.min(o.records - confirmed);
        let data = (confirmed..confirmed + count)
            .map(|i| payload(&template, i))
            .collect::<Result<Vec<_>>>()?;
        let slices = data.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let begin = Instant::now();
        if let Err(error) = backend.append(&slices) {
            stopped = Some(
                json!({"phase":"append","error":error.to_string(),"confirmed_before_failure":confirmed}),
            );
            break;
        }
        let reserved = begin.elapsed().as_secs_f64() * 1000.0;
        let commit_start = Instant::now();
        if let Err(error) = backend.commit() {
            stopped = Some(
                json!({"phase":"commit","error":error.to_string(),"confirmed_before_failure":confirmed}),
            );
            break;
        }
        times.push(json!({"reserve_encrypt_ms":reserved,"commit_ms":commit_start.elapsed().as_secs_f64()*1000.0,
            "durable_batch_ms":begin.elapsed().as_secs_f64()*1000.0,"records":count}));
        confirmed += count;
        if times.len() % 128 == 0 {
            growth.push(json!({"confirmed":confirmed,"stats":backend.stats()?}));
        }
    }
    let workload_seconds = start.elapsed().as_secs_f64();
    let final_stats = backend.stats()?;
    drop(backend);
    let reopen = Instant::now();
    let mut backend = Backend::open(&o, key)?;
    let reopen_ms = reopen.elapsed().as_secs_f64() * 1000.0;
    let replay = verify(&mut backend, &template, confirmed, o.records)?;
    Ok(
        json!({"backend":o.backend,"requested_records":o.records,"confirmed_records":confirmed,
        "payload_bytes":sample_bytes,"batch_size":o.batch,"rate":o.rate,"max_disk_bytes":o.disk,
        "redb_cache_bytes":o.cache,"open_ms":open_ms,"workload_seconds":workload_seconds,
        "stopped":stopped,"final_stats":final_stats,"reopen_ms":reopen_ms,"replay":replay,
        "batches":times,"growth":growth}),
    )
}

fn main() {
    match Options::parse().and_then(run) {
        Ok(result) => println!("{result}"),
        Err(error) => {
            eprintln!("spool comparison failed: {error}");
            std::process::exit(1);
        }
    }
}
