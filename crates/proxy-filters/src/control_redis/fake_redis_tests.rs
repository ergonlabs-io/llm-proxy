//! Tests against an in-process fake Redis. The store under test is the real
//! [`RedisControlPlaneStore`], talking real RESP over real loopback sockets
//! through the real `redis` client; only the server is fake.
//!
//! # Why a fake, when this module already has Redis tests
//!
//! Those are `#[ignore]`d behind `LLM_PROXY_TEST_REDIS`, so a normal run never
//! executes them. And a real Redis cannot do what the lane tests need, which
//! is to stall ONE connection while it keeps serving another: it runs
//! commands one at a time, and its only pause (`CLIENT PAUSE`) stops every
//! client at once. The fake parks a chosen command unanswered on its
//! connection, which is exactly what a stalled Redis looks like to a client:
//! a read that does not return.
//!
//! The fake implements no Redis semantics; every reply is canned. These tests
//! prove WHICH CONNECTION each store call travels on and what the others do
//! while one is stuck. What a real Redis stores is the other tests' business.

use std::collections::{HashSet, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, MutexGuard};
use std::thread;

use super::*;
use crate::control::log_capture::Capture;
use crate::spend::{MicroUsd, Period};
use proxy_http::tenant_credentials::CredentialSource;

/// What the fake answers `add_spend` with. Distinct from the `1` every other
/// script call gets, so a reply that reached the wrong caller shows.
const SPEND_TOTAL: u64 = 100;
const GENERATION: u64 = 7;
const STORED_SPEND: u64 = 42;
const LAST_SEQ: u64 = 3;

/// How long a test waits for something that should already be happening
/// before it calls the run broken. Only a failing run ever waits this long:
/// nothing a passing run asserts depends on it.
const PATIENCE: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// The fake server
// ---------------------------------------------------------------------------

/// A command the fake can park or hang up on, named for what the STORE is
/// doing rather than for the Redis command, so the tests read as intent.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Gate {
    /// `add_spend`'s script call: the flusher's unit of work.
    SpendFlush,
    /// The `EXEC` that carries `load()`'s five reads.
    PolicyLoad,
}

#[derive(Default)]
struct State {
    /// Connections accepted so far, which is also the next connection's id.
    accepted: usize,
    /// `(connection id, command)` in the order the server read them. The
    /// client library's own connect-time `CLIENT` commands are not logged.
    log: Vec<(usize, String)>,
    /// The same commands with their arguments, so a test can assert what was
    /// actually sent (which keys, in which order, inside which transaction)
    /// and not only which command it was.
    wire: Vec<(usize, Vec<String>)>,
    /// Replies to the next scripts that write rate cards, oldest first. An
    /// empty queue answers `1`, like every other script call.
    rate_card_script_replies: VecDeque<i64>,
    /// Gates whose commands are parked instead of answered.
    held: HashSet<Gate>,
    /// How many commands are parked at each gate right now.
    parked: HashMap<Gate, usize>,
    /// Gates whose next command makes the server hang up instead of answer.
    kill_next: HashSet<Gate>,
    shutdown: bool,
}

struct Shared {
    state: Mutex<State>,
    changed: Condvar,
    rows: Rows,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        // Rust note: a poisoned lock only records that some thread panicked
        // while holding it. The state is still usable, and it has to be:
        // `FakeRedis::drop` locks it while a failing test unwinds, and a
        // second panic during unwinding aborts the whole process.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The policy state the fake serves for `load()`. Built with the store's own
/// row encoders, so the rows follow the store's format when it changes, and a
/// row that stops decoding fails `load()` loudly rather than going unnoticed.
struct Rows {
    tenants: Vec<String>,
    keys: Vec<(String, Vec<u8>)>,
    policies: Vec<(String, Vec<u8>)>,
    budgets: Vec<(String, Vec<u8>)>,
    credentials: Vec<(String, Vec<u8>)>,
    rate_cards: Vec<(String, Vec<u8>)>,
}

fn sample_credential() -> StoredTenantCredential {
    StoredTenantCredential {
        schema_version: TENANT_CREDENTIALS_SCHEMA_VERSION,
        tenant: TenantId::new("tenant-a"),
        provider: "openai".into(),
        key_id: "kek-1".into(),
        nonce: [9; 12],
        ciphertext: b"sealed-credential-bytes".to_vec(),
        last4: "wxyz".into(),
        fingerprint: "fp-1".into(),
        created_at: "2026-10-12T00:00:00Z".into(),
        updated_at: "2026-10-12T00:00:00Z".into(),
        verified_at: None,
    }
}

fn sample_budget() -> TenantBudget {
    TenantBudget {
        max_micros: MicroUsd::from_micros(5_000_000),
        period: Period::Monthly,
        credential_source: CredentialSource::Platform,
    }
}

/// A rate card for `chain`. The document is opaque to the store, so a
/// placeholder object stands in for a real one.
fn sample_rate_card(chain: &str) -> StoredRateCard {
    StoredRateCard {
        chain: chain.into(),
        version: format!("version-{chain}"),
        card_json: format!(r#"{{"chain":"{chain}"}}"#),
    }
}

impl Rows {
    /// Two tenants, three keys (one revoked), one policy, one budget, one
    /// sealed credential and four rate card rows (three readable, one not):
    /// a different count for most kinds, so a count reported under the wrong
    /// name cannot pass.
    fn sample() -> Rows {
        let key_row = |tenant: &str, revoked: bool, fill: u8| {
            encode_json(&EncodedKeyRow {
                schema_version: SPEND_SCHEMA_VERSION,
                digest: [fill; 32],
                tenant: tenant.into(),
                revoked,
            })
        };
        Rows {
            tenants: vec!["tenant-a".into(), "tenant-b".into()],
            keys: vec![
                ("key-1".into(), key_row("tenant-a", false, 1)),
                ("key-2".into(), key_row("tenant-a", true, 2)),
                ("key-3".into(), key_row("tenant-b", false, 3)),
            ],
            policies: vec![(
                "tenant-a".into(),
                encode_json(&EncodedModelAccess::from(&ModelAccess::All)),
            )],
            budgets: vec![(
                "tenant-b".into(),
                encode_json(&EncodedTenantBudget::from(&sample_budget())),
            )],
            credentials: vec![(
                RedisControlPlaneStore::credential_field("tenant-a", "openai"),
                encode_json(&EncodedTenantCredentialRow::from(&sample_credential())),
            )],
            rate_cards: vec![
                (
                    "chain-a".into(),
                    encode_json(&EncodedRateCardRow::from(&sample_rate_card("chain-a"))),
                ),
                (
                    "chain-b".into(),
                    encode_json(&EncodedRateCardRow::from(&sample_rate_card("chain-b"))),
                ),
                (
                    "chain-c".into(),
                    encode_json(&EncodedRateCardRow::from(&sample_rate_card("chain-c"))),
                ),
                // A row no build could read: `load()` skips it and carries on.
                ("chain-broken".into(), b"not a rate card row".to_vec()),
            ],
        }
    }

    /// The combined length of every field name, set member and value: what a
    /// correct `payload_bytes` comes to, worked out here from the rows served
    /// rather than by the code under test.
    fn payload_bytes(&self) -> usize {
        let tenants: usize = self.tenants.iter().map(String::len).sum();
        let hashes: usize = [
            &self.keys,
            &self.policies,
            &self.budgets,
            &self.credentials,
            &self.rate_cards,
        ]
        .into_iter()
        .flatten()
        .map(|(field, value)| field.len() + value.len())
        .sum();
        tenants + hashes
    }

    /// The `EXEC` reply to `load()`'s pipeline: an array of six replies.
    fn exec_reply(&self) -> Vec<u8> {
        let mut out = Vec::new();
        array_len(&mut out, 6);
        array_len(&mut out, self.tenants.len());
        for tenant in &self.tenants {
            bulk(&mut out, tenant.as_bytes());
        }
        // An `HGETALL` reply is flat: field, value, field, value, ...
        for hash in [
            &self.keys,
            &self.policies,
            &self.budgets,
            &self.credentials,
            &self.rate_cards,
        ] {
            array_len(&mut out, hash.len() * 2);
            for (field, value) in hash {
                bulk(&mut out, field.as_bytes());
                bulk(&mut out, value);
            }
        }
        out
    }
}

fn array_len(out: &mut Vec<u8>, len: usize) {
    out.extend_from_slice(format!("*{len}\r\n").as_bytes());
}

fn bulk(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(format!("${}\r\n", bytes.len()).as_bytes());
    out.extend_from_slice(bytes);
    out.extend_from_slice(b"\r\n");
}

fn bulk_number(n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    bulk(&mut out, n.to_string().as_bytes());
    out
}

/// Reads one line without its terminator, or `None` at end of stream.
fn read_line(reader: &mut BufReader<TcpStream>) -> Option<String> {
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    Some(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Reads one command (a RESP array of bulk strings), or `None` when the
/// client has closed the connection.
fn read_command(reader: &mut BufReader<TcpStream>) -> Option<Vec<Vec<u8>>> {
    let count: usize = read_line(reader)?.strip_prefix('*')?.parse().ok()?;
    let mut args = Vec::with_capacity(count);
    for _ in 0..count {
        let len: usize = read_line(reader)?.strip_prefix('$')?.parse().ok()?;
        // The payload plus its trailing CRLF.
        let mut buf = vec![0; len + 2];
        reader.read_exact(&mut buf).ok()?;
        buf.truncate(len);
        args.push(buf);
    }
    (!args.is_empty()).then_some(args)
}

/// Applies `gate` to a command about to be answered: `false` means hang up
/// without answering, `true` means answer, after waiting out the gate if it
/// is held.
fn pass(shared: &Shared, gate: Gate) -> bool {
    let mut state = shared.lock();
    if state.kill_next.remove(&gate) {
        return false;
    }
    if state.held.contains(&gate) {
        *state.parked.entry(gate).or_default() += 1;
        shared.changed.notify_all();
        while state.held.contains(&gate) && !state.shutdown {
            state = shared
                .changed
                .wait(state)
                .unwrap_or_else(|e| e.into_inner());
        }
        *state.parked.entry(gate).or_default() -= 1;
    }
    true
}

/// The canned reply to one command, or `None` to hang up instead.
fn answer(
    shared: &Shared,
    name: &str,
    args: &[Vec<u8>],
    queued: &mut Option<Vec<String>>,
) -> Option<Vec<u8>> {
    let mentions = |needle: &str| {
        args.iter()
            .any(|arg| String::from_utf8_lossy(arg).contains(needle))
    };
    Some(match name {
        "MULTI" => {
            *queued = Some(Vec::new());
            b"+OK\r\n".to_vec()
        }
        "EXEC" => {
            let commands = queued.take().unwrap_or_default();
            if commands.first().map(String::as_str) == Some("SMEMBERS") {
                // `load()`'s pipeline: the only one that starts with a read.
                if !pass(shared, Gate::PolicyLoad) {
                    return None;
                }
                shared.rows.exec_reply()
            } else {
                // An admin write: one canned integer per queued command.
                let mut out = format!("*{}\r\n", commands.len()).into_bytes();
                for _ in &commands {
                    out.extend_from_slice(b":1\r\n");
                }
                out
            }
        }
        _ if queued.is_some() => {
            if let Some(commands) = queued {
                commands.push(name.to_string());
            }
            b"+QUEUED\r\n".to_vec()
        }
        // `add_spend`'s script is the only one whose keys are spend rows.
        "EVALSHA" if mentions(":spend:") => {
            if !pass(shared, Gate::SpendFlush) {
                return None;
            }
            format!(":{SPEND_TOTAL}\r\n").into_bytes()
        }
        // The script that seeds a rate card if the chain has none: `1` when
        // it wrote, `0` when a card was already there.
        "EVALSHA" if mentions(":rate_cards") => {
            let reply = shared
                .lock()
                .rate_card_script_replies
                .pop_front()
                .unwrap_or(1);
            format!(":{reply}\r\n").into_bytes()
        }
        "EVALSHA" => b":1\r\n".to_vec(),
        "GET" if mentions(":generation") => bulk_number(GENERATION),
        "GET" => bulk_number(STORED_SPEND),
        "HGET" => bulk_number(LAST_SEQ),
        "SET" | "CLIENT" => b"+OK\r\n".to_vec(),
        // `SCRIPT LOAD` answers the script's hash; the store ignores it.
        "SCRIPT" => {
            let mut out = Vec::new();
            bulk(&mut out, b"0000000000000000000000000000000000000000");
            out
        }
        other => format!("-ERR the fake does not expect {other}\r\n").into_bytes(),
    })
}

/// One connection's thread: read a command, answer it, repeat until the
/// client hangs up or the fake does.
fn serve(shared: Arc<Shared>, conn: usize, stream: TcpStream) {
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let mut writer = stream;
    // `Some` between `MULTI` and `EXEC`: the commands queued so far.
    let mut queued: Option<Vec<String>> = None;
    while let Some(args) = read_command(&mut reader) {
        let name = String::from_utf8_lossy(&args[0]).to_ascii_uppercase();
        if name != "CLIENT" {
            let mut state = shared.lock();
            state.log.push((conn, name.clone()));
            state.wire.push((
                conn,
                args.iter()
                    .map(|arg| String::from_utf8_lossy(arg).into_owned())
                    .collect(),
            ));
        }
        let Some(reply) = answer(&shared, &name, &args, &mut queued) else {
            // Hang up: returning drops both halves, which closes the socket.
            return;
        };
        if writer.write_all(&reply).is_err() {
            return;
        }
    }
}

struct FakeRedis {
    addr: SocketAddr,
    shared: Arc<Shared>,
    accept: Option<thread::JoinHandle<()>>,
}

impl FakeRedis {
    fn start() -> FakeRedis {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral loopback port");
        let addr = listener
            .local_addr()
            .expect("a bound listener has an address");
        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            rows: Rows::sample(),
        });
        let accept = thread::spawn({
            let shared = Arc::clone(&shared);
            move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else {
                        return;
                    };
                    let conn = {
                        let mut state = shared.lock();
                        if state.shutdown {
                            return;
                        }
                        state.accepted += 1;
                        state.accepted - 1
                    };
                    // Replies are tiny and sent back to back; without this,
                    // Nagle plus delayed ACK can add tens of milliseconds to
                    // each one.
                    let _ = stream.set_nodelay(true);
                    let shared = Arc::clone(&shared);
                    thread::spawn(move || serve(shared, conn, stream));
                }
            }
        });
        FakeRedis {
            addr,
            shared,
            accept: Some(accept),
        }
    }

    /// The real store, pointed at this fake.
    fn store(&self) -> RedisControlPlaneStore {
        let mut store =
            RedisControlPlaneStore::open_with_namespace(&format!("redis://{}", self.addr), "lanes")
                .expect("Client::open only parses the URL");
        // Production's one-second timeout would end a stall the test is still
        // holding. These tests decide when a stall ends, so a loaded machine
        // cannot race them.
        store.io_timeout = PATIENCE * 3;
        store
    }

    /// Parks every command at `gate`: the server reads it and says nothing
    /// until [`Self::release`].
    fn hold(&self, gate: Gate) {
        self.shared.lock().held.insert(gate);
    }

    fn release(&self, gate: Gate) {
        self.shared.lock().held.remove(&gate);
        self.shared.changed.notify_all();
    }

    /// Makes the next command at `gate` close its connection unanswered.
    fn kill_next(&self, gate: Gate) {
        self.shared.lock().kill_next.insert(gate);
    }

    /// Blocks until a command is parked at `gate`, so the test knows the
    /// store call is genuinely in flight (sent, and unanswered) before it
    /// acts.
    fn wait_until_parked(&self, gate: Gate) {
        let state = self.shared.lock();
        let (_state, timeout) = self
            .shared
            .changed
            .wait_timeout_while(state, PATIENCE, |s| {
                s.parked.get(&gate).copied().unwrap_or(0) == 0
            })
            .unwrap_or_else(|e| e.into_inner());
        assert!(
            !timeout.timed_out(),
            "no command ever parked at {gate:?}: the store never sent it"
        );
    }

    /// The connection that carried the most recent command.
    fn last_conn(&self) -> usize {
        self.shared
            .lock()
            .log
            .last()
            .expect("the fake has seen a command")
            .0
    }

    fn accepted(&self) -> usize {
        self.shared.lock().accepted
    }
}

impl Drop for FakeRedis {
    fn drop(&mut self) {
        self.shared.lock().shutdown = true;
        // Unparks anything a failed test left held, so no thread outlives it.
        self.shared.changed.notify_all();
        // `accept` is blocked in the kernel; a throwaway connection wakes it
        // so it can see `shutdown` and return.
        let _ = TcpStream::connect(self.addr);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
    }
}

/// Runs `f` on its own thread and fails the test if it has not returned
/// within [`PATIENCE`]: a call that should not be waiting on anything must
/// not be seen to wait. The helper thread outlives a failed wait, which is
/// harmless: dropping the [`FakeRedis`] unparks everything.
///
/// Rust note: `'static` and `Send` because the closure moves to another
/// thread that may outlive this function.
fn within<T: Send + 'static>(what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        // The receiver is gone if the wait below already gave up.
        let _ = tx.send(f());
    });
    rx.recv_timeout(PATIENCE)
        .unwrap_or_else(|_| panic!("{what}: still blocked after {PATIENCE:?}"))
}

/// [`within`], for one call on the shared store.
fn store_call<T: Send + 'static>(
    what: &str,
    store: &Arc<RedisControlPlaneStore>,
    call: impl FnOnce(&RedisControlPlaneStore) -> T + Send + 'static,
) -> T {
    let store = Arc::clone(store);
    within(what, move || call(&store))
}

/// One `add_spend`: the flusher's call, with canned arguments.
fn flush(store: &RedisControlPlaneStore) -> Result<u64, StoreError> {
    store.add_spend(
        "chain",
        &TenantId::new("tenant-a"),
        &PeriodKey::for_test("2026-10"),
        5,
        FlushToken {
            node_id: "node-a",
            seq: 1,
        },
    )
}

// ---------------------------------------------------------------------------
// Lanes
// ---------------------------------------------------------------------------

#[test]
fn a_flush_stuck_on_the_spend_lane_does_not_delay_policy_calls() {
    let fake = FakeRedis::start();
    let store = Arc::new(fake.store());

    fake.hold(Gate::SpendFlush);
    let stuck_flush = thread::spawn({
        let store = Arc::clone(&store);
        move || flush(&store)
    });
    fake.wait_until_parked(Gate::SpendFlush);

    // The flush is on the wire and unanswered. Everything a revocation needs
    // still goes through: the write itself, then the poll and the full read
    // that pick it up.
    store_call("revoke_key behind a stuck flush", &store, |s| {
        s.revoke_key(&KeyId::new("key-1"))
    })
    .expect("revoke_key");
    let generation = store_call("policy_generation behind a stuck flush", &store, |s| {
        s.policy_generation()
    })
    .expect("policy_generation");
    assert_eq!(generation, GENERATION);
    let loaded = store_call("load behind a stuck flush", &store, |s| s.load()).expect("load");
    assert_eq!(loaded.keys.len(), 3);

    // The stuck flush then completes normally: nothing was cut off or retried
    // while it waited.
    fake.release(Gate::SpendFlush);
    assert_eq!(stuck_flush.join().expect("flush thread"), Ok(SPEND_TOTAL));
}

#[test]
fn a_load_stuck_on_the_control_lane_does_not_delay_spend_reconciliation() {
    let fake = FakeRedis::start();
    let store = Arc::new(fake.store());

    fake.hold(Gate::PolicyLoad);
    let stuck_load = thread::spawn({
        let store = Arc::clone(&store);
        move || store.load()
    });
    fake.wait_until_parked(Gate::PolicyLoad);

    // The load is on the wire and unanswered. A whole flush cycle still goes
    // through: the sequence seed, the write that returns the global total,
    // and the read that fills a bucket at bind time.
    let tenant = TenantId::new("tenant-a");
    let period = PeriodKey::for_test("2026-10");
    let seq = store_call("last_flush_seq behind a stuck load", &store, {
        let (tenant, period) = (tenant.clone(), period.clone());
        move |s| s.last_flush_seq("chain", &tenant, &period, "node-a")
    })
    .expect("last_flush_seq");
    assert_eq!(seq, LAST_SEQ);
    let total = store_call("add_spend behind a stuck load", &store, flush).expect("add_spend");
    assert_eq!(total, SPEND_TOTAL);
    let stored = store_call("load_spend behind a stuck load", &store, move |s| {
        s.load_spend("chain", &tenant, &period)
    })
    .expect("load_spend");
    assert_eq!(stored, STORED_SPEND);

    fake.release(Gate::PolicyLoad);
    let loaded = stuck_load
        .join()
        .expect("load thread")
        .expect("the released load completes");
    assert_eq!(loaded.keys.len(), 3);
}

#[test]
fn every_store_call_runs_on_the_connection_of_its_tier() {
    let fake = FakeRedis::start();
    let store = fake.store();
    let tenant = TenantId::new("tenant-a");
    let key = StoredKey {
        key_id: KeyId::new("key-1"),
        digest: [1; 32],
        tenant: tenant.clone(),
        revoked: false,
    };
    let period = PeriodKey::for_test("2026-10");
    let node = FlushToken {
        node_id: "node-a",
        seq: 1,
    };

    // Every other call of each tier, as (name, call). A call returns whether
    // the store accepted the fake's canned reply, so one that failed cannot
    // pass as a routing result.
    //
    // Rust note: `Box<dyn Fn>` lets closures with different bodies share one
    // list type; each borrows the fixtures above, hence the `'a`.
    type Call<'a> = (&'a str, Box<dyn Fn() -> bool + 'a>);
    let control_calls: Vec<Call> = vec![
        ("load", Box::new(|| store.load().is_ok())),
        (
            "create_tenant",
            Box::new(|| store.create_tenant(&tenant).is_ok()),
        ),
        (
            "delete_tenant",
            Box::new(|| store.delete_tenant(&tenant).is_ok()),
        ),
        ("put_key", Box::new(|| store.put_key(&key).is_ok())),
        (
            "revoke_key",
            Box::new(|| store.revoke_key(&key.key_id).is_ok()),
        ),
        (
            "set_policy",
            Box::new(|| store.set_policy(&tenant, &ModelAccess::All).is_ok()),
        ),
        (
            "set_budget (set)",
            Box::new(|| store.set_budget(&tenant, Some(&sample_budget())).is_ok()),
        ),
        (
            "set_budget (clear)",
            Box::new(|| store.set_budget(&tenant, None).is_ok()),
        ),
        (
            "put_tenant_credential",
            Box::new(|| store.put_tenant_credential(&sample_credential()).is_ok()),
        ),
        (
            "delete_tenant_credential",
            Box::new(|| store.delete_tenant_credential(&tenant, "openai").is_ok()),
        ),
        (
            "put_rate_card",
            Box::new(|| store.put_rate_card(&sample_rate_card("chain-a")).is_ok()),
        ),
        (
            "put_rate_card_if_absent",
            Box::new(|| {
                store
                    .put_rate_card_if_absent(&sample_rate_card("chain-a"))
                    .is_ok()
            }),
        ),
    ];
    let spend_calls: Vec<Call> = vec![
        (
            "overwrite_spend",
            Box::new(|| store.overwrite_spend("chain", &tenant, &period, 0).is_ok()),
        ),
        (
            "last_flush_seq",
            Box::new(|| {
                store
                    .last_flush_seq("chain", &tenant, &period, "node-a")
                    .is_ok()
            }),
        ),
        (
            "load_spend",
            Box::new(|| store.load_spend("chain", &tenant, &period).is_ok()),
        ),
        (
            "add_spend_batch",
            Box::new(|| {
                let row = SpendDelta {
                    tenant: &tenant,
                    period: &period,
                    delta_micros: 5,
                    seq: 2,
                };
                store
                    .add_spend_batch("chain", "node-a", &[row])
                    .iter()
                    .all(Result::is_ok)
            }),
        ),
        (
            "last_flush_seq_batch",
            Box::new(|| {
                store
                    .last_flush_seq_batch("chain", "node-a", &[(tenant.clone(), period.clone())])
                    .iter()
                    .all(Result::is_ok)
            }),
        ),
        (
            "load_spend_batch",
            Box::new(|| {
                store
                    .load_spend_batch("chain", &[(tenant.clone(), period.clone())])
                    .iter()
                    .all(Result::is_ok)
            }),
        ),
    ];

    // The first call of each tier opens that tier's connection; every other
    // call of the tier must reuse it.
    assert!(store.policy_generation().is_ok());
    let control = fake.last_conn();
    assert!(store.add_spend("chain", &tenant, &period, 5, node).is_ok());
    let spend = fake.last_conn();
    assert_ne!(control, spend, "policy and spend calls shared a connection");

    for (name, call) in &control_calls {
        assert!(call(), "{name}: the store rejected the fake's canned reply");
        assert_eq!(
            fake.last_conn(),
            control,
            "{name} must use the control connection"
        );
    }
    for (name, call) in &spend_calls {
        assert!(call(), "{name}: the store rejected the fake's canned reply");
        assert_eq!(
            fake.last_conn(),
            spend,
            "{name} must use the spend connection"
        );
    }
    assert_eq!(
        fake.accepted(),
        2,
        "one connection per lane, opened on first use and never replaced"
    );
}

#[test]
fn a_failed_call_resets_only_its_own_lane_and_that_lane_reconnects() {
    let fake = FakeRedis::start();
    let store = fake.store();
    let tenant = TenantId::new("tenant-a");
    let period = PeriodKey::for_test("2026-10");

    store.policy_generation().expect("policy_generation");
    let control = fake.last_conn();
    store
        .load_spend("chain", &tenant, &period)
        .expect("load_spend");
    let spend = fake.last_conn();
    assert_ne!(control, spend);

    // The server hangs up on a flush. That call fails and drops the spend
    // connection; the control connection must not notice.
    fake.kill_next(Gate::SpendFlush);
    assert!(flush(&store).is_err(), "a hung-up flush must fail");
    store.policy_generation().expect("policy_generation");
    assert_eq!(
        fake.last_conn(),
        control,
        "a spend failure must not reset the control connection"
    );
    assert_eq!(fake.accepted(), 2);

    // The spend lane reconnects on its next call, and only the spend lane.
    assert_eq!(flush(&store), Ok(SPEND_TOTAL));
    let spend_again = fake.last_conn();
    assert!(
        spend_again != spend && spend_again != control,
        "the spend lane must reconnect on a fresh connection"
    );
    assert_eq!(fake.accepted(), 3);

    // And the same the other way round: a failed load resets the control
    // connection and leaves the spend one alone.
    fake.kill_next(Gate::PolicyLoad);
    assert!(store.load().is_err(), "a hung-up load must fail");
    store
        .load_spend("chain", &tenant, &period)
        .expect("load_spend");
    assert_eq!(
        fake.last_conn(),
        spend_again,
        "a control failure must not reset the spend connection"
    );
    assert_eq!(fake.accepted(), 3);
    store.policy_generation().expect("policy_generation");
    let control_again = fake.last_conn();
    assert!(
        control_again != control && control_again != spend_again,
        "the control lane must reconnect on a fresh connection"
    );
    assert_eq!(fake.accepted(), 4);
}

// ---------------------------------------------------------------------------
// The load log line
// ---------------------------------------------------------------------------

/// The load's cost is exported, not only logged: two loads read back from
/// the Prometheus scrape as two duration samples, and a size and row count
/// equal to ONE load's (they are gauges of the last load, so a second load of
/// the same state must not add to them).
#[test]
fn a_load_exports_its_duration_and_size_as_stats() {
    let fake = FakeRedis::start();
    let control = proxy_observability::stats::StatsControl::new(1);
    let store = fake.store().with_load_stats(control.registry(), "chain-a");

    store.load().expect("first load");
    store.load().expect("second load");

    let scrape = proxy_observability::stats::prometheus_render::render(&control.registry());
    let sample = |prefix: &str| -> String {
        scrape
            .lines()
            .find(|line| line.starts_with(prefix) && line.contains(r#"scope="chain-a""#))
            .unwrap_or_else(|| panic!("no {prefix} sample in:\n{scrape}"))
            .rsplit(' ')
            .next()
            .expect("a sample line ends with its value")
            .to_string()
    };
    let rows = &fake.shared.rows;
    let row_count = rows.tenants.len()
        + [
            &rows.keys,
            &rows.policies,
            &rows.budgets,
            &rows.credentials,
            &rows.rate_cards,
        ]
        .iter()
        .map(|hash| hash.len())
        .sum::<usize>();
    assert_eq!(
        sample("envoy_llmproxy_control_plane_load_payload_bytes"),
        rows.payload_bytes().to_string()
    );
    assert_eq!(
        sample("envoy_llmproxy_control_plane_load_rows"),
        row_count.to_string()
    );
    assert_eq!(
        sample("envoy_llmproxy_control_plane_load_duration_count"),
        "2"
    );
}

#[test]
fn a_load_logs_its_duration_and_size_and_never_row_content() {
    let fake = FakeRedis::start();
    let store = fake.store();

    let (capture, guard) = Capture::start();
    let loaded = store.load().expect("the fake serves a well-formed load");
    drop(guard);
    assert_eq!(loaded.keys.len(), 3, "the rows decoded as served");
    assert_eq!(
        loaded.rate_cards.len(),
        3,
        "the unreadable rate card row is skipped, not fatal"
    );

    let events = capture.events();
    let load_lines: Vec<_> = events
        .iter()
        .filter(|(_, fields)| fields.contains_key("payload_bytes"))
        .collect();
    assert_eq!(load_lines.len(), 1, "one log line per load: {events:?}");
    let (level, fields) = load_lines[0];
    assert_eq!(*level, tracing::Level::INFO);

    // A different count per kind, so a count reported under the wrong name
    // cannot pass.
    for (field, want) in [
        ("tenants", "2"),
        ("keys", "3"),
        ("policies", "1"),
        ("budgets", "1"),
        ("tenant_credentials", "1"),
        ("rate_cards", "4"),
    ] {
        assert_eq!(fields[field], want, "{field}");
    }
    assert_eq!(
        fields["payload_bytes"],
        fake.shared.rows.payload_bytes().to_string()
    );
    // Durations depend on the machine; they only have to be there.
    assert!(fields.contains_key("duration_ms") && fields.contains_key("fetch_ms"));

    // Counts and lengths only. The rows hold key digests and a sealed
    // credential, so a field that is not a plain number is a field that could
    // be carrying one.
    for (name, value) in fields.iter().filter(|(name, _)| *name != "message") {
        assert!(
            value.parse::<u64>().is_ok(),
            "field {name} is not a number: {value}"
        );
    }
}

// ---------------------------------------------------------------------------
// Rate cards: the card and the generation bump travel together
// ---------------------------------------------------------------------------

impl FakeRedis {
    /// The commands the server read after the first `skip`, as
    /// `(connection, arguments)`.
    fn wire_since(&self, skip: usize) -> Vec<(usize, Vec<String>)> {
        self.shared.lock().wire[skip..].to_vec()
    }

    fn wire_len(&self) -> usize {
        self.shared.lock().wire.len()
    }
}

#[test]
fn a_rate_card_and_its_generation_bump_are_one_transaction_on_the_control_connection() {
    let fake = FakeRedis::start();
    let store = fake.store();
    // Open the control connection first so the write below is the only thing
    // after the mark.
    store.policy_generation().expect("policy_generation");
    let control = fake.last_conn();
    let mark = fake.wire_len();

    let card = sample_rate_card("chain-a");
    store.put_rate_card(&card).expect("put_rate_card");

    // Exactly MULTI, HSET, INCR, EXEC, and nothing in between: Redis applies
    // a transaction as a unit, so a poller cannot see the new stamp without
    // the card, and a connection that dies before EXEC leaves neither. An
    // HSET and an INCR sent as two plain commands would pass every other test
    // here and lose that property.
    let sent = fake.wire_since(mark);
    assert!(
        sent.iter().all(|(conn, _)| *conn == control),
        "the whole write must travel on the control connection: {sent:?}"
    );
    let commands: Vec<&[String]> = sent.iter().map(|(_, args)| args.as_slice()).collect();
    assert_eq!(commands.len(), 4, "MULTI, HSET, INCR, EXEC: {commands:?}");
    assert_eq!(commands[0], ["MULTI"]);
    assert_eq!(commands[1][..3], ["HSET", "lanes:rate_cards", "chain-a"]);
    assert_eq!(commands[2], ["INCR", "lanes:generation"]);
    assert_eq!(commands[3], ["EXEC"]);

    // The row that went out is the card, and reads back as the same card.
    assert_eq!(
        decode_rate_card_row("chain-a", commands[1][3].as_bytes()),
        Some(card)
    );
}

#[test]
fn seeding_a_rate_card_is_one_script_that_names_the_card_and_the_generation() {
    let fake = FakeRedis::start();
    let store = fake.store();
    store.policy_generation().expect("policy_generation");
    let mark = fake.wire_len();

    let card = sample_rate_card("chain-a");
    assert_eq!(store.put_rate_card_if_absent(&card), Ok(true));

    // One EVALSHA carrying both keys, and no separate HSETNX/INCR: the check,
    // the write and the bump are one atomic step on the server.
    let sent = fake.wire_since(mark);
    assert_eq!(sent.len(), 1, "one script call and nothing else: {sent:?}");
    let args = &sent[0].1;
    assert_eq!(args[0], "EVALSHA");
    assert_eq!(args[2], "2", "two keys");
    assert_eq!(args[3], "lanes:rate_cards");
    assert_eq!(args[4], "lanes:generation");
    assert_eq!(args[5], "chain-a");
    assert_eq!(
        decode_rate_card_row("chain-a", args[6].as_bytes()),
        Some(card)
    );

    // The script's `0` means a card was already there.
    fake.shared.lock().rate_card_script_replies.push_back(0);
    assert_eq!(
        store.put_rate_card_if_absent(&sample_rate_card("chain-a")),
        Ok(false)
    );
}

// ---------------------------------------------------------------------------
// Spend: pipelines and expiry
// ---------------------------------------------------------------------------

impl FakeRedis {
    /// How many times the server has read `command` so far.
    fn count(&self, command: &str) -> usize {
        self.shared
            .lock()
            .log
            .iter()
            .filter(|(_, name)| name == command)
            .count()
    }
}

/// An accumulator over the real store, pointed at the fake.
fn accumulator_over(fake: &FakeRedis) -> crate::spend::SpendAccumulator {
    crate::spend::SpendAccumulator::new(
        "chain".into(),
        Arc::new(fake.store()),
        Period::Daily,
        "node-a".into(),
    )
}

/// Review H5's boot: 20k keys used to cost one blocking read per row before
/// the listener could bind (80k round trips). The rows now go out as
/// pipelines of a thousand, each led by one `SCRIPT LOAD`, so counting
/// those counts round trips.
///
/// Mutation: set `SPEND_PIPELINE_ROWS` to 1; the round trips equal the
/// rows again.
#[test]
fn a_boot_prefetch_of_20k_keys_reads_in_pipelines_of_a_thousand_rows() {
    let fake = FakeRedis::start();
    let accumulator = Arc::new(accumulator_over(&fake));
    let keys: Vec<KeyId> = (0..20_000)
        .map(|i| KeyId::new(format!("key-{i}")))
        .collect();

    let prefetched = {
        let (accumulator, keys) = (Arc::clone(&accumulator), keys.clone());
        within("prefetch", move || {
            accumulator.prepare_request_workers(&keys)
        })
    };
    assert_eq!(prefetched, Ok(()));

    // Today and tomorrow, daily and monthly: 3 distinct rows per key, or 4
    // on the last day of a month.
    let reads = fake.count("GET");
    assert!(
        reads == 60_000 || reads == 80_000,
        "one read per distinct row: {reads}"
    );
    assert_eq!(
        fake.count("SCRIPT"),
        reads / 1000,
        "one pipeline per 1000 rows"
    );
    // The rows landed in memory with the store's total, so serving reads none.
    let today = Period::Daily.key_for_now();
    assert_eq!(
        accumulator.current_total_key(&keys[19_999], &today),
        STORED_SPEND
    );
    assert_eq!(
        fake.count("GET"),
        reads,
        "a prefetched row is never re-read"
    );
}

/// One flush tick: the sequence seeds go out as one pipeline and the
/// deliveries as another, and every delivery carries its period's expiry.
#[test]
fn a_flush_pipelines_its_deliveries_and_each_carries_its_periods_expiry() {
    let fake = FakeRedis::start();
    let accumulator = accumulator_over(&fake);
    accumulator
        .prepare_request_workers(&[])
        .expect("nothing to read");
    let now = chrono::Utc::now();
    for tenant in ["tenant-a", "tenant-b", "tenant-c"] {
        accumulator.record(
            &TenantId::new(tenant),
            now,
            Period::Daily,
            crate::spend::Charge::Priced(MicroUsd::from_micros(7)),
            None,
            None,
        );
    }
    let mark = fake.wire_len();

    accumulator
        .flush_now()
        .expect("the fake accepts every delivery");

    let sent: Vec<Vec<String>> = fake.wire_since(mark).into_iter().map(|(_, a)| a).collect();
    let names: Vec<&str> = sent.iter().map(|args| args[0].as_str()).collect();
    assert_eq!(
        names,
        ["SCRIPT", "HGET", "HGET", "HGET", "SCRIPT", "EVALSHA", "EVALSHA", "EVALSHA"],
        "two pipelines: the seeds, then the deliveries"
    );
    // The day after `now`, at midnight UTC, plus the 32-day retention.
    let expires_at = (now.date_naive() + chrono::Duration::days(1 + 32))
        .and_hms_opt(0, 0, 0)
        .expect("midnight exists")
        .and_utc()
        .timestamp()
        .to_string();
    for args in &sent[5..] {
        // EVALSHA sha 2 spend_key seq_key node seq delta expires_at
        assert_eq!(args[6], (LAST_SEQ + 1).to_string(), "seeded from the store");
        assert_eq!(args[7], "7");
        assert_eq!(args[8], expires_at, "{args:?}");
    }
}

/// `SET` drops a key's expiry, so the operator's correction restates it in
/// the same transaction; without that the corrected row would never expire.
#[test]
fn an_operator_overwrite_keeps_the_rows_expiry() {
    let fake = FakeRedis::start();
    let store = fake.store();
    let period = Period::Monthly.key_for_now();
    store.policy_generation().expect("policy_generation");
    let mark = fake.wire_len();

    store
        .overwrite_spend("chain", &TenantId::new("tenant-a"), &period, 0)
        .expect("the fake accepts the write");

    let sent: Vec<Vec<String>> = fake.wire_since(mark).into_iter().map(|(_, a)| a).collect();
    let names: Vec<&str> = sent.iter().map(|args| args[0].as_str()).collect();
    assert_eq!(names, ["MULTI", "SET", "EXPIREAT", "EXEC"]);
    assert_eq!(sent[2][1], sent[1][1], "the expiry is on the row just set");
    assert_eq!(
        sent[2][2],
        spend_expires_at(&period).to_string(),
        "and it is the period's"
    );
}
