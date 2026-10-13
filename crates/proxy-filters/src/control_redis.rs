//! [`RedisControlPlaneStore`], the shared, Redis-backed
//! [`crate::control::ControlPlaneStore`]. `internal-docs/adr/0006-shared-state-tiers.md`
//! is normative for everything this file implements; read its §§1-2 and 7
//! before touching [`RedisControlPlaneStore::add_spend`] or
//! [`RedisControlPlaneStore::policy_generation`].
//!
//! # Why this file, and what it must NOT do
//!
//! `control.rs`'s `RedbControlPlaneStore` is the embedded, single-process
//! default. This is its multi-replica twin: same trait, the same row shapes
//! (`EncodedKeyRow`/`EncodedModelAccess`/`EncodedTenantBudget`, and
//! `encode_json`/`decode_json`/`store_err`, all made `pub(crate)` in
//! `control.rs` for exactly this file to reuse rather than duplicate), a
//! different backend. ADR-0006 §6 calls this "one code path; the difference
//! is the store, and the bounds" -- this module must not grow behaviour
//! `ControlPlaneStore`'s own trait doc does not already require, or the two
//! stores stop being interchangeable.
//!
//! **Sync connections only.** `ControlPlaneStore` is a synchronous trait
//! because nothing on the request path is meant to call it -- only the
//! control runtime's policy poller and [`crate::spend::SpendAccumulator`]'s
//! flusher thread do, both off the hot path (ADR-0005). This crate therefore
//! depends on `redis` with its default (sync) transport and no
//! `tokio-comp`/`aio` feature -- see the workspace `Cargo.toml`'s `redis`
//! entry. Threading an async runtime through a trait that has none would buy
//! nothing for a connection nothing on the hot path ever holds. There are
//! two of them, one per [`Lane`], so those two callers never queue behind each
//! other; see [`RedisControlPlaneStore`].
//!
//! # Key layout
//!
//! ```text
//! {ns}:tenants                              SET of tenant id
//! {ns}:keys                                 HASH key_id -> encode_json(EncodedKeyRow)
//! {ns}:policies                             HASH tenant -> encode_json(EncodedModelAccess)
//! {ns}:budgets                              HASH tenant -> encode_json(EncodedTenantBudget)
//! {ns}:tenant_credentials                   HASH <esc(tenant)>|<esc(provider)> -> encode_json(EncodedTenantCredentialRow)
//! {ns}:rate_cards                           HASH chain (the usage filter's stat_prefix) -> encode_json(EncodedRateCardRow)
//! {ns}:generation                           STRING, INCR
//! {ns}:spend:{<prefix>|<tenant>|<period>}   STRING, micros
//! {ns}:seq:{<prefix>|<tenant>|<period>}     HASH node_id -> highest accepted seq
//! ```
//!
//! `{ns}` is a constructor parameter ([`RedisControlPlaneStore::open_with_namespace`],
//! defaulting to [`DEFAULT_NAMESPACE`] via [`RedisControlPlaneStore::open`]) so
//! two deployments can share one Redis. The braces around
//! `<prefix>|<tenant>|<period>` are **literal** -- see
//! [`RedisControlPlaneStore::hash_tag`]'s doc for why they are a Redis
//! Cluster hash tag, not decoration, and [`escape_component`]'s doc for why
//! the three components must be escaped before they are joined.
//!
//! The `rate_cards` field is the chain name as it is: one component, so there
//! is no separator to protect. The row holds the pricing document as an opaque
//! string, which this store never parses. Writing a card and bumping
//! `{ns}:generation` are one `MULTI`/`EXEC` (replace) or one script (seed if
//! absent), so a poller never sees the stamp move without the card.
//!
//! The `tenant_credentials` field is the escaped tenant and the escaped
//! provider joined by `|`. `escape_component` rewrites every `|` inside a
//! component, so the first `|` in a field is always the separator and no
//! two (tenant, provider) pairs share a field. The row value carries
//! ciphertext only; this store never decrypts (ADR-0007 decision 2).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use redis::{Client, Connection, Script};

use crate::auth::{KeyId, TenantId};
use crate::control::decode_tenant_credential_row;
use crate::control::{
    decode_json, decode_rate_card_row, encode_json, store_err, ControlPlaneStore, EncodedKeyRow,
    EncodedModelAccess, EncodedRateCardRow, EncodedTenantBudget, EncodedTenantCredentialRow,
    FlushToken, StoreError, StoredControlPlane, StoredKey, StoredRateCard, StoredTenantCredential,
    SPEND_SCHEMA_VERSION, TENANT_CREDENTIALS_SCHEMA_VERSION,
};
use crate::model_authz::ModelAccess;
use crate::spend::{PeriodKey, TenantBudget};

/// Namespace prefix used when a caller does not supply one -- see
/// [`RedisControlPlaneStore::open`].
const DEFAULT_NAMESPACE: &str = "llmproxy";

/// How long a connect, a read, or a write may block, on either [`Lane`]. A
/// store that cannot answer within this fails the one call and reconnects on
/// the next, rather than holding its lane indefinitely.
const IO_TIMEOUT: Duration = Duration::from_secs(1);

/// Which of the store's two connections a call runs on. Every trait method
/// names one, so a slow call can only ever queue behind calls of its own kind.
///
/// Rust note: a closed `enum` rather than, say, a `HashMap` of connections
/// keyed by a string: the set of lanes is fixed, so a `match` over it (in
/// [`RedisControlPlaneStore::with_connection`]) is checked by the compiler to
/// give every lane a connection, and a typo at a call site cannot compile.
#[derive(Clone, Copy, Debug)]
enum Lane {
    /// Tier 2 (ADR-0006 §1): the generation poll, `load`, and every admin
    /// write. A revoked key reaches this replica through a call on this lane,
    /// so nothing slow may be allowed to queue ahead of it.
    Control,
    /// Tier 3: spend reconciliation. `add_spend` (one script call per bucket,
    /// in sequence), the `last_flush_seq` that seeds it, the `load_spend`
    /// reads that fill buckets at bind time, and the operator's
    /// `overwrite_spend`.
    Spend,
}

/// [`ControlPlaneStore::add_spend`]'s Lua script, verbatim from ADR-0006
/// §2's worked example.
///
/// # Why a script, not a `MULTI`/`EXEC` pipeline
///
/// The dedup decision (`seq <= last`) is a READ the WRITE depends on --
/// `MULTI` queues commands blind, without ever handing the queuing code the
/// read's value, so there is nowhere in a pipeline to put the `if`.
/// `WATCH`/retry could express the branch, but costs a round trip PER RETRY
/// attempt under contention; a script is ONE round trip and atomic by
/// construction, because Redis runs an entire script as a single command --
/// no other client's command can interleave partway through it. This is the
/// same reasoning [`REVOKE_KEY_LUA`] uses for `revoke_key`, and the same
/// property `RedbControlPlaneStore::add_spend`'s doc names for why it needs
/// ONE write transaction rather than a read transaction plus a write one.
///
/// `KEYS[1]` = the spend total key, `KEYS[2]` = the per-writer sequence
/// hash, `ARGV[1]` = `token.node_id`, `ARGV[2]` = `token.seq`, `ARGV[3]` =
/// `delta_micros`. Dedup state lives in `KEYS[2]`, a HASH keyed by
/// `ARGV[1]` (the node id) -- see [`FlushToken`]'s doc for why keying it on
/// `seq` alone loses one replica's spend the instant two replicas emit the
/// same sequence number.
const ADD_SPEND_LUA: &str = r#"
local last = tonumber(redis.call('HGET', KEYS[2], ARGV[1]) or '0')
local seq = tonumber(ARGV[2])
if seq <= last then
  return tonumber(redis.call('GET', KEYS[1]) or '0')
end
redis.call('HSET', KEYS[2], ARGV[1], ARGV[2])
return redis.call('INCRBY', KEYS[1], ARGV[3])
"#;

/// [`ControlPlaneStore::revoke_key`]'s Lua script.
///
/// # Why this needs a script too, and why it is not just an existence check
///
/// `revoke_key` must (a) return [`StoreError::NotFound`] and write nothing
/// for an unknown `key_id`, and (b) flip `revoked` to `true` on the SAME row
/// it just confirmed exists, with nothing else able to observe -- or
/// interleave with -- the gap between the check and the write.
/// `RedbControlPlaneStore::revoke_key` gets this for free because its read
/// and its write share one `redb` write transaction. A plain `HGET` in Rust
/// followed by a separate `HSET` would reopen exactly that gap: a `put_key`
/// racing between the two could have its update silently overwritten by a
/// stale copy this script never saw.
///
/// The row is stored as `encode_json::<EncodedKeyRow>` bytes (see the module
/// doc's key layout), so the read-modify-write has to happen at the JSON
/// level, not the byte level -- this uses `cjson`, bundled in every Redis
/// Lua sandbox, rather than parsing JSON in Rust and shipping the whole
/// rewritten row as an argument (which would still race: the row could have
/// changed between a Rust-side read and this script's write). `KEYS[1]` =
/// the keys hash, `KEYS[2]` = the generation counter, `ARGV[1]` = `key_id`.
/// Returns `0` (not found, nothing written) or `1` (revoked, and the
/// generation bumped in the same script invocation).
const REVOKE_KEY_LUA: &str = r#"
local raw = redis.call('HGET', KEYS[1], ARGV[1])
if not raw then
  return 0
end
local row = cjson.decode(raw)
row['revoked'] = true
redis.call('HSET', KEYS[1], ARGV[1], cjson.encode(row))
redis.call('INCR', KEYS[2])
return 1
"#;

// Ownership, tombstone checks, write, and generation bump share one Redis transaction.
const PUT_KEY_LUA: &str = r#"
local raw = redis.call('HGET', KEYS[1], ARGV[1])
local next = cjson.decode(ARGV[2])
if raw then
  local previous = cjson.decode(raw)
  local version = previous['schema_version'] or 1
  if version ~= 1 and version ~= 2 then return -3 end
  if previous['tenant'] ~= next['tenant'] then return -1 end
  if previous['revoked'] then
    if not next['revoked'] then return -2 end
    for i = 1, #previous['digest'] do
      if previous['digest'][i] ~= next['digest'][i] then return -2 end
    end
  end
end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
redis.call('INCR', KEYS[2])
return 1
"#;

/// Deletes one tenant credential field and bumps the generation in one
/// script, so a missing field returns `0` with no bump. `KEYS[1]` = the
/// credentials hash, `KEYS[2]` = the generation counter, `ARGV[1]` = field.
const DELETE_TENANT_CREDENTIAL_LUA: &str = r#"
if redis.call('HDEL', KEYS[1], ARGV[1]) == 0 then
  return 0
end
redis.call('INCR', KEYS[2])
return 1
"#;

/// `delete_tenant` as one script, so the tenant's credential rows go in the
/// same atomic write as the rest (the trait requires it). The credential
/// fields are `<esc(tenant)>|<esc(provider)>`, so the prefix
/// `<esc(tenant)>|` matches exactly that tenant: an escaped tenant contains
/// no `|`. `KEYS` = tenants, policies, budgets, credentials, generation.
/// `ARGV[1]` = tenant, `ARGV[2]` = credential field prefix.
const DELETE_TENANT_LUA: &str = r#"
redis.call('SREM', KEYS[1], ARGV[1])
redis.call('HDEL', KEYS[2], ARGV[1])
redis.call('HDEL', KEYS[3], ARGV[1])
local prefix = ARGV[2]
for _, field in ipairs(redis.call('HKEYS', KEYS[4])) do
  if string.sub(field, 1, #prefix) == prefix then
    redis.call('HDEL', KEYS[4], field)
  end
end
redis.call('INCR', KEYS[5])
return 1
"#;

/// [`ControlPlaneStore::put_rate_card_if_absent`] as one script: `HSETNX`
/// writes the field only if it does not exist and says which happened, and the
/// generation is bumped only on the write. `KEYS[1]` = the rate cards hash,
/// `KEYS[2]` = the generation counter, `ARGV[1]` = the chain, `ARGV[2]` = the
/// row. Returns `1` (written and bumped) or `0` (a row was already there:
/// nothing written, no bump).
///
/// A script rather than a pipeline for the reason [`ADD_SPEND_LUA`] gives: the
/// bump depends on what `HSETNX` returned, and a `MULTI` block cannot branch on
/// a reply it has not seen. Unconditional replacement
/// ([`ControlPlaneStore::put_rate_card`]) has no such dependency and stays a
/// plain `MULTI`/`EXEC`.
const PUT_RATE_CARD_IF_ABSENT_LUA: &str = r#"
if redis.call('HSETNX', KEYS[1], ARGV[1], ARGV[2]) == 0 then
  return 0
end
redis.call('INCR', KEYS[2])
return 1
"#;

/// Percent-encodes the four bytes that would otherwise let two DIFFERENT
/// `(stat_prefix, tenant, period)` triples build the SAME Redis key: `%`
/// itself (so the encoding cannot be ambiguous), `|` (the delimiter
/// [`RedisControlPlaneStore::hash_tag`] joins components with), and `{`/`}`
/// (Redis Cluster hash-tag delimiters -- an unescaped `}` inside a component
/// would close the hash tag early and route the key to the wrong slot,
/// independent of the collision hazard below).
///
/// # Why this matters: a collision here merges two tenants' spend
///
/// `stat_prefix`, tenant, and period are all operator-supplied strings.
/// Without escaping, `("a|b", "c", "d")` and `("a", "b|c", "d")` would both
/// join to the literal string `a|b|c|d` and silently become the SAME spend
/// row -- two unrelated tenants (or filter chains) sharing one budget. See
/// this module's `escaping_prevents_a_collision_between_differently_split_components`
/// test.
///
/// Rust note: escaping byte-by-byte rather than char-by-char is safe here
/// specifically because every byte this function rewrites (`%`, `|`, `{`,
/// `}`) is ASCII and therefore a complete UTF-8 code point on its own --
/// none of them can appear as a continuation byte of a multi-byte sequence,
/// so leaving every other byte untouched can never split one apart.
/// `String::from_utf8` on the result cannot fail as a consequence, but this
/// still checks (`.expect`) rather than assuming it silently -- "cannot
/// fail" here is an argument about this function's own logic, not a
/// language guarantee, and `unsafe` (denied workspace-wide) is not on the
/// table as a shortcut around checking it.
fn escape_component(raw: &str) -> String {
    let mut out = Vec::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'%' | b'|' | b'{' | b'}' => {
                out.push(b'%');
                out.extend_from_slice(format!("{byte:02X}").as_bytes());
            }
            other => out.push(other),
        }
    }
    String::from_utf8(out)
        .expect("escape_component only ever rewrites single-byte ASCII characters")
}

/// Inverse of [`escape_component`]. `None` on a malformed `%XX` sequence or
/// non-UTF-8 result; the caller turns that into a load error.
fn unescape_component(escaped: &str) -> Option<String> {
    let raw = escaped.as_bytes();
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' {
            let hex = std::str::from_utf8(raw.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Persistent, shared [`ControlPlaneStore`] backed by Redis -- the
/// multi-replica counterpart to [`crate::control::RedbControlPlaneStore`].
/// Built on composable (additive) spend writes and the policy generation
/// stamp, both of which this store's [`Self::add_spend`] and
/// [`Self::policy_generation`] exist to serve.
///
/// # Two connections (one per [`Lane`]), `std::sync::Mutex`-guarded, reconnected on failure
///
/// Rust note: the same interior-mutability shape `InMemoryControlPlaneStore`
/// uses (`&self` writes, a `Mutex` inside) -- but for a different reason.
/// There, the mutex guards actual mutable state; here it only ever guards
/// ONE `redis::Connection` per lane, because a sync `redis-rs` `Connection`
/// is not safe to share across threads on its own (nothing stops two threads
/// from interleaving their bytes on the same socket). Every store method
/// borrows its lane's connection for exactly the duration of its own round
/// trip and never holds the lock across a call into another method -- see
/// [`Self::with_connection`].
///
/// # Why two: policy calls and spend calls must not queue behind each other
///
/// The policy poller (`policy_generation`, `load`, and the admin writes) and
/// the spend flusher (`add_spend`, once per bucket, in sequence) share this
/// one store, and their calls differ by orders of magnitude in how long they
/// hold a connection. On a single connection each had to wait its turn behind
/// the other: a revocation pickup behind a long flush, a reconciliation
/// behind a `load` that reads the whole policy state in one `MULTI`/`EXEC`,
/// and, when Redis was slow, either one behind a full [`IO_TIMEOUT`] per
/// call. ADR-0006 §4 keeps the policy poll and spend reconciliation on
/// separate intervals because they answer different questions and one must
/// not set the other's pace; separate connections give them the same
/// independence at the I/O level.
///
/// A Redis that stops answering still stalls both lanes, since both talk to
/// it. What a lane buys is that a slow or long CALL on one cannot delay calls
/// on the other, and that an error on one (which drops that lane's
/// connection, see [`Self::with_connection`]) leaves the other's connection
/// alone. The cost is that a replica holds up to two Redis connections.
pub struct RedisControlPlaneStore {
    client: Client,
    /// The [`Lane::Control`] connection, opened on first use.
    control_conn: Mutex<Option<Connection>>,
    /// The [`Lane::Spend`] connection, opened on first use.
    spend_conn: Mutex<Option<Connection>>,
    /// Connect, read, and write timeout of both lanes: [`IO_TIMEOUT`] in
    /// production. A field rather than the constant read in place so the
    /// lane tests can hold a call in flight far longer than that without
    /// racing the timeout.
    io_timeout: Duration,
    namespace: String,
    add_spend_script: Script,
    revoke_key_script: Script,
    delete_tenant_credential_script: Script,
    delete_tenant_script: Script,
    put_rate_card_if_absent_script: Script,
}

impl RedisControlPlaneStore {
    /// Connects to `url` (e.g. `redis://127.0.0.1:6379`) under the default
    /// namespace [`DEFAULT_NAMESPACE`]. Opening performs no I/O of its own --
    /// `redis::Client::open` only parses the URL -- so a Redis outage at
    /// construction time is not observed until the first real call, at
    /// which point it reports [`StoreError::Unavailable`] exactly like every
    /// other failure this store has, rather than a special "never
    /// connected" case a caller would have to handle differently.
    pub fn open(url: &str) -> Result<Self, StoreError> {
        Self::open_with_namespace(url, DEFAULT_NAMESPACE)
    }

    /// As [`Self::open`], but under an explicit `namespace` -- so two
    /// deployments (or, in this module's own integration tests, two
    /// concurrent test runs) can share one Redis without their keys
    /// colliding. See the module doc's key layout.
    pub fn open_with_namespace(
        url: &str,
        namespace: impl Into<String>,
    ) -> Result<Self, StoreError> {
        let client = Client::open(url).map_err(store_err)?;
        Ok(RedisControlPlaneStore {
            client,
            control_conn: Mutex::new(None),
            spend_conn: Mutex::new(None),
            io_timeout: IO_TIMEOUT,
            namespace: namespace.into(),
            add_spend_script: Script::new(ADD_SPEND_LUA),
            revoke_key_script: Script::new(REVOKE_KEY_LUA),
            delete_tenant_credential_script: Script::new(DELETE_TENANT_CREDENTIAL_LUA),
            delete_tenant_script: Script::new(DELETE_TENANT_LUA),
            put_rate_card_if_absent_script: Script::new(PUT_RATE_CARD_IF_ABSENT_LUA),
        })
    }

    /// Runs `f` against `lane`'s live connection, opening one first if that
    /// lane holds none, and drops the connection on ANY error `f` returns so
    /// the NEXT call on that lane reopens fresh rather than retrying a socket
    /// that may already be dead. The other lane's connection is never touched:
    /// it has its own lock and its own reconnect state.
    ///
    /// # Why "any error", not just ones that look like a dead socket
    ///
    /// `redis-rs` exposes ways to classify a `RedisError` (e.g. "was this a
    /// connection problem"), but misclassifying even one error kind as "not
    /// a connection problem" leaves a broken connection cached for every
    /// subsequent call to fail against, silently, until something external
    /// restarts the process. Reconnecting unconditionally costs one extra
    /// TCP handshake on the rare non-connection error (say, a corrupted
    /// value that fails to decode) and fixes itself either way -- guessing
    /// which errors "deserve" a reconnect is exactly the kind of
    /// classification a bug can hide inside, the same shape AGENTS.md "Build And Test"
    /// describes for "acting on the obvious symptom instead of
    /// the actual cause".
    fn with_connection<T>(
        &self,
        lane: Lane,
        f: impl FnOnce(&mut Connection) -> redis::RedisResult<T>,
    ) -> Result<T, StoreError> {
        let slot = match lane {
            Lane::Control => &self.control_conn,
            Lane::Spend => &self.spend_conn,
        };
        let mut guard = slot
            .lock()
            .expect("redis control-plane store connection mutex poisoned");
        if guard.is_none() {
            let timeout = self.io_timeout;
            let conn = self
                .client
                .get_connection_with_timeout(timeout)
                .map_err(store_err)?;
            conn.set_read_timeout(Some(timeout)).map_err(store_err)?;
            conn.set_write_timeout(Some(timeout)).map_err(store_err)?;
            *guard = Some(conn);
        }
        // Rust note: `.as_mut()` on the `Option`, not `.take()` -- a
        // successful call must leave the connection in the `Mutex` for the
        // NEXT call to reuse; only the error arm below clears it.
        let conn = guard
            .as_mut()
            .expect("connection was just ensured present above");
        match f(conn) {
            Ok(value) => Ok(value),
            Err(err) => {
                *guard = None;
                Err(store_err(err))
            }
        }
    }

    fn tenants_key(&self) -> String {
        format!("{}:tenants", self.namespace)
    }

    fn keys_key(&self) -> String {
        format!("{}:keys", self.namespace)
    }

    fn policies_key(&self) -> String {
        format!("{}:policies", self.namespace)
    }

    fn budgets_key(&self) -> String {
        format!("{}:budgets", self.namespace)
    }

    fn tenant_credentials_key(&self) -> String {
        format!("{}:tenant_credentials", self.namespace)
    }

    fn rate_cards_key(&self) -> String {
        format!("{}:rate_cards", self.namespace)
    }

    /// Hash field for one credential row: `<esc(tenant)>|<esc(provider)>`.
    fn credential_field(tenant: &str, provider: &str) -> String {
        format!(
            "{}|{}",
            escape_component(tenant),
            escape_component(provider)
        )
    }

    fn generation_key(&self) -> String {
        format!("{}:generation", self.namespace)
    }

    /// Joins the three escaped spend-row components with `|`. Not a full key
    /// on its own -- [`Self::spend_key`] and [`Self::seq_key`] each wrap the
    /// result in the literal `{...}` the module doc's key layout shows.
    ///
    /// # The braces are a Redis Cluster hash tag, not decoration
    ///
    /// [`Self::add_spend`] touches the spend key AND the seq key in ONE Lua
    /// script, and Redis Cluster requires every key a script touches to
    /// hash to the SAME slot (`EVAL`/`EVALSHA` on a cluster reject a script
    /// whose `KEYS` span slots, with a `CROSSSLOT` error). Redis Cluster
    /// hashes only the substring between the first `{` and the next `}` in
    /// a key when one is present -- so wrapping the IDENTICAL
    /// `hash_tag(...)` output in both `spend_key` and `seq_key` guarantees
    /// they land on the same slot no matter what the rest of each key name
    /// is. Without the braces this works today against a single node and
    /// fails on a cluster, which is the exact deployment this store exists for.
    fn hash_tag(stat_prefix: &str, tenant: &str, period: &str) -> String {
        format!(
            "{}|{}|{}",
            escape_component(stat_prefix),
            escape_component(tenant),
            escape_component(period)
        )
    }

    fn spend_key(&self, stat_prefix: &str, tenant: &str, period: &str) -> String {
        format!(
            "{}:spend:{{{}}}",
            self.namespace,
            Self::hash_tag(stat_prefix, tenant, period)
        )
    }

    fn seq_key(&self, stat_prefix: &str, tenant: &str, period: &str) -> String {
        format!(
            "{}:seq:{{{}}}",
            self.namespace,
            Self::hash_tag(stat_prefix, tenant, period)
        )
    }
}

/// The six replies [`RedisControlPlaneStore::load`]'s single pipeline comes
/// back with, in the order the commands were queued: the tenant set, then
/// the keys, policies, budgets, tenant credentials and rate cards hashes as
/// raw `encode_json` bytes.
///
/// Rust note: this annotation is not decoration. `redis`'s `query` is
/// generic over `FromRedisValue`, and a pipeline's reply decodes into a
/// TUPLE -- so the element types are what tells inference to read reply 1
/// as a `Vec<String>` and replies 2-5 as maps, and there is no other
/// expression in `load` to infer them from. Written inline it is also
/// exactly the shape clippy's `type_complexity` lint exists to catch, hence
/// the alias rather than a multi-line type ascription at the binding.
type LoadReply = (
    Vec<String>,
    HashMap<String, Vec<u8>>,
    HashMap<String, Vec<u8>>,
    HashMap<String, Vec<u8>>,
    HashMap<String, Vec<u8>>,
    HashMap<String, Vec<u8>>,
);

impl ControlPlaneStore for RedisControlPlaneStore {
    /// One pipeline: `SMEMBERS tenants`, then `HGETALL` of keys, policies,
    /// budgets, tenant credentials and rate cards -- run inside `MULTI`/`EXEC`
    /// (`.atomic()`) so a rebuild sees one consistent point-in-time snapshot,
    /// the same property `RedbControlPlaneStore::load`'s single read
    /// transaction gives for free. Runs on [`Lane::Control`].
    ///
    /// # The log line
    ///
    /// One `info` per successful load, because this call reads the WHOLE
    /// policy state, so its cost grows with the state and nothing else made
    /// that visible. `fetch_ms` is the time to get the replies off the wire,
    /// including any wait for the control connection (an admin write queued
    /// ahead of the load shows up there); `duration_ms` adds decoding the
    /// rows. The counts are per kind of row, and `payload_bytes` is the
    /// combined length of the field names, set members and values read,
    /// without the protocol framing. The line carries counts and lengths
    /// ONLY: the rows hold key digests and sealed tenant credentials, which
    /// must never reach a log (AGENTS.md "Fail-open controls").
    fn load(&self) -> Result<StoredControlPlane, StoreError> {
        let started = Instant::now();
        let tenants_key = self.tenants_key();
        let keys_key = self.keys_key();
        let policies_key = self.policies_key();
        let budgets_key = self.budgets_key();

        let credentials_key = self.tenant_credentials_key();
        let rate_cards_key = self.rate_cards_key();

        let (tenants_raw, keys_raw, policies_raw, budgets_raw, credentials_raw, rate_cards_raw): LoadReply =
            self.with_connection(Lane::Control, |conn| {
                redis::pipe()
                    .atomic()
                    .cmd("SMEMBERS")
                    .arg(&tenants_key)
                    .cmd("HGETALL")
                    .arg(&keys_key)
                    .cmd("HGETALL")
                    .arg(&policies_key)
                    .cmd("HGETALL")
                    .arg(&budgets_key)
                    .cmd("HGETALL")
                    .arg(&credentials_key)
                    .cmd("HGETALL")
                    .arg(&rate_cards_key)
                    .query(conn)
            })?;
        let fetched = started.elapsed();

        // Sized before the decode loops below consume the maps.
        let hash_bytes = |hash: &HashMap<String, Vec<u8>>| -> usize {
            hash.iter()
                .map(|(field, value)| field.len() + value.len())
                .sum()
        };
        let payload_bytes = tenants_raw.iter().map(String::len).sum::<usize>()
            + hash_bytes(&keys_raw)
            + hash_bytes(&policies_raw)
            + hash_bytes(&budgets_raw)
            + hash_bytes(&credentials_raw)
            + hash_bytes(&rate_cards_raw);
        let (n_tenants, n_keys, n_policies, n_budgets, n_credentials, n_rate_cards) = (
            tenants_raw.len(),
            keys_raw.len(),
            policies_raw.len(),
            budgets_raw.len(),
            credentials_raw.len(),
            rate_cards_raw.len(),
        );

        let tenants = tenants_raw.into_iter().map(TenantId::new).collect();

        let mut keys = Vec::with_capacity(keys_raw.len());
        for (key_id, bytes) in keys_raw {
            let row: EncodedKeyRow = decode_json(&bytes)?;
            keys.push(StoredKey {
                key_id: KeyId::new(key_id),
                digest: row.digest,
                tenant: TenantId::new(row.tenant),
                revoked: row.revoked,
            });
        }

        let mut policies = HashMap::new();
        for (tenant, bytes) in policies_raw {
            let encoded: EncodedModelAccess = decode_json(&bytes)?;
            policies.insert(TenantId::new(tenant), encoded.into());
        }

        let mut budgets = HashMap::new();
        for (tenant, bytes) in budgets_raw {
            let encoded: EncodedTenantBudget = decode_json(&bytes)?;
            budgets.insert(TenantId::new(tenant), encoded.into());
        }

        // Same fail-closed rule as redb: one row this build cannot read
        // fails the whole load rather than dropping a tenant's credential.
        let mut tenant_credentials = Vec::with_capacity(credentials_raw.len());
        for (field, bytes) in credentials_raw {
            let (tenant, provider) = field
                .split_once('|')
                .and_then(|(t, p)| Some((unescape_component(t)?, unescape_component(p)?)))
                .ok_or_else(|| {
                    StoreError::Unavailable(
                        "tenant credential hash has a malformed field; \
                         refusing the whole control-plane load"
                            .into(),
                    )
                })?;
            tenant_credentials.push(decode_tenant_credential_row(&tenant, &provider, &bytes)?);
        }

        // A rate card row this build cannot read is skipped and logged, not a
        // load error: see `decode_rate_card_row`.
        let rate_cards = rate_cards_raw
            .into_iter()
            .filter_map(|(chain, bytes)| decode_rate_card_row(&chain, &bytes))
            .collect();

        tracing::info!(
            duration_ms = started.elapsed().as_millis() as u64,
            fetch_ms = fetched.as_millis() as u64,
            tenants = n_tenants,
            keys = n_keys,
            policies = n_policies,
            budgets = n_budgets,
            tenant_credentials = n_credentials,
            rate_cards = n_rate_cards,
            payload_bytes,
            "loaded control-plane state from redis"
        );

        Ok(StoredControlPlane {
            tenants,
            keys,
            policies,
            budgets,
            tenant_credentials,
            rate_cards,
        })
    }

    fn policy_generation(&self) -> Result<u64, StoreError> {
        let key = self.generation_key();
        let value: Option<u64> = self.with_connection(Lane::Control, |conn| {
            redis::cmd("GET").arg(&key).query(conn)
        })?;
        Ok(value.unwrap_or(0))
    }

    fn create_tenant(&self, tenant: &TenantId) -> Result<(), StoreError> {
        let tenants_key = self.tenants_key();
        let generation_key = self.generation_key();
        self.with_connection(Lane::Control, |conn| {
            redis::pipe()
                .atomic()
                .cmd("SADD")
                .arg(&tenants_key)
                .arg(tenant.as_str())
                .ignore()
                .cmd("INCR")
                .arg(&generation_key)
                .ignore()
                .query::<()>(conn)
        })
    }

    fn delete_tenant(&self, tenant: &TenantId) -> Result<(), StoreError> {
        // Matches `InMemoryControlPlaneStore`/`RedbControlPlaneStore`: the
        // `keys` hash is left untouched -- a tenant's keys outliving the
        // tenant row is the existing, deliberate behaviour. Credential rows
        // go in the same script (see [`DELETE_TENANT_LUA`]).
        let prefix = format!("{}|", escape_component(tenant.as_str()));
        self.with_connection(Lane::Control, |conn| {
            self.delete_tenant_script
                .key(self.tenants_key())
                .key(self.policies_key())
                .key(self.budgets_key())
                .key(self.tenant_credentials_key())
                .key(self.generation_key())
                .arg(tenant.as_str())
                .arg(prefix)
                .invoke::<i64>(conn)
        })?;
        Ok(())
    }

    fn put_tenant_credential(&self, rec: &StoredTenantCredential) -> Result<(), StoreError> {
        // Reject before any write: no row, no generation bump.
        if rec.schema_version != TENANT_CREDENTIALS_SCHEMA_VERSION {
            return Err(StoreError::Conflict(
                "unsupported tenant credential schema_version".into(),
            ));
        }
        let field = Self::credential_field(rec.tenant.as_str(), &rec.provider);
        let value = encode_json(&EncodedTenantCredentialRow::from(rec));
        // No tenant-existence check, same as redb. HSET is last-writer-wins,
        // which is the required create-or-replace.
        self.with_connection(Lane::Control, |conn| {
            redis::pipe()
                .atomic()
                .cmd("HSET")
                .arg(self.tenant_credentials_key())
                .arg(&field)
                .arg(value)
                .ignore()
                .cmd("INCR")
                .arg(self.generation_key())
                .ignore()
                .query::<()>(conn)
        })
    }

    fn delete_tenant_credential(
        &self,
        tenant: &TenantId,
        provider: &str,
    ) -> Result<(), StoreError> {
        let field = Self::credential_field(tenant.as_str(), provider);
        let removed: i64 = self.with_connection(Lane::Control, |conn| {
            self.delete_tenant_credential_script
                .key(self.tenant_credentials_key())
                .key(self.generation_key())
                .arg(&field)
                .invoke::<i64>(conn)
        })?;
        if removed == 1 {
            Ok(())
        } else {
            Err(StoreError::NotFound)
        }
    }

    fn put_key(&self, rec: &StoredKey) -> Result<(), StoreError> {
        let row = EncodedKeyRow {
            schema_version: SPEND_SCHEMA_VERSION,
            digest: rec.digest,
            tenant: rec.tenant.as_str().into(),
            revoked: rec.revoked,
        };
        let result: i64 = self.with_connection(Lane::Control, |conn| {
            Script::new(PUT_KEY_LUA)
                .key(self.keys_key())
                .key(self.generation_key())
                .arg(rec.key_id.as_str())
                .arg(encode_json(&row))
                .invoke(conn)
        })?;
        match result {
            1 => Ok(()),
            -1 => Err(StoreError::Conflict("key ownership is immutable".into())),
            -2 => Err(StoreError::Conflict(
                "revoked key IDs cannot be reused".into(),
            )),
            _ => Err(StoreError::Unavailable(
                "unsupported spend schema version".into(),
            )),
        }
    }

    /// See [`REVOKE_KEY_LUA`]'s doc for why the existence check and the
    /// write live in one script rather than a Rust-side `HGET` followed by
    /// an `HSET`.
    fn revoke_key(&self, key_id: &KeyId) -> Result<(), StoreError> {
        let keys_key = self.keys_key();
        let generation_key = self.generation_key();
        let found: i64 = self.with_connection(Lane::Control, |conn| {
            self.revoke_key_script
                .key(&keys_key)
                .key(&generation_key)
                .arg(key_id.as_str())
                .invoke::<i64>(conn)
        })?;
        if found == 1 {
            Ok(())
        } else {
            Err(StoreError::NotFound)
        }
    }

    fn set_policy(&self, tenant: &TenantId, access: &ModelAccess) -> Result<(), StoreError> {
        let policies_key = self.policies_key();
        let generation_key = self.generation_key();
        let encoded: EncodedModelAccess = access.into();
        let bytes = encode_json(&encoded);
        self.with_connection(Lane::Control, |conn| {
            redis::pipe()
                .atomic()
                .cmd("HSET")
                .arg(&policies_key)
                .arg(tenant.as_str())
                .arg(&bytes)
                .ignore()
                .cmd("INCR")
                .arg(&generation_key)
                .ignore()
                .query::<()>(conn)
        })
    }

    fn set_budget(
        &self,
        tenant: &TenantId,
        budget: Option<&TenantBudget>,
    ) -> Result<(), StoreError> {
        let budgets_key = self.budgets_key();
        let generation_key = self.generation_key();
        match budget {
            Some(budget) => {
                let encoded: EncodedTenantBudget = budget.into();
                let bytes = encode_json(&encoded);
                self.with_connection(Lane::Control, |conn| {
                    redis::pipe()
                        .atomic()
                        .cmd("HSET")
                        .arg(&budgets_key)
                        .arg(tenant.as_str())
                        .arg(&bytes)
                        .ignore()
                        .cmd("INCR")
                        .arg(&generation_key)
                        .ignore()
                        .query::<()>(conn)
                })
            }
            None => self.with_connection(Lane::Control, |conn| {
                redis::pipe()
                    .atomic()
                    .cmd("HDEL")
                    .arg(&budgets_key)
                    .arg(tenant.as_str())
                    .ignore()
                    .cmd("INCR")
                    .arg(&generation_key)
                    .ignore()
                    .query::<()>(conn)
            }),
        }
    }

    /// The card and the generation bump are one `MULTI`/`EXEC` on
    /// [`Lane::Control`], like `set_policy`: Redis applies a transaction as a
    /// unit, so a poller that sees the new stamp also finds the card, and a
    /// connection that dies before `EXEC` leaves neither behind.
    fn put_rate_card(&self, card: &StoredRateCard) -> Result<(), StoreError> {
        let rate_cards_key = self.rate_cards_key();
        let generation_key = self.generation_key();
        let row = encode_json(&EncodedRateCardRow::from(card));
        self.with_connection(Lane::Control, |conn| {
            redis::pipe()
                .atomic()
                .cmd("HSET")
                .arg(&rate_cards_key)
                .arg(&card.chain)
                .arg(&row)
                .ignore()
                .cmd("INCR")
                .arg(&generation_key)
                .ignore()
                .query::<()>(conn)
        })
    }

    /// See [`PUT_RATE_CARD_IF_ABSENT_LUA`]'s doc for why this one is a script.
    fn put_rate_card_if_absent(&self, card: &StoredRateCard) -> Result<bool, StoreError> {
        let row = encode_json(&EncodedRateCardRow::from(card));
        let written: i64 = self.with_connection(Lane::Control, |conn| {
            self.put_rate_card_if_absent_script
                .key(self.rate_cards_key())
                .key(self.generation_key())
                .arg(&card.chain)
                .arg(&row)
                .invoke::<i64>(conn)
        })?;
        Ok(written == 1)
    }

    /// Redis is the shared store: it is meant to outlive any replica.
    fn is_durable(&self) -> bool {
        true
    }

    /// See [`ADD_SPEND_LUA`]'s doc -- this is the whole method: build the two
    /// hash-tagged keys, invoke the script, and let `?`/`store_err` turn a
    /// `RedisError` into [`StoreError::Unavailable`].
    fn add_spend(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &PeriodKey,
        delta_micros: u64,
        token: FlushToken<'_>,
    ) -> Result<u64, StoreError> {
        let spend_key = self.spend_key(stat_prefix, tenant.as_str(), period.as_str());
        let seq_key = self.seq_key(stat_prefix, tenant.as_str(), period.as_str());
        self.with_connection(Lane::Spend, |conn| {
            self.add_spend_script
                .key(&spend_key)
                .key(&seq_key)
                .arg(token.node_id)
                .arg(token.seq)
                .arg(delta_micros)
                .invoke::<u64>(conn)
        })
    }

    /// A plain `SET` -- must NOT touch the seq hash (see the trait doc's
    /// "ADMIN ONLY" note). No script needed: there is no read this write
    /// depends on.
    fn overwrite_spend(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &PeriodKey,
        total_micros: u64,
    ) -> Result<(), StoreError> {
        let spend_key = self.spend_key(stat_prefix, tenant.as_str(), period.as_str());
        self.with_connection(Lane::Spend, |conn| {
            redis::cmd("SET")
                .arg(&spend_key)
                .arg(total_micros)
                .query::<()>(conn)
        })
    }

    fn last_flush_seq(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &PeriodKey,
        node_id: &str,
    ) -> Result<u64, StoreError> {
        let seq_key = self.seq_key(stat_prefix, tenant.as_str(), period.as_str());
        let value: Option<u64> = self.with_connection(Lane::Spend, |conn| {
            redis::cmd("HGET").arg(&seq_key).arg(node_id).query(conn)
        })?;
        Ok(value.unwrap_or(0))
    }

    fn load_spend(
        &self,
        stat_prefix: &str,
        tenant: &TenantId,
        period: &PeriodKey,
    ) -> Result<u64, StoreError> {
        let spend_key = self.spend_key(stat_prefix, tenant.as_str(), period.as_str());
        let value: Option<u64> = self.with_connection(Lane::Spend, |conn| {
            redis::cmd("GET").arg(&spend_key).query(conn)
        })?;
        Ok(value.unwrap_or(0))
    }
}

// Tests that run in every `make tq`, against an in-process fake Redis; the
// `#[ignore]`d tests in `tests` below need a real one.
#[cfg(test)]
mod fake_redis_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use chrono::TimeZone;

    use crate::spend::{Charge, MicroUsd, Period, SpendAccumulator};
    use proxy_http::tenant_credentials::CredentialSource;

    // ------------------------------------------------------------------
    // Unit tests: no Redis needed. `Client::open` only parses the URL, so
    // building a store to exercise its private key-building helpers costs
    // no I/O even against a URL nothing is listening on.
    // ------------------------------------------------------------------

    #[test]
    fn escape_component_encodes_percent_pipe_and_braces() {
        assert_eq!(escape_component("plain"), "plain");
        assert_eq!(escape_component("a|b"), "a%7Cb");
        assert_eq!(escape_component("a{b}c"), "a%7Bb%7Dc");
        assert_eq!(escape_component("100%"), "100%25");
    }

    #[test]
    fn escaping_prevents_a_collision_between_differently_split_components() {
        // Without escaping, ("a|b", "c", "d") and ("a", "b|c", "d") would
        // both join to the literal string "a|b|c|d" -- two different
        // (stat_prefix, tenant, period) triples silently sharing one spend
        // row.
        let first = RedisControlPlaneStore::hash_tag("a|b", "c", "d");
        let second = RedisControlPlaneStore::hash_tag("a", "b|c", "d");
        assert_ne!(
            first, second,
            "differently-split components must never escape to the same hash tag"
        );
    }

    #[test]
    fn spend_and_seq_keys_share_the_same_hash_tag() {
        let store =
            RedisControlPlaneStore::open_with_namespace("redis://127.0.0.1:6390", "test-ns")
                .unwrap();
        let spend = store.spend_key("chain-a", "tenant-a", "2026-09");
        let seq = store.seq_key("chain-a", "tenant-a", "2026-09");
        // Both must wrap the IDENTICAL `{...}` substring -- see
        // `hash_tag`'s doc for why Redis Cluster requires this for
        // `add_spend`'s script to be routable at all.
        assert_eq!(spend, "test-ns:spend:{chain-a|tenant-a|2026-09}");
        assert_eq!(seq, "test-ns:seq:{chain-a|tenant-a|2026-09}");
    }

    #[test]
    fn add_spend_script_reads_the_seq_hash_keyed_by_node_id() {
        // Regression guard on the dedup key: `FlushToken`'s doc names
        // keying dedup state on `seq` alone (dropping `node_id`) as the
        // exact bug this store exists to avoid reintroducing. `HGET
        // KEYS[2], ARGV[1]` is that per-node lookup -- if a future edit
        // changes it to read straight off `ARGV[2]` (the seq) instead of
        // `ARGV[1]` (the node id), this test goes red.
        assert!(
            ADD_SPEND_LUA.contains("redis.call('HGET', KEYS[2], ARGV[1])"),
            "add_spend's dedup read must be keyed by node_id (ARGV[1]) against \
             the per-writer hash (KEYS[2])"
        );
    }

    #[test]
    fn revoke_key_script_checks_existence_before_writing() {
        assert!(
            REVOKE_KEY_LUA.contains("redis.call('HGET', KEYS[1], ARGV[1])"),
            "revoke_key must read the row before writing it, inside the same script -- \
             a separate Rust-side HGET/HSET pair would reopen the race this script exists \
             to close"
        );
    }

    // ------------------------------------------------------------------
    // Integration tests: a real Redis is required. `#[ignore]`d because
    // CI has none, exactly like `local_openai_smoke.rs`'s Ollama tests.
    //
    // How to run:
    //
    //   docker run -d --rm -p 6390:6379 --name llmproxy-test-redis redis:7-alpine
    //   LLM_PROXY_TEST_REDIS=redis://127.0.0.1:6390 \
    //     cargo nextest run -p proxy-filters --run-ignored all -E 'test(redis)'
    //   docker rm -f llmproxy-test-redis
    //
    // Port 6390, not 6379: a fixed port is a cross-lane hazard, and 6379 is
    // where a developer's own Redis is already likely listening (AGENTS.md
    // "Running The Product"). Each test below builds its own namespace, timestamped to
    // the nanosecond, so concurrent runs never collide either.
    // ------------------------------------------------------------------

    fn test_store(label: &str) -> RedisControlPlaneStore {
        let url = std::env::var("LLM_PROXY_TEST_REDIS").unwrap_or_else(|_| {
            panic!(
                "LLM_PROXY_TEST_REDIS is not set -- start a Redis with `docker run -d --rm \
                 -p 6390:6379 --name llmproxy-test-redis redis:7-alpine` and set \
                 LLM_PROXY_TEST_REDIS=redis://127.0.0.1:6390"
            )
        });
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before the epoch")
            .as_nanos();
        RedisControlPlaneStore::open_with_namespace(&url, format!("llmproxy-test-{label}-{nanos}"))
            .expect("Client::open only parses the URL and must not fail here")
    }

    #[test]
    #[ignore = "needs a real Redis -- see this module's doc comment"]
    fn redis_rotation_keeps_history_and_rejects_owner_changes_and_tombstone_reuse() {
        let store = test_store("key-lifecycle");
        let id = KeyId::new("stable");
        let tenant = TenantId::new("owner");
        let subject = crate::spend::key_spend_subject(&id);
        let period = PeriodKey::for_test("2026-09");
        let mut row = StoredKey {
            key_id: id.clone(),
            digest: [1; 32],
            tenant: tenant.clone(),
            revoked: false,
        };
        store.put_key(&row).unwrap();
        let budget = TenantBudget {
            max_micros: crate::spend::MicroUsd::from_micros(10),
            period: crate::spend::Period::Monthly,
            credential_source: CredentialSource::Platform,
        };
        store.set_budget(&subject, Some(&budget)).unwrap();
        store
            .add_spend(
                "chain",
                &subject,
                &period,
                7,
                FlushToken {
                    node_id: "node",
                    seq: 1,
                },
            )
            .unwrap();
        row.digest = [2; 32];
        store.put_key(&row).unwrap();
        assert_eq!(store.load().unwrap().keys[0].digest, [2; 32]);
        assert_eq!(store.load().unwrap().budgets.get(&subject), Some(&budget));
        assert_eq!(store.load_spend("chain", &subject, &period).unwrap(), 7);
        let generation = store.policy_generation().unwrap();
        row.tenant = TenantId::new("other");
        assert!(matches!(store.put_key(&row), Err(StoreError::Conflict(_))));
        assert_eq!(store.policy_generation().unwrap(), generation);
        row.tenant = tenant;
        store.revoke_key(&id).unwrap();
        let generation = store.policy_generation().unwrap();
        assert!(matches!(store.put_key(&row), Err(StoreError::Conflict(_))));
        assert_eq!(store.policy_generation().unwrap(), generation);
        assert!(store.load().unwrap().keys[0].revoked);
        assert_eq!(store.load_spend("chain", &subject, &period).unwrap(), 7);
    }

    #[test]
    fn put_rate_card_if_absent_script_bumps_only_after_a_successful_hsetnx() {
        let hsetnx = PUT_RATE_CARD_IF_ABSENT_LUA
            .find("HSETNX")
            .expect("the script writes with HSETNX");
        let incr = PUT_RATE_CARD_IF_ABSENT_LUA
            .find("INCR")
            .expect("the script bumps the generation");
        assert!(
            hsetnx < incr,
            "the bump must come after the conditional write, never before it"
        );
        assert!(
            PUT_RATE_CARD_IF_ABSENT_LUA.contains("return 0"),
            "a seed that finds a card must return before the bump"
        );
    }

    #[test]
    fn the_redis_store_claims_durability() {
        let store = RedisControlPlaneStore::open("redis://127.0.0.1:6390").unwrap();
        assert!(store.is_durable());
    }

    #[test]
    #[ignore = "needs a real Redis -- see this module's doc comment"]
    fn redis_rate_cards_round_trip_replace_and_seed_with_one_bump_each() {
        let store = test_store("rate-cards");
        let card = |marker: &str| StoredRateCard {
            chain: "chain-a".into(),
            version: format!("v-{marker}"),
            card_json: format!(r#"{{"marker":"{marker}"}}"#),
        };
        let base = store.policy_generation().unwrap();

        assert_eq!(store.put_rate_card_if_absent(&card("seed")), Ok(true));
        assert_eq!(store.policy_generation().unwrap(), base + 1);
        assert_eq!(store.put_rate_card_if_absent(&card("again")), Ok(false));
        assert_eq!(store.policy_generation().unwrap(), base + 1);
        assert_eq!(store.load().unwrap().rate_cards, vec![card("seed")]);

        store.put_rate_card(&card("published")).unwrap();
        assert_eq!(store.policy_generation().unwrap(), base + 2);
        assert_eq!(store.load().unwrap().rate_cards, vec![card("published")]);
        assert_eq!(store.put_rate_card_if_absent(&card("later")), Ok(false));
        assert_eq!(store.load().unwrap().rate_cards, vec![card("published")]);
    }

    #[test]
    #[ignore = "needs a real Redis -- see this module's doc comment"]
    fn redis_two_writers_adding_to_the_same_row_converge() {
        let store = test_store("converge");
        let tenant = TenantId::new("tenant-a");
        let period = PeriodKey::for_test("2026-09");

        let total_a = store
            .add_spend(
                "chain-a",
                &tenant,
                &period,
                100,
                FlushToken {
                    node_id: "node-a",
                    seq: 1,
                },
            )
            .unwrap();
        let total_b = store
            .add_spend(
                "chain-a",
                &tenant,
                &period,
                50,
                FlushToken {
                    node_id: "node-b",
                    seq: 1,
                },
            )
            .unwrap();
        assert_eq!(total_a, 100);
        assert_eq!(
            total_b, 150,
            "two writers' deltas must compose, not clobber"
        );
        assert_eq!(store.load_spend("chain-a", &tenant, &period).unwrap(), 150);
    }

    #[test]
    #[ignore = "needs a real Redis -- see this module's doc comment"]
    fn redis_a_replayed_token_is_a_no_op_returning_the_total() {
        let store = test_store("replay");
        let tenant = TenantId::new("tenant-a");
        let period = PeriodKey::for_test("2026-09");
        let token = FlushToken {
            node_id: "node-a",
            seq: 1,
        };

        let first = store
            .add_spend("chain-a", &tenant, &period, 100, token)
            .unwrap();
        let replay = store
            .add_spend("chain-a", &tenant, &period, 100, token)
            .unwrap();
        assert_eq!(first, 100);
        assert_eq!(replay, 100, "a replayed token must not re-apply the delta");
    }

    #[test]
    #[ignore = "needs a real Redis -- see this module's doc comment"]
    fn redis_the_same_seq_from_two_different_node_ids_both_land() {
        let store = test_store("same-seq-diff-node");
        let tenant = TenantId::new("tenant-a");
        let period = PeriodKey::for_test("2026-09");

        let total_a = store
            .add_spend(
                "chain-a",
                &tenant,
                &period,
                100,
                FlushToken {
                    node_id: "node-a",
                    seq: 7,
                },
            )
            .unwrap();
        let total_b = store
            .add_spend(
                "chain-a",
                &tenant,
                &period,
                100,
                FlushToken {
                    node_id: "node-b",
                    seq: 7,
                },
            )
            .unwrap();
        assert_eq!(total_a, 100);
        assert_eq!(
            total_b, 200,
            "dedup keyed by seq ALONE would treat node-b's seq 7 as a duplicate of \
             node-a's and drop it -- see FlushToken's doc"
        );
    }

    #[test]
    #[ignore = "needs a real Redis -- see this module's doc comment"]
    fn redis_last_flush_seq_reports_per_node() {
        let store = test_store("last-flush-seq");
        let tenant = TenantId::new("tenant-a");
        let period = PeriodKey::for_test("2026-09");

        assert_eq!(
            store
                .last_flush_seq("chain-a", &tenant, &period, "node-a")
                .unwrap(),
            0
        );
        store
            .add_spend(
                "chain-a",
                &tenant,
                &period,
                10,
                FlushToken {
                    node_id: "node-a",
                    seq: 5,
                },
            )
            .unwrap();
        assert_eq!(
            store
                .last_flush_seq("chain-a", &tenant, &period, "node-a")
                .unwrap(),
            5
        );
        assert_eq!(
            store
                .last_flush_seq("chain-a", &tenant, &period, "node-b")
                .unwrap(),
            0,
            "node-b has flushed nothing yet, independent of node-a's sequence"
        );
    }

    #[test]
    #[ignore = "needs a real Redis -- see this module's doc comment"]
    fn redis_overwrite_spend_leaves_dedup_state_alone() {
        let store = test_store("overwrite-leaves-dedup");
        let tenant = TenantId::new("tenant-a");
        let period = PeriodKey::for_test("2026-09");
        let token = FlushToken {
            node_id: "node-a",
            seq: 3,
        };

        store
            .add_spend("chain-a", &tenant, &period, 100, token)
            .unwrap();
        store
            .overwrite_spend("chain-a", &tenant, &period, 0)
            .unwrap();
        assert_eq!(store.load_spend("chain-a", &tenant, &period).unwrap(), 0);

        // A replay of the SAME token, after the operator's correction, must
        // stay deduplicated -- overwrite_spend does not touch the seq hash,
        // so the store still remembers seq 3 was already accepted.
        let replay = store
            .add_spend("chain-a", &tenant, &period, 100, token)
            .unwrap();
        assert_eq!(
            replay, 0,
            "overwrite_spend must not reset dedup state -- a replay after it stays a no-op"
        );
    }

    #[test]
    #[ignore = "needs a real Redis -- see this module's doc comment"]
    fn redis_a_tier_two_write_bumps_the_generation_and_add_spend_does_not() {
        let store = test_store("generation");
        assert_eq!(store.policy_generation().unwrap(), 0);

        let tenant = TenantId::new("tenant-a");
        store.create_tenant(&tenant).unwrap();
        assert_eq!(store.policy_generation().unwrap(), 1);

        store
            .add_spend(
                "chain-a",
                &tenant,
                &PeriodKey::for_test("2026-09"),
                100,
                FlushToken {
                    node_id: "node-a",
                    seq: 1,
                },
            )
            .unwrap();
        assert_eq!(
            store.policy_generation().unwrap(),
            1,
            "add_spend is tier-3 and must never bump the tier-2 generation"
        );

        store.set_policy(&tenant, &ModelAccess::All).unwrap();
        assert_eq!(store.policy_generation().unwrap(), 2);
    }

    #[test]
    #[ignore = "needs a real Redis -- see this module's doc comment"]
    fn redis_revoke_key_on_an_unknown_id_returns_not_found_without_bumping() {
        let store = test_store("revoke-unknown");
        assert_eq!(store.policy_generation().unwrap(), 0);

        assert_eq!(
            store.revoke_key(&KeyId::new("no-such-key")),
            Err(StoreError::NotFound)
        );
        assert_eq!(
            store.policy_generation().unwrap(),
            0,
            "a NotFound revoke wrote nothing and must not bump the generation"
        );
    }

    #[test]
    #[ignore = "needs a real Redis -- see this module's doc comment"]
    fn redis_load_round_trips_tenants_keys_policies_and_budgets() {
        let store = test_store("load-roundtrip");
        let tenant = TenantId::new("tenant-a");
        store.create_tenant(&tenant).unwrap();
        store
            .put_key(&StoredKey {
                key_id: KeyId::new("k1"),
                digest: [7u8; 32],
                tenant: tenant.clone(),
                revoked: false,
            })
            .unwrap();
        store.set_policy(&tenant, &ModelAccess::All).unwrap();
        store
            .set_budget(
                &tenant,
                Some(&TenantBudget {
                    max_micros: MicroUsd::from_micros(5_000_000),
                    period: Period::Monthly,
                    credential_source: CredentialSource::Platform,
                }),
            )
            .unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.tenants, vec![tenant.clone()]);
        assert_eq!(loaded.keys.len(), 1);
        assert_eq!(loaded.keys[0].key_id, KeyId::new("k1"));
        assert!(matches!(
            loaded.policies.get(&tenant),
            Some(ModelAccess::All)
        ));
        assert!(loaded.budgets.contains_key(&tenant));
    }

    // ------------------------------------------------------------------
    // Acceptance, at the `SpendAccumulator` level:
    // "three processes against one Redis converge on spend" and "a killed
    // process's backlog flushes on restart and the ledger self-heals".
    //
    // WHAT THESE TWO TESTS PROVE, AND WHAT THEY DO NOT: AGENTS.md "Running The Product"
    // forbids a worktree-isolated agent from spawning OS processes or
    // binding ports, so "three processes" below is three `SpendAccumulator`s
    // with three DISTINCT `node_id`s sharing ONE `RedisControlPlaneStore`,
    // in this one test process, and "a killed process" is a `SpendAccumulator`
    // dropped and a fresh one built over the same store and `node_id`. This
    // proves the STORE's dedup/composable-write path handles multiple
    // independent writers and that a fresh accumulator resumes from the
    // store's own total rather than the in-memory state of the one that
    // came before it. It does NOT exercise process supervision, a real
    // `kill -9`, socket reconnection after a network partition, or anything
    // else that is specifically about being a separate OS process -- only
    // the store-level convergence and resume properties those processes
    // would rely on.
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // Tenant credential rows (ADR-0007). Same semantics as the redb and
    // in-memory stores; see `control.rs`'s `tenant_credential_*` tests.
    // ------------------------------------------------------------------

    /// A row whose every replaceable field carries `marker`. The bytes are
    /// opaque: this store persists ciphertext and never interprets it.
    fn credential_row(tenant: &str, provider: &str, marker: &str) -> StoredTenantCredential {
        let mut nonce = [0u8; 12];
        nonce[0] = marker.as_bytes()[0];
        StoredTenantCredential {
            schema_version: 1,
            tenant: TenantId::new(tenant),
            provider: provider.to_string(),
            key_id: format!("kek-{marker}"),
            nonce,
            ciphertext: format!("ciphertext-{marker}").into_bytes(),
            last4: format!("last4-{marker}"),
            fingerprint: format!("fp-{marker}"),
            created_at: "2026-10-11T00:00:00Z".to_string(),
            updated_at: "2026-10-11T00:00:01Z".to_string(),
            verified_at: None,
        }
    }

    #[test]
    fn credential_field_never_collides_across_differently_split_pairs() {
        let a = RedisControlPlaneStore::credential_field("a|b", "c");
        let b = RedisControlPlaneStore::credential_field("a", "b|c");
        assert_ne!(a, b);
        assert_eq!(a, "a%7Cb|c");
        assert_eq!(unescape_component("a%7Cb"), Some("a|b".to_string()));
        assert_eq!(unescape_component("100%25"), Some("100%".to_string()));
        assert_eq!(unescape_component("bad%2"), None);
        assert_eq!(unescape_component("bad%zz"), None);
    }

    #[test]
    #[ignore = "needs a real Redis -- see this module's doc comment"]
    fn redis_tenant_credential_put_then_load_round_trips_and_replaces() {
        let store = test_store("cred-roundtrip");
        // Tenant and provider chosen so escaping is exercised on the way
        // in and decoded on the way out.
        let first = credential_row("ten|ant{1}%", "prov|ider", "first");
        store.put_tenant_credential(&first).unwrap();
        assert_eq!(
            store.load().unwrap().tenant_credentials,
            vec![first.clone()]
        );

        store
            .put_tenant_credential(&credential_row("ten|ant{1}%", "other", "other"))
            .unwrap();
        let second = credential_row("ten|ant{1}%", "prov|ider", "second");
        store.put_tenant_credential(&second).unwrap();
        let loaded = store.load().unwrap().tenant_credentials;
        assert_eq!(loaded.len(), 2, "same (tenant, provider) must replace");
        let replaced = loaded
            .iter()
            .find(|r| r.provider == "prov|ider")
            .expect("replaced row present");
        assert_eq!(replaced, &second);
        assert!(loaded.iter().any(|r| r.provider == "other"));
    }

    #[test]
    #[ignore = "needs a real Redis -- see this module's doc comment"]
    fn redis_tenant_credential_put_bumps_the_generation() {
        let store = test_store("cred-put-bump");
        let before = store.policy_generation().unwrap();
        store
            .put_tenant_credential(&credential_row("t", "p", "one"))
            .unwrap();
        assert_eq!(store.policy_generation().unwrap(), before + 1);
        store
            .put_tenant_credential(&credential_row("t", "p", "two"))
            .unwrap();
        assert_eq!(store.policy_generation().unwrap(), before + 2);
    }

    #[test]
    #[ignore = "needs a real Redis -- see this module's doc comment"]
    fn redis_tenant_credential_bad_schema_version_is_conflict_with_no_bump_and_no_row() {
        let store = test_store("cred-bad-version");
        let mut row = credential_row("t", "p", "one");
        row.schema_version = 2;
        assert!(matches!(
            store.put_tenant_credential(&row),
            Err(StoreError::Conflict(_))
        ));
        assert_eq!(store.policy_generation().unwrap(), 0);
        assert!(store.load().unwrap().tenant_credentials.is_empty());
    }

    #[test]
    #[ignore = "needs a real Redis -- see this module's doc comment"]
    fn redis_tenant_credential_delete_removes_and_bumps_and_a_missing_row_is_not_found() {
        let store = test_store("cred-delete");
        let tenant = TenantId::new("t");
        store
            .put_tenant_credential(&credential_row("t", "p", "one"))
            .unwrap();
        let before = store.policy_generation().unwrap();

        store.delete_tenant_credential(&tenant, "p").unwrap();
        assert!(store.load().unwrap().tenant_credentials.is_empty());
        assert_eq!(store.policy_generation().unwrap(), before + 1);

        assert_eq!(
            store.delete_tenant_credential(&tenant, "p"),
            Err(StoreError::NotFound)
        );
        assert_eq!(
            store.delete_tenant_credential(&tenant, "never-written"),
            Err(StoreError::NotFound)
        );
        assert_eq!(
            store.policy_generation().unwrap(),
            before + 1,
            "a NotFound delete must not bump"
        );
    }

    #[test]
    #[ignore = "needs a real Redis -- see this module's doc comment"]
    fn redis_delete_tenant_cascades_to_only_that_tenants_credentials() {
        let store = test_store("cred-cascade");
        // "a" and "a|b" share a naive prefix ("a|"), and under naive
        // joining ("a", "b|c") would equal ("a|b", "c"). Escaping must keep
        // the survivors out of the cascade.
        let doomed = [("a", "b|c"), ("a", "plain")];
        let survivors = [("a|b", "c"), ("ab", "plain"), ("other", "plain")];
        for (t, p) in doomed.iter().chain(survivors.iter()) {
            store
                .put_tenant_credential(&credential_row(t, p, "x"))
                .unwrap();
        }
        store.create_tenant(&TenantId::new("a")).unwrap();
        let before = store.policy_generation().unwrap();

        store.delete_tenant(&TenantId::new("a")).unwrap();

        let mut left: Vec<(String, String)> = store
            .load()
            .unwrap()
            .tenant_credentials
            .into_iter()
            .map(|r| (r.tenant.as_str().to_string(), r.provider))
            .collect();
        left.sort();
        let mut want: Vec<(String, String)> = survivors
            .iter()
            .map(|(t, p)| (t.to_string(), p.to_string()))
            .collect();
        want.sort();
        assert_eq!(left, want);
        assert_eq!(
            store.policy_generation().unwrap(),
            before + 1,
            "the cascade shares the delete's single bump"
        );
    }

    #[test]
    #[ignore = "needs a real Redis -- see this module's doc comment"]
    fn redis_a_second_replica_sees_a_tenant_secret_stored_and_deleted_by_the_first() {
        use crate::auth::{HmacSecret, KeySet};
        use crate::control::{ControlPlane, CredentialKeys};
        use crate::tenant_credential_crypto::{CredentialKek, KeyRing, TenantSecret};
        use proxy_http::tenant_credentials::TenantCredential;

        let url = std::env::var("LLM_PROXY_TEST_REDIS").expect("LLM_PROXY_TEST_REDIS is not set");
        let namespace = format!(
            "llmproxy-test-replicas-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let replica = || {
            let ring = KeyRing::new(
                CredentialKek::from_bytes("kek", *b"0123456789abcdef0123456789abcdef").unwrap(),
                vec![],
            )
            .unwrap();
            ControlPlane::new_with_credential_keys(
                Box::new(
                    RedisControlPlaneStore::open_with_namespace(&url, namespace.clone()).unwrap(),
                ),
                HmacSecret::new(b"operator-secret"),
                KeySet::new(),
                Some(CredentialKeys::new(ring, b"operator-secret")),
            )
            .expect("replica must load")
        };
        let first = replica();
        let second = replica();
        let usable = |cp: &ControlPlane| {
            let snapshot = cp.handle().load();
            let set = snapshot
                .tenant_credentials
                .get(&TenantId::new("tenant-a"))?;
            match set.get("openai")? {
                TenantCredential::Usable(secret) => Some(secret.expose().to_string()),
                TenantCredential::Unusable => None,
            }
        };
        assert_eq!(usable(&second), None);

        first
            .store_tenant_secret(
                &TenantId::new("tenant-a"),
                "openai",
                &TenantSecret::new("sk-replica-secret".to_string()),
                false,
            )
            .unwrap();
        assert_eq!(usable(&second), None, "not visible before the poll");
        assert!(second.poll_once().unwrap(), "the generation moved");
        assert_eq!(usable(&second).as_deref(), Some("sk-replica-secret"));

        first
            .delete_tenant_credential(&TenantId::new("tenant-a"), "openai")
            .unwrap();
        assert!(second.poll_once().unwrap());
        assert_eq!(usable(&second), None);
        let snapshot = second.handle().load();
        assert!(snapshot
            .tenant_credentials
            .get(&TenantId::new("tenant-a"))
            .is_none_or(|set| set.get("openai").is_none()));
    }

    fn dt(y: i32, mo: u32, d: u32) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.with_ymd_and_hms(y, mo, d, 12, 0, 0).unwrap()
    }

    fn record_micros(
        accumulator: &SpendAccumulator,
        tenant: &TenantId,
        at: chrono::DateTime<chrono::Utc>,
        m: u64,
    ) {
        accumulator.record(
            tenant,
            at,
            Period::Daily,
            Charge::Priced(MicroUsd::from_micros(m)),
            Some("cluster-a"),
            Some("model-a"),
        );
    }

    #[test]
    #[ignore = "needs a real Redis -- see this module's doc comment"]
    fn redis_three_accumulators_with_distinct_node_ids_converge_on_one_total() {
        let store: Arc<dyn ControlPlaneStore> = Arc::new(test_store("three-way"));
        let tenant = TenantId::new("tenant-a");
        let now = dt(2026, 9, 7);
        let period_key = Period::Daily.key_for(now);

        // THREE DISTINCT node ids over the SAME store -- sharing one node id here would not exercise
        // convergence at all, because every write past the first would be
        // deduped as a replay of that shared id's own sequence.
        let replica_a = SpendAccumulator::new(
            "chain-a".to_string(),
            Arc::clone(&store),
            Period::Daily,
            "node-a".to_string(),
        );
        let replica_b = SpendAccumulator::new(
            "chain-a".to_string(),
            Arc::clone(&store),
            Period::Daily,
            "node-b".to_string(),
        );
        let replica_c = SpendAccumulator::new(
            "chain-a".to_string(),
            Arc::clone(&store),
            Period::Daily,
            "node-c".to_string(),
        );

        record_micros(&replica_a, &tenant, now, 10_000_000);
        record_micros(&replica_b, &tenant, now, 5_000_000);
        record_micros(&replica_c, &tenant, now, 7_000_000);

        replica_a.flush_now().unwrap();
        replica_b.flush_now().unwrap();
        replica_c.flush_now().unwrap();

        assert_eq!(
            store.load_spend("chain-a", &tenant, &period_key).unwrap(),
            22_000_000,
            "three accumulators with distinct node ids must all land in the store and \
             compose into one total, not clobber or drop each other"
        );

        // The total alone does not distinguish "three distinct node ids" from
        // "one shared node id, three sequential flushes": each accumulator's
        // `next_seq` is lazily seeded from `last_flush_seq` on its own first
        // flush (see `spend.rs`), so a SHARED id still composes correctly
        // when the flushes happen one after another rather than racing --
        // sequential in-process calls, exactly what AGENTS.md "Running The Product" confines
        // this test to, cannot reproduce the concurrent-race collision a
        // shared node id risks in real deployment. This assertion catches
        // the shared-id case anyway, by checking WHERE the sequence landed:
        // with three distinct ids, each one's own high-water mark is 1: it
        // was the only writer under that id.
        for node_id in ["node-a", "node-b", "node-c"] {
            assert_eq!(
                store
                    .last_flush_seq("chain-a", &tenant, &period_key, node_id)
                    .unwrap(),
                1,
                "each of the three distinct node ids must show exactly one flush of its own; \
                 a shared node id would advance one id's sequence to 3 and leave the other two \
                 at 0 (never written), which the total-only assertion above cannot tell apart \
                 from three-way convergence"
            );
        }
    }

    #[test]
    #[ignore = "needs a real Redis -- see this module's doc comment"]
    fn redis_a_restarted_accumulator_reusing_its_node_id_resumes_rather_than_resetting() {
        let store: Arc<dyn ControlPlaneStore> = Arc::new(test_store("restart-self-heal"));
        let tenant = TenantId::new("tenant-a");
        let now = dt(2026, 9, 7);
        let period_key = Period::Daily.key_for(now);

        {
            let before_restart = SpendAccumulator::new(
                "chain-a".to_string(),
                Arc::clone(&store),
                Period::Daily,
                "node-a".to_string(),
            );
            record_micros(&before_restart, &tenant, now, 3_000_000);
            before_restart.flush_now().unwrap();
            // Dropped at the end of this block -- standing in for the
            // process exiting, per this section's doc comment.
        }

        let after_restart = SpendAccumulator::new(
            "chain-a".to_string(),
            Arc::clone(&store),
            Period::Daily,
            "node-a".to_string(),
        );
        assert_eq!(
            after_restart.current_total(&tenant, &period_key),
            3_000_000,
            "a fresh accumulator over the same store and node_id must resume from the \
             store's own total the moment it touches this bucket, not reset to zero"
        );

        record_micros(&after_restart, &tenant, now, 4_000_000);
        after_restart.flush_now().unwrap();

        assert_eq!(
            store.load_spend("chain-a", &tenant, &period_key).unwrap(),
            7_000_000,
            "the restarted accumulator's flush must land on top of the pre-restart total \
             -- neither resetting it (losing the 3,000,000 already flushed) nor double- \
             charging it (re-sending a total the store already has)"
        );
    }
}
