//! The billing ledger (ADR-0009) across the real HTTP chain a dialect config
//! builds: auth, spend, usage, the router and access logging, against a mock
//! provider on a loopback socket. Entries go to an in-memory [`LedgerSink`];
//! there is no writer yet. Charges are checked against the spend accumulator
//! the filter wrote, never against a price this test computes from tokens.

use super::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use proxy_filters::auth::{KeyId, TenantId};
use proxy_filters::control::ControlPlane;
use proxy_filters::spend::{MicroUsd, Period, SpendAccumulator, TenantBudget};
use proxy_filters::spend_limit_filter::SharedSpendLimitState;
use proxy_http::{
    filter::RequestHeaders,
    handler::{local_boxed, DownstreamInfo, HttpRequestParts},
    tenant_credentials::CredentialSource,
};
use proxy_observability::records::{ChargeScope, Ledger, LedgerEntry, LedgerSink};
use std::sync::Mutex;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::LocalSet,
};

const TENANT: &str = "acme";
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Nanodollars per token. Not multiples of 1000, so a charge that skipped
/// the round-up, or summed record costs, comes out different.
const INPUT_NANO: u64 = 1_001;
const OUTPUT_NANO: u64 = 2_003;

#[derive(Default)]
struct CaptureLedger(Mutex<Vec<LedgerEntry>>);

impl LedgerSink for CaptureLedger {
    fn append(&self, entry: LedgerEntry) {
        self.0.lock().unwrap().push(entry);
    }
}

impl CaptureLedger {
    fn entries(&self) -> Vec<LedgerEntry> {
        self.0.lock().unwrap().clone()
    }
}

/// A provider that answers by the request's model: `priced-model` with a
/// JSON reply reporting 3 input and 2 output tokens, `cut-model` with two
/// SSE frames and then a reset, `silent-model` never.
struct Provider {
    address: std::net::SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Provider {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Provider {
    async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(Self::serve(socket));
            }
        });
        Self { address, task }
    }

    async fn serve(mut socket: TcpStream) {
        let Some(request) = read_request(&mut socket).await else {
            return;
        };
        if request.contains("silent-model") {
            tokio::time::sleep(Duration::from_secs(30)).await;
        } else if request.contains("cut-model") {
            let frame = r#"data: {"id":"chatcmpl-cut","model":"cut-model","choices":[{"index":0,"delta":{"content":"abcd"}}]}"#;
            let chunk = format!("{frame}\n\n");
            let mut out = String::from(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
            );
            for _ in 0..2 {
                out.push_str(&format!("{:x}\r\n{chunk}\r\n", chunk.len()));
            }
            let _ = socket.write_all(out.as_bytes()).await;
            let _ = socket.flush().await;
            // No terminating chunk: the stream is cut mid-flight.
            tokio::time::sleep(Duration::from_millis(50)).await;
        } else {
            let body = r#"{"id":"chatcmpl-1","object":"chat.completion","model":"priced-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}"#;
            let _ = socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await;
        }
    }
}

/// Reads one request head and its `content-length` body.
async fn read_request(socket: &mut TcpStream) -> Option<String> {
    let mut received = Vec::new();
    let mut byte = [0];
    while !received.ends_with(b"\r\n\r\n") {
        socket.read_exact(&mut byte).await.ok()?;
        received.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&received).to_ascii_lowercase();
    let length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    socket.read_exact(&mut body).await.ok()?;
    received.extend_from_slice(&body);
    Some(String::from_utf8_lossy(&received).into_owned())
}

async fn chain(spend: bool) -> Chain {
    chain_on(spend, r#""127.0.0.1:1""#).await
}

struct Chain {
    handler: Rc<dyn StreamHandler>,
    ledger: Arc<CaptureLedger>,
    control_plane: Arc<ControlPlane>,
    accumulator: Arc<SpendAccumulator>,
    _provider: Provider,
}

/// `spend` decides whether the dialect keeps `llmproxy.spend_limit` in the
/// chain; without it the ledger prices from the usage filter's list cost.
/// `listen` is the dialect `listen:` value.
async fn chain_on(spend: bool, listen: &str) -> Chain {
    let provider = Provider::spawn().await;
    let text = format!(
        r#"version: 0
listen: {listen}
providers:
  openai:
    type: openai
    base_url: http://{upstream}
    api_key: sk-upstream-provider-key
routes:
  - {{ model: "*", provider: openai }}
auth:
  hmac_secret: "ledger-test-secret"
  enforce: {{ tenants_without_policy: allow, spend: {spend} }}
pricing:
  price_list:
    version: ledger-card
    effective_from: "2026-01-01T00:00:00Z"
    entries:
      - provider_type: openai
        model: priced-model
        tier_mode: whole_request
        tiers: [{{ input_nanodollars_per_token: {INPUT_NANO}, cached_input_nanodollars_per_token: 0, cache_write_nanodollars_per_token: 0, output_nanodollars_per_token: {OUTPUT_NANO} }}]
      - provider_type: openai
        model: cut-model
        tier_mode: whole_request
        tiers: [{{ input_nanodollars_per_token: {INPUT_NANO}, cached_input_nanodollars_per_token: 0, cache_write_nanodollars_per_token: 0, output_nanodollars_per_token: {OUTPUT_NANO} }}]
limits:
  - {{ key: tenant, requests_per_minute: 1, models: [limited-model] }}
"#,
        upstream = provider.address,
    );
    let config = proxy_simple_config::parse_simple_config(&text).unwrap();
    let loaded = proxy_simple_config::lower_to_loaded(&config).unwrap();
    let snapshot = proxy_config::build_snapshot(&loaded).unwrap();
    let manager = Arc::new(ClusterManager::with_default_transport(Arc::new(
        proxy_cluster::resolver::TokioResolver,
    )));
    manager.update_from_snapshot(&snapshot.clusters).await;
    for name in snapshot.clusters.keys() {
        manager.force_initialize(name);
    }
    let control = proxy_observability::stats::StatsControl::new(1);
    let router = tests::router_stats_for(&control, &snapshot);
    let token = tests::token_stats_for(&control, &snapshot);
    let latency = tests::latency_stats_for(&control);
    let shared = Arc::new(SharedFactoryState::default());
    let sink = Arc::new(CaptureLedger::default());
    let ledger = Arc::new(Ledger::new(
        "test-instance".to_owned(),
        7,
        sink.clone() as Arc<dyn LedgerSink>,
    ));
    let runtime = HcmRuntime {
        snapshot_version: snapshot.version,
        routes: &snapshot.routes,
        cluster_manager: &manager,
        router_stats: &router,
        token_stats: &token,
        latency_stats: &latency,
        tracing_handles: None,
        metadata: None,
        ledger: Some(&ledger),
        factory_state: &shared,
    };
    let listener = snapshot.listeners.values().next().unwrap();
    let handler = build_listener_hcm(listener, &runtime)
        .unwrap()
        .chain_handlers[0]
        .as_ref()
        .unwrap()
        .clone();
    let control_plane = shared
        .get_across_scopes(proxy_filters::auth_filter::TYPE_URL)
        .unwrap()
        .unwrap()
        .downcast::<ControlPlane>()
        .unwrap();
    // Without a spend filter nothing charges; an accumulator of its own keeps
    // the field uniform and reads zero.
    let accumulator = match shared
        .get_across_scopes(proxy_filters::spend_limit_filter::TYPE_URL)
        .unwrap()
    {
        Some(state) => Arc::clone(
            state
                .downcast::<SharedSpendLimitState>()
                .unwrap()
                .accumulator(),
        ),
        None => Arc::new(SpendAccumulator::new(
            "unused".to_owned(),
            Arc::new(proxy_filters::control::InMemoryControlPlaneStore::default()),
            Period::Monthly,
            "unused".to_owned(),
        )),
    };
    Chain {
        handler,
        ledger: sink,
        control_plane,
        accumulator,
        _provider: provider,
    }
}

impl Chain {
    fn mint(&self, key_id: &str) -> String {
        self.control_plane
            .mint_key(&TenantId::new(TENANT), &KeyId::new(key_id))
            .unwrap()
            .plaintext
    }

    /// Sends one chat request and drains the response, so the stream ends and
    /// its access-log point runs. Returns the status.
    async fn send(&self, key: &str, model: &str, stream: bool) -> u16 {
        let body = format!(
            r#"{{"model":"{model}","stream":{stream},"messages":[{{"role":"user","content":"hello"}}]}}"#
        );
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Bearer {key}").parse().unwrap(),
        );
        headers.insert(
            http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        let request = HttpRequestParts {
            head: RequestHeaders {
                method: http::Method::POST,
                uri: "/v1/chat/completions".parse().unwrap(),
                headers,
            },
            body: local_boxed(Full::new(Bytes::from(body)).map_err(|never| match never {})),
            downstream: DownstreamInfo::loopback(),
            on_upgrade: None,
        };
        let response = tokio::time::timeout(IO_TIMEOUT, self.handler.handle(request))
            .await
            .expect("response head in time");
        let status = response.head.status.as_u16();
        // A cut stream ends in an error; either way the body is finished.
        let _ = tokio::time::timeout(IO_TIMEOUT, response.body.collect())
            .await
            .expect("response body ends in time");
        status
    }

    fn key_spend(&self, key_id: &str, period: &str) -> u64 {
        let period = [Period::Daily, Period::Monthly]
            .into_iter()
            .map(|p| p.key_for_now())
            .find(|key| key.as_str() == period)
            .expect("the scope names the current period");
        self.accumulator
            .current_total_key(&KeyId::new(key_id), &period)
    }

    fn tenant_spend(&self, period: &str) -> u64 {
        let period = [Period::Daily, Period::Monthly]
            .into_iter()
            .map(|p| p.key_for_now())
            .find(|key| key.as_str() == period)
            .expect("the scope names the current period");
        self.accumulator
            .current_total(&TenantId::new(TENANT), &period)
    }
}

fn run(test: impl std::future::Future<Output = ()>) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(LocalSet::new().run_until(test));
}

/// On a spend route the entry carries what the accumulator recorded, for
/// the key and the tenant, with each charge's period.
#[test]
fn a_charged_request_is_entered_at_the_accumulators_amount() {
    run(async {
        let chain = chain(true).await;
        let key = chain.mint("key-a");
        assert_eq!(chain.send(&key, "priced-model", false).await, 200);
        let entries = chain.ledger.entries();
        assert_eq!(entries.len(), 1, "{entries:?}");
        let entry = &entries[0];
        assert!(entry.charged_micro_usd > 0, "{entry:?}");
        let key_scope = entry
            .charged_scopes
            .iter()
            .find(|s| s.scope == ChargeScope::Key)
            .expect("the key was charged");
        assert_eq!(key_scope.id, "key-a");
        assert_eq!(
            entry.charged_micro_usd,
            chain.key_spend("key-a", &key_scope.period)
        );
        let tenant_scope = entry
            .charged_scopes
            .iter()
            .find(|s| s.scope == ChargeScope::Tenant)
            .expect("the tenant was charged");
        assert_eq!(tenant_scope.id, TENANT);
        assert_eq!(
            entry.charged_micro_usd,
            chain.tenant_spend(&tenant_scope.period)
        );
        assert_eq!(entry.record.user_id.as_deref(), Some("key-a"));
        assert_eq!(entry.record.cost.as_ref().unwrap().kind, "list");
        assert!(entry
            .rate_card_version
            .as_deref()
            .is_some_and(|v| v.starts_with("ledger-card")));
        assert_eq!(entry.policy_generation, entry.record.policy_generation);
        assert!(entry.policy_generation.is_some());
        assert_eq!(
            (entry.instance_id.as_str(), entry.epoch),
            ("test-instance", 7)
        );
    });
}

/// Without a spend filter the entry is the list price rounded up to
/// micro-USD: (3 * 1001 + 2 * 2003) nanodollars = 7009, charged as 8.
#[test]
fn without_a_spend_filter_the_entry_is_the_list_price_rounded_up() {
    run(async {
        let chain = chain(false).await;
        let key = chain.mint("key-a");
        assert_eq!(chain.send(&key, "priced-model", false).await, 200);
        let entries = chain.ledger.entries();
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].record.cost.as_ref().unwrap().amount, 7_009);
        assert_eq!(entries[0].charged_micro_usd, 8);
        assert!(entries[0].charged_scopes.is_empty());
    });
}

/// A stream cut after headers is charged its estimate, and the entry says so.
#[test]
fn a_cut_stream_is_entered_at_its_estimate_charge() {
    run(async {
        let chain = chain(true).await;
        let key = chain.mint("key-a");
        chain.send(&key, "cut-model", true).await;
        let entries = chain.ledger.entries();
        assert_eq!(entries.len(), 1, "{entries:?}");
        let entry = &entries[0];
        assert_eq!(entry.record.cost.as_ref().unwrap().kind, "estimate");
        let key_scope = entry
            .charged_scopes
            .iter()
            .find(|s| s.scope == ChargeScope::Key)
            .expect("the key was charged");
        assert!(entry.charged_micro_usd > 0, "{entry:?}");
        assert_eq!(
            entry.charged_micro_usd,
            chain.key_spend("key-a", &key_scope.period)
        );
    });
}

/// A provider that never answers is still dialled: the entry exists and is
/// charged nothing.
#[test]
fn a_timeout_before_response_headers_is_entered_at_zero() {
    run(async {
        let chain = chain_on(
            true,
            r#"{ address: "127.0.0.1:1", max_stream_duration: 300ms }"#,
        )
        .await;
        let key = chain.mint("key-a");
        let status = chain.send(&key, "silent-model", false).await;
        assert!(status >= 400, "status {status}");
        let entries = chain.ledger.entries();
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].charged_micro_usd, 0);
        assert!(entries[0].record.usage.is_none());
    });
}

/// Refusals before dialling (unknown key, exhausted budget, rate limit) get
/// no entry,
/// and the entries around them still number without a gap.
#[test]
fn refused_requests_get_no_entry_and_seq_has_no_gaps() {
    run(async {
        let chain = chain(true).await;
        let key = chain.mint("key-a");
        let broke = chain.mint("key-broke");
        chain
            .control_plane
            .set_key_budget(
                &KeyId::new("key-broke"),
                Some(&TenantBudget {
                    max_micros: MicroUsd::from_micros(0),
                    period: Period::Daily,
                    credential_source: CredentialSource::Platform,
                }),
            )
            .unwrap();

        assert_eq!(chain.send(&key, "priced-model", false).await, 200);
        assert_eq!(
            chain.send("llmp_not-a-key", "priced-model", false).await,
            401
        );
        assert_eq!(chain.send(&key, "priced-model", false).await, 200);
        let refused = chain.send(&broke, "priced-model", false).await;
        assert!(
            (400..500).contains(&refused) && refused != 401,
            "budget refusal, got {refused}"
        );
        assert_eq!(chain.send(&key, "limited-model", false).await, 200);
        assert_eq!(chain.send(&key, "limited-model", false).await, 429);
        assert_eq!(chain.send(&key, "priced-model", false).await, 200);

        let entries = chain.ledger.entries();
        assert_eq!(
            entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [0, 1, 2, 3],
            "{entries:?}"
        );
        assert!(entries
            .iter()
            .all(|e| e.record.key_id.as_deref() == Some("key-a")));
    });
}
