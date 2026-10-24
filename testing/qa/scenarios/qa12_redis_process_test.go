package scenarios

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/ergonlabs-io/llm-proxy/testing/qa/harness"
	"github.com/ergonlabs-io/llm-proxy/testing/qa/mocks"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Three OS processes admit against stale local snapshots during the partition.
// $12 against an $8 ceiling demonstrates completion-accounting/outage overspend,
// rather than claiming a strict reservation ceiling.
func TestQA12_RedisProcessPartitionRecovery(t *testing.T) {
	addr := os.Getenv("QA_REDIS_ADDR")
	if addr == "" {
		t.Skip("set QA_REDIS_ADDR to an isolated Redis address to run the process drill")
	}
	ns := fmt.Sprintf("qa12-%d-%d", os.Getpid(), time.Now().UnixNano())
	redis := func(args ...string) string { return qa11Redis(t, addr, args...) }
	redis("PING")
	period := time.Now().UTC().Format("2006-01-02")
	tag := "{llmproxy|\x1fkey:key-a|" + period + "}"
	ledger, sequence := ns+":spend:"+tag, ns+":seq:"+tag
	t.Cleanup(func() { qa11CleanupRedis(t, addr, ns) })
	const secret = "qa12-hmac-secret"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("llmp_key-a"))
	digest := make([]int, sha256.Size)
	for i, b := range mac.Sum(nil) {
		digest[i] = int(b)
	}
	row, _ := json.Marshal(map[string]any{"digest": digest, "tenant": "tenant-a", "revoked": false})
	redis("SADD", ns+":tenants", "tenant-a")
	redis("HSET", ns+":keys", "key-a", string(row))
	relay := qa12NewRelay(t, addr)
	upstream := mocks.NewOpenAI()
	defer upstream.Close()
	upstream.NonStreaming = &mocks.ChatCompletion{ID: "qa12", Content: "ok", Usage: mocks.Usage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2}}
	host, port, err := net.SplitHostPort(strings.TrimPrefix(upstream.URL(), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("LLMPROXY_ADMIN_TOKEN", "qa12-admin")
	type replica struct {
		listener, admin int
		node, path      string
		proxy           *harness.Proxy
	}
	var replicas [3]replica
	for i := range replicas {
		r := &replicas[i]
		r.listener, r.admin = harness.FreePort(t), harness.FreePort(t)
		r.node = fmt.Sprintf("qa12-node-%d", i)
		journal := filepath.Join(t.TempDir(), "spend.redb")
		config := fmt.Sprintf(`
node: {id: %s}
admin:
  address: {socket_address: {address: 127.0.0.1, port_value: %d}}
static_resources:
  clusters:
  - name: openai
    type: STATIC
    connect_timeout: 1s
    load_assignment:
      cluster_name: openai
      endpoints:
      - lb_endpoints:
        - endpoint:
            address: {socket_address: {address: %s, port_value: %s}}
  listeners:
  - name: qa12
    address: {socket_address: {address: 127.0.0.1, port_value: %d}}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          '@type': type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: llmproxy
          route_config:
            name: qa12
            virtual_hosts:
            - name: qa12
              domains: ['*']
              routes:
              - match: {prefix: /}
                route: {cluster: openai}
          http_filters:
          - name: llmproxy.auth
            typed_config:
              '@type': type.llmproxy.dev/llmproxy.filters.v0.Authentication
              hmac_secret: {inline_string: %s}
              shared:
                url: {inline_string: 'redis://%s/'}
                namespace: %s
              poll_interval_seconds: 1
          - name: llmproxy.body_rewrite
            typed_config:
              '@type': type.llmproxy.dev/envoy.config.core.v3.RuntimeFeatureFlag
              default_value: true
              runtime_key: openai
          - name: llmproxy.spend_limit
            typed_config:
              '@type': type.llmproxy.dev/llmproxy.filters.v0.SpendLimit
              legacy_tenant_budget_cutover: START_KEYS_FRESH
              flush_interval_seconds: 1
              reconciliation_bound_seconds: 1
              recovery_journal_path: '%s'
          - name: llmproxy.usage
            typed_config:
              '@type': type.llmproxy.dev/llmproxy.filters.v0.Usage
              dialect: openai
              # $1 per token in and out, so 1 token costs 1,000,000 micro-USD.
              pricing_json: '{"price_list":{"effective_from":"2026-01-01T00:00:00Z","entries":[{"provider_type":"openai","model":"gpt-test","tier_mode":"whole_request","tiers":[{"input_nanodollars_per_token":1000000000,"cached_input_nanodollars_per_token":0,"cache_write_nanodollars_per_token":0,"output_nanodollars_per_token":1000000000}]}]},"providers":{"openai":"openai"}}'
          - name: envoy.filters.http.router
            typed_config:
              '@type': type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
`, r.node, r.admin, host, port, r.listener, secret, relay.listener.Addr(), ns, journal)
		r.path = harness.WriteConfig(t, fmt.Sprintf("replica-%d.yaml", i), config)
	}
	start := func(r *replica) {
		r.proxy = harness.Start(t, harness.StartOpts{BootstrapPath: r.path, ExtraArgs: []string{"--service-node", r.node, "--drain-time-s", "1"}})
		r.proxy.WaitReady(fmt.Sprintf("127.0.0.1:%d", r.admin), 10*time.Second)
		r.proxy.WaitReady(fmt.Sprintf("127.0.0.1:%d", r.listener), 10*time.Second)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	request := func(r *replica, method, path, body string, want int) []byte {
		t.Helper()
		port, token := r.admin, "qa12-admin"
		if method == "POST" {
			port, token = r.listener, "llmp_key-a"
		}
		req, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-llmproxy-model", "gpt-test")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != want {
			t.Fatalf("%s %s %s: status %d want %d: %s; log: %s", r.node, method, path, res.StatusCode, want, data, r.proxy.Log())
		}
		return data
	}
	type report struct {
		Spend      *uint64    `json:"spend_micro_usd"`
		Budget     *uint64    `json:"budget_micro_usd"`
		Age        *uint64    `json:"reconciliation_age_seconds"`
		Expired    *bool      `json:"reconciliation_expired"`
		Admissions *uint64    `json:"unreconciled_admissions"`
		Checkpoint *time.Time `json:"journal_checkpoint_at"`
		Pending    *uint64    `json:"journal_pending_micro_usd"`
		Rows       *uint64    `json:"journal_pending_rows"`
	}
	read := func(r *replica) report {
		data := request(r, "GET", "/keys/key-a/spend", "", 200)
		var out report
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatal(err)
		}
		if out.Spend == nil || out.Age == nil || out.Expired == nil || out.Admissions == nil || out.Pending == nil || out.Rows == nil {
			t.Fatalf("missing spend/recovery observability: %s", data)
		}
		return out
	}
	poll := func(label string, condition func() bool) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for !condition() {
			if time.Now().After(deadline) {
				for i := range replicas {
					t.Logf("%s: %s", replicas[i].node, replicas[i].proxy.Log())
				}
				t.Fatal(label)
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	chat := func(r *replica, status int) {
		request(r, "POST", "/v1/chat/completions", `{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]}`, status)
	}
	for i := range replicas {
		start(&replicas[i])
	}
	request(&replicas[0], "PUT", "/keys/key-a/budget", `{"budget":{"max_usd":"8.00","period":"daily"}}`, 204)
	for i := range replicas {
		r := &replicas[i]
		poll("budget did not propagate", func() bool { x := read(r); return x.Budget != nil && *x.Budget == 8000000 })
	}
	for i := range replicas {
		chat(&replicas[i], 200)
	}
	poll("initial three-writer charges did not converge", func() bool {
		if redis("GET", ledger) != "6000000" {
			return false
		}
		for i := range replicas {
			if *read(&replicas[i]).Spend != 6000000 {
				return false
			}
		}
		return true
	})
	var before [3]int
	for i := range replicas {
		before[i], err = strconv.Atoi(redis("HGET", sequence, replicas[i].node))
		if err != nil || before[i] < 1 {
			t.Fatalf("missing writer sequence %s", replicas[i].node)
		}
	}
	relay.setAvailable(false)
	for i := range replicas {
		r := &replicas[i]
		poll("partition did not become observable", func() bool { x := read(r); return *x.Expired && *x.Age >= 1 })
	}
	for i := range replicas {
		r := &replicas[i]
		chat(r, 200)
		chat(r, 429)
	}
	completed := time.Now()
	for i := range replicas {
		r := &replicas[i]
		poll("outage backlog was not durably checkpointed", func() bool {
			x := read(r)
			return *x.Spend == 8000000 && *x.Admissions >= 1 && *x.Pending == 2000000 && *x.Rows >= 1 && x.Checkpoint != nil && x.Checkpoint.After(completed)
		})
	}
	if redis("GET", ledger) != "6000000" {
		t.Fatal("partition charges escaped relay")
	}
	replicas[0].proxy.Signal(syscall.SIGKILL)
	if replicas[0].proxy.Wait(5*time.Second) != -1 {
		t.Fatal("expected signal exit")
	}
	relay.setAvailable(true)
	// Shared authentication bootstrap remains fail-closed during an outage.
	start(&replicas[0])
	poll("journal replay and reconnect did not converge exactly", func() bool {
		if redis("GET", ledger) != "12000000" {
			return false
		}
		for i := range replicas {
			x := read(&replicas[i])
			if *x.Spend != 12000000 || *x.Pending != 0 || *x.Rows != 0 || *x.Expired {
				return false
			}
		}
		return true
	})
	for i := range replicas {
		after, e := strconv.Atoi(redis("HGET", sequence, replicas[i].node))
		if e != nil || after <= before[i] {
			t.Fatalf("writer %s sequence failed to advance: %d -> %d (%v)", replicas[i].node, before[i], after, e)
		}
		chat(&replicas[i], 429)
	}
	// A second clean restart must not replay the acknowledged journal again.
	replicas[0].proxy.Terminate()
	if replicas[0].proxy.Wait(10*time.Second) != 0 {
		t.Fatal(replicas[0].proxy.Log())
	}
	start(&replicas[0])
	poll("clean restart did not restore reconciled ledger", func() bool { x := read(&replicas[0]); return *x.Spend == 12000000 && !*x.Expired })
	for i := range replicas {
		replicas[i].proxy.Terminate()
		if replicas[i].proxy.Wait(10*time.Second) != 0 {
			t.Fatal(replicas[i].proxy.Log())
		}
	}
	if redis("GET", ledger) != "12000000" {
		t.Fatal("replay duplicated or dropped spend")
	}
	if len(upstream.Requests()) != 6 {
		t.Fatalf("denied requests reached upstream: %d", len(upstream.Requests()))
	}
}

// Retain the same address while closing both sides of every pooled connection.
type qa12Relay struct {
	listener  net.Listener
	target    string
	mu        sync.Mutex
	available bool
	sockets   map[net.Conn]bool
}

func qa12NewRelay(t *testing.T, target string) *qa12Relay {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &qa12Relay{listener: listener, target: target, available: true, sockets: make(map[net.Conn]bool)}
	t.Cleanup(func() { listener.Close(); r.setAvailable(false) })
	go func() {
		for {
			downstream, err := listener.Accept()
			if err != nil {
				return
			}
			go r.forward(downstream)
		}
	}()
	return r
}
func (r *qa12Relay) setAvailable(available bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.available = available
	if !available {
		for socket := range r.sockets {
			socket.Close()
		}
	}
}
func (r *qa12Relay) forward(downstream net.Conn) {
	defer downstream.Close()
	r.mu.Lock()
	if !r.available {
		r.mu.Unlock()
		return
	}
	r.sockets[downstream] = true
	r.mu.Unlock()
	defer func() { r.mu.Lock(); delete(r.sockets, downstream); r.mu.Unlock() }()
	upstream, err := net.DialTimeout("tcp", r.target, time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	r.mu.Lock()
	if !r.available {
		r.mu.Unlock()
		return
	}
	r.sockets[upstream] = true
	r.mu.Unlock()
	defer func() { r.mu.Lock(); delete(r.sockets, upstream); r.mu.Unlock() }()
	done := make(chan struct{})
	go func() { io.Copy(upstream, downstream); upstream.Close(); close(done) }()
	io.Copy(downstream, upstream)
	downstream.Close()
	<-done
}
