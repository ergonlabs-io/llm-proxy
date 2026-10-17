package scenarios

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vigneshaigal/llm-proxy/testing/qa/harness"
	"github.com/vigneshaigal/llm-proxy/testing/qa/mocks"
)

// This drill deliberately kills only AFTER Redis acknowledges the charge.
// It proves persisted spend recovery, not recovery of an unflushed RAM backlog.
// Legacy tenant history has no key attribution: the operator explicitly starts
// fresh key budgets at cutover, retaining the legacy rows without copying them.
func TestQA11_RedisSpendMigrationRestart(t *testing.T) {
	addr := os.Getenv("QA_REDIS_ADDR")
	if addr == "" {
		t.Skip("set QA_REDIS_ADDR to an isolated Redis address to run the process drill")
	}
	ns := fmt.Sprintf("qa11-%d-%d", os.Getpid(), time.Now().UnixNano())
	redis := func(args ...string) string { return qa11Redis(t, addr, args...) }
	redis("PING")
	period := time.Now().UTC().Format("2006-01-02")
	legacy := ns + ":spend:{llmproxy|tenant-a|" + period + "}"
	redis("SADD", ns+":tenants", "tenant-a")
	redis("HSET", ns+":budgets", "tenant-a", `{"max_micros":1000000,"period":"Daily"}`)
	redis("SET", legacy, "9000000")
	const secret = "qa11-hmac-secret"
	for _, id := range []string{"key-a", "key-b"} {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte("llmp_" + id))
		digest := mac.Sum(nil)
		bytes := make([]int, len(digest))
		for i, b := range digest {
			bytes[i] = int(b)
		}
		row, _ := json.Marshal(map[string]any{"digest": bytes, "tenant": "tenant-a", "revoked": false})
		redis("HSET", ns+":keys", id, string(row))
	}
	t.Cleanup(func() {
		qa11CleanupRedis(t, addr, ns)
	})
	upstream := mocks.NewOpenAI()
	defer upstream.Close()
	upstream.NonStreaming = &mocks.ChatCompletion{ID: "qa11", Content: "ok", Usage: mocks.Usage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2}}
	listener, admin := harness.FreePort(t), harness.FreePort(t)
	upstreamAddr := strings.TrimPrefix(upstream.URL(), "http://")
	host, port, err := net.SplitHostPort(upstreamAddr)
	if err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`
node: {id: qa11-stable-node}
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
  - name: qa11
    address: {socket_address: {address: 127.0.0.1, port_value: %d}}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          '@type': type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: llmproxy
          route_config:
            name: qa11
            virtual_hosts:
            - name: qa11
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
          - name: llmproxy.usage
            typed_config:
              '@type': type.llmproxy.dev/llmproxy.filters.v0.Usage
              dialect: openai
              # $1 per token in and out, so 1 token costs 1,000,000 micro-USD.
              pricing_json: '{"price_list":{"effective_from":"2026-01-01T00:00:00Z","entries":[{"provider_type":"openai","model":"gpt-test","tier_mode":"whole_request","tiers":[{"input_nanodollars_per_token":1000000000,"cached_input_nanodollars_per_token":0,"cache_write_nanodollars_per_token":0,"output_nanodollars_per_token":1000000000}]}]},"providers":{"openai":"openai"}}'
          - name: envoy.filters.http.router
            typed_config:
              '@type': type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
`, admin, host, port, listener, secret, addr, ns)
	path := harness.WriteConfig(t, "redis.yaml", config)
	t.Setenv("LLMPROXY_ADMIN_TOKEN", "qa11-admin")
	start := func() *harness.Proxy {
		p := harness.Start(t, harness.StartOpts{BootstrapPath: path, ExtraArgs: []string{"--service-node", "qa11-stable-node", "--drain-time-s", "1"}})
		p.WaitReady(fmt.Sprintf("127.0.0.1:%d", admin), 10*time.Second)
		p.WaitReady(fmt.Sprintf("127.0.0.1:%d", listener), 10*time.Second)
		return p
	}
	client := &http.Client{Timeout: 5 * time.Second}
	request := func(method, url, token, body string, want int) []byte {
		t.Helper()
		req, err := http.NewRequest(method, url, strings.NewReader(body))
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
			t.Fatalf("%s %s: status %d want %d: %s", method, url, res.StatusCode, want, data)
		}
		return data
	}
	adminURL := fmt.Sprintf("http://127.0.0.1:%d", admin)
	chat := func(id string, status int) {
		request("POST", fmt.Sprintf("http://127.0.0.1:%d/v1/chat/completions", listener), "llmp_"+id, `{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]}`, status)
	}
	spend := func(id string) uint64 {
		data := request("GET", adminURL+"/keys/"+id+"/spend", "qa11-admin", "", 200)
		var report struct {
			Spend *uint64 `json:"spend_micro_usd"`
		}
		if err := json.Unmarshal(data, &report); err != nil {
			t.Fatal(err)
		}
		if report.Spend == nil {
			t.Fatalf("missing spend_micro_usd: %s", data)
		}
		return *report.Spend
	}
	p := start()
	for _, id := range []string{"key-a", "key-b"} {
		request("PUT", adminURL+"/keys/"+id+"/budget", "qa11-admin", `{"budget":{"max_usd":"2.00","period":"daily"}}`, 204)
		if got := spend(id); got != 0 {
			t.Fatalf("cutover %s inherited %d legacy micros", id, got)
		}
	}
	chat("key-a", 200)
	// Gate SIGKILL on the persisted ledger, not a sleep or an admin RAM read.
	persisted := ns + ":spend:{llmproxy|\x1fkey:key-a|" + period + "}"
	deadline := time.Now().Add(10 * time.Second)
	for redis("GET", persisted) != "2000000" {
		if time.Now().After(deadline) {
			t.Fatalf("key charge never persisted; proxy log: %s", p.Log())
		}
		time.Sleep(20 * time.Millisecond)
	}
	seq := ns + ":seq:{llmproxy|\x1fkey:key-a|" + period + "}"
	before, err := strconv.Atoi(redis("HGET", seq, "qa11-stable-node"))
	if err != nil || before < 1 {
		t.Fatalf("missing stable writer sequence: %v, %d", err, before)
	}
	p.Signal(syscall.SIGKILL)
	if p.Wait(5*time.Second) != -1 {
		t.Fatal("expected signal exit")
	}
	p = start()
	if got := spend("key-a"); got != 2000000 {
		t.Fatalf("restart forgot key-a: %d", got)
	}
	if got := spend("key-b"); got != 0 {
		t.Fatalf("restart merged key-b: %d", got)
	}
	chat("key-a", 429)
	chat("key-b", 200)
	chat("key-b", 429)
	// Raise A's ceiling to exercise sequence continuation and additive recovery.
	request("PUT", adminURL+"/keys/key-a/budget", "qa11-admin", `{"budget":{"max_usd":"4.00","period":"daily"}}`, 204)
	chat("key-a", 200)
	deadline = time.Now().Add(10 * time.Second)
	for redis("GET", persisted) != "4000000" {
		if time.Now().After(deadline) {
			t.Fatalf("restart flush lost or duplicated charge; log: %s", p.Log())
		}
		time.Sleep(20 * time.Millisecond)
	}
	after, err := strconv.Atoi(redis("HGET", seq, "qa11-stable-node"))
	if err != nil || after <= before {
		t.Fatalf("writer sequence did not advance: %d -> %d (%v)", before, after, err)
	}
	chat("key-a", 429)
	if redis("GET", legacy) != "9000000" {
		t.Fatal("legacy tenant history changed")
	}
	if redis("HGET", ns+":budgets", "tenant-a") != `{"max_micros":1000000,"period":"Daily"}` {
		t.Fatal("legacy budget changed")
	}
	rotated := request("POST", adminURL+"/keys", "qa11-admin", `{"schema_version":2,"tenant":"tenant-a","key_id":"key-a"}`, 201)
	var minted struct {
		Key     string `json:"key"`
		Version int    `json:"schema_version"`
	}
	if err := json.Unmarshal(rotated, &minted); err != nil {
		t.Fatal(err)
	}
	if minted.Key == "" || minted.Version != 2 {
		t.Fatalf("invalid rotation response: %s", rotated)
	}
	chat("key-a", 401)
	request("POST", fmt.Sprintf("http://127.0.0.1:%d/v1/chat/completions", listener), minted.Key, `{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]}`, 429)
	if spend("key-a") != 4000000 {
		t.Fatal("rotation reset key spend")
	}
	request("POST", adminURL+"/keys", "qa11-admin", `{"tenant":"tenant-b","key_id":"key-a"}`, 409)
	request("DELETE", adminURL+"/keys/key-a", "qa11-admin", "", 204)
	request("POST", adminURL+"/keys", "qa11-admin", `{"tenant":"tenant-a","key_id":"key-a"}`, 409)
	p.Terminate()
	if p.Wait(10*time.Second) != 0 {
		t.Fatal(p.Log())
	}
	if redis("GET", ns+":spend:{llmproxy|\x1fkey:key-b|"+period+"}") != "2000000" {
		t.Fatal("key-b charge did not persist independently")
	}
	if len(upstream.Requests()) != 3 {
		t.Fatalf("denied requests reached upstream: %d", len(upstream.Requests()))
	}
}

// Minimal RESP2 command client keeps the black-box suite dependency-free.
// Each call has a deadline and a fresh socket; errors never look like nil rows.
func qa11Redis(t *testing.T, addr string, args ...string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	var command strings.Builder
	fmt.Fprintf(&command, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&command, "$%d\r\n%s\r\n", len(arg), arg)
	}
	if _, err := io.WriteString(conn, command.String()); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	line = strings.TrimSuffix(line, "\r\n")
	switch line[0] {
	case '+', ':':
		return line[1:]
	case '-':
		t.Fatalf("Redis %s: %s", args[0], line[1:])
	case '$':
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			t.Fatal(err)
		}
		if n == -1 {
			return ""
		}
		if n < 0 {
			t.Fatal("invalid Redis length")
		}
		body := make([]byte, n+2)
		if _, err := io.ReadFull(reader, body); err != nil {
			t.Fatal(err)
		}
		return string(body[:n])
	case '*':
		n, err := strconv.Atoi(line[1:])
		if err != nil || n < 0 {
			t.Fatalf("invalid Redis array: %q", line)
		}
		items := make([]string, 0, n)
		for i := 0; i < n; i++ {
			header, err := reader.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if len(header) < 3 || header[0] != '$' {
				t.Fatalf("expected bulk Redis key: %q", header)
			}
			length, err := strconv.Atoi(strings.TrimSuffix(header[1:], "\r\n"))
			if err != nil || length < 0 {
				t.Fatal("invalid Redis key length")
			}
			body := make([]byte, length+2)
			if _, err := io.ReadFull(reader, body); err != nil {
				t.Fatal(err)
			}
			items = append(items, string(body[:length]))
		}
		encoded, err := json.Marshal(items)
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	default:
		t.Fatalf("unexpected Redis response: %q", line)
	}
	return ""
}

// The Redis instance must be disposable. Remove every row in our unique
// namespace, including zero-charge windows prefetched by the production flusher.
func qa11CleanupRedis(t *testing.T, addr, namespace string) {
	t.Helper()
	var keys []string
	if err := json.Unmarshal([]byte(qa11Redis(t, addr, "KEYS", namespace+":*")), &keys); err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if !strings.HasPrefix(key, namespace+":") {
			t.Fatal("Redis cleanup escaped its namespace")
		}
	}
	if len(keys) != 0 {
		qa11Redis(t, addr, append([]string{"DEL"}, keys...)...)
	}
}
