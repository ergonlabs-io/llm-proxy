package scenarios

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vigneshaigal/llm-proxy/testing/qa/harness"
	"github.com/vigneshaigal/llm-proxy/testing/qa/mocks"
)

// QA-16: chargeback tags as an operator and a finance consumer see them,
// through the real binary's listener, admin API and ledger only.
//
// crates/proxy/tests/ledger_e2e.rs proves one keyed request's tags reach its
// ledger entry. This case adds what that file never switches on: two
// tenants on one chain, a tag change through PUT /keys/{id}/tags, the tag
// header never reaching the provider, a restart over the persistent auth
// store (tagged key rows are a new store row version), and a burst of
// distinct tag values against the whole Prometheus scrape.

const (
	qa16Node       = "qa16-node"
	qa16AdminToken = "qa16-admin-token"
)

type qa16Proxy struct {
	t        *testing.T
	proc     *harness.Proxy
	listen   string
	admin    string
	client   *http.Client
	upstream *mocks.OpenAI
}

func qa16Setup(t *testing.T) func() *qa16Proxy {
	t.Helper()
	upstream := mocks.NewOpenAI()
	t.Cleanup(upstream.Close)
	upstream.NonStreaming = &mocks.ChatCompletion{
		ID: "qa16", Content: "ok",
		Usage: mocks.Usage{PromptTokens: 6, CompletionTokens: 4, TotalTokens: 10},
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "ledger.key")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		t.Fatal(err)
	}
	listen := fmt.Sprintf("127.0.0.1:%d", harness.FreePort(t))
	admin := fmt.Sprintf("127.0.0.1:%d", harness.FreePort(t))
	config := fmt.Sprintf(`version: 1
listen: %s
admin: %s
providers:
  openai:
    type: openai
    base_url: %s
    api_key: sk-qa16-provider-key
routes:
  - { model: "*", provider: openai }
auth:
  hmac_secret: "qa16-hmac-secret"
  store:
    persistent: { path: %s }
  chargeback_tags:
    from_header: true
    max_tags: 3
    max_value_bytes: 16
    allowed:
      - key: team
        values: [infra, search]
      - key: project
ledger:
  directory: %s
  encryption_key_file: %s
  encryption_key_id: qa16-key
  max_disk_bytes: 67108864
  group_commit_interval: 10ms
  on_unavailable: reject
`, listen, admin, upstream.URL(), filepath.Join(dir, "auth.redb"), filepath.Join(dir, "ledger"), keyFile)
	path := harness.WriteConfig(t, "llmproxy.yaml", config)
	t.Setenv("LLMPROXY_ADMIN_TOKEN", qa16AdminToken)
	return func() *qa16Proxy {
		proc := harness.Start(t, harness.StartOpts{
			ConfigPath: path,
			ExtraArgs:  []string{"--service-node", qa16Node, "--drain-time-s", "1"},
		})
		proc.WaitReady(admin, 10*time.Second)
		proc.WaitReady(listen, 10*time.Second)
		return &qa16Proxy{
			t: t, proc: proc, listen: listen, admin: admin, upstream: upstream,
			client: &http.Client{Timeout: 10 * time.Second},
		}
	}
}

// adminCall sends an admin request and fails unless it answers want.
func (p *qa16Proxy) adminCall(method, path, body string, want int) []byte {
	p.t.Helper()
	req, _ := http.NewRequest(method, "http://"+p.admin+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+qa16AdminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		p.t.Fatalf("QA-16: %s %s: %v\n--- proxy log ---\n%s", method, path, err, p.proc.Log())
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		p.t.Fatalf("QA-16: %s %s: status %d, want %d: %s", method, path, resp.StatusCode, want, out)
	}
	return out
}

// chat sends one chat completion as key, with the tag header when header is
// not empty; the request must be served.
func (p *qa16Proxy) chat(key, header string) {
	p.t.Helper()
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	req, _ := http.NewRequest(http.MethodPost, "http://"+p.listen+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	if header != "" {
		req.Header.Set("x-cost-tags", header)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		p.t.Fatalf("QA-16: chat: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		p.t.Fatalf("QA-16: chat with x-cost-tags %q: status %d: %s", header, resp.StatusCode, out)
	}
}

type qa16Entry struct {
	SchemaVersion int `json:"schema_version"`
	Record        struct {
		TenantID string            `json:"tenant_id"`
		KeyID    string            `json:"key_id"`
		Tags     map[string]string `json:"tags"`
	} `json:"record"`
}

// entries waits until the ledger holds n entries and returns them in order.
func (p *qa16Proxy) entries(n int) []qa16Entry {
	p.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var page struct {
			Entries []qa16Entry `json:"entries"`
		}
		out := p.adminCall("GET", "/ledger/entries?after=0&limit=1000", "", http.StatusOK)
		if err := json.Unmarshal(out, &page); err != nil {
			p.t.Fatalf("QA-16: ledger page: %v: %s", err, out)
		}
		if len(page.Entries) >= n {
			return page.Entries
		}
		if time.Now().After(deadline) {
			p.t.Fatalf("QA-16: ledger holds %d entries, want %d", len(page.Entries), n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// series counts the sample lines of one Prometheus scrape.
func (p *qa16Proxy) scrape() string {
	p.t.Helper()
	resp, err := p.client.Get("http://" + p.admin + "/stats/prometheus")
	if err != nil {
		p.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return string(out)
}

func qa16Series(scrape string) int {
	n := 0
	for _, line := range strings.Split(scrape, "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			n++
		}
	}
	return n
}

func qa16WantTags(t *testing.T, step string, got qa16Entry, tenant string, want map[string]string) {
	t.Helper()
	if got.Record.TenantID != tenant || !reflect.DeepEqual(got.Record.Tags, want) {
		t.Fatalf("QA-16 %s: entry tenant %q tags %v, want tenant %q tags %v", step, got.Record.TenantID, got.Record.Tags, tenant, want)
	}
}

func TestQA16ChargebackTags(t *testing.T) {
	start := qa16Setup(t)
	p := start()

	keys := map[string]string{}
	for _, k := range []struct{ tenant, id, tags string }{
		{"acme", "acme-key", `{"team":"infra"}`},
		{"globex", "globex-key", `{}`},
	} {
		p.adminCall("POST", "/tenants", fmt.Sprintf(`{"tenant":%q}`, k.tenant), http.StatusCreated)
		p.adminCall("PUT", "/tenants/"+k.tenant+"/policy", `{"access":"all"}`, http.StatusNoContent)
		var minted struct {
			Key string `json:"key"`
		}
		out := p.adminCall("POST", "/keys", fmt.Sprintf(`{"tenant":%q,"key_id":%q,"tags":%s}`, k.tenant, k.id, k.tags), http.StatusCreated)
		if err := json.Unmarshal(out, &minted); err != nil || minted.Key == "" {
			t.Fatalf("QA-16: POST /keys returned no key: %s", out)
		}
		keys[k.tenant] = minted.Key
	}

	// 1. The admin's team tag wins over the client's; the client adds a project.
	p.chat(keys["acme"], "team=search, project=alpha")
	// 2. The other tenant's key carries only what its own request sent.
	p.chat(keys["globex"], "team=search")
	// 3. Not allow-listed, a value not allowed, and malformed: served, untagged.
	p.chat(keys["globex"], "owner=me,team=ads")
	p.chat(keys["globex"], "team")
	entries := p.entries(4)
	for _, e := range entries {
		if e.SchemaVersion != 2 {
			t.Fatalf("QA-16: ledger entry schema_version %d, want 2", e.SchemaVersion)
		}
	}
	qa16WantTags(t, "key beats header", entries[0], "acme", map[string]string{"team": "infra", "project": "alpha"})
	qa16WantTags(t, "header only", entries[1], "globex", map[string]string{"team": "search"})
	qa16WantTags(t, "refused tags", entries[2], "globex", map[string]string{})
	qa16WantTags(t, "malformed header", entries[3], "globex", map[string]string{})
	for _, r := range p.upstream.Requests() {
		if v := r.Headers.Get("x-cost-tags"); v != "" {
			t.Fatalf("QA-16: the tag header reached the provider: %q", v)
		}
	}

	// 4. Many distinct tag values add no metric series.
	before := qa16Series(p.scrape())
	for i := range 200 {
		p.chat(keys["globex"], fmt.Sprintf("project=p%d,x%d=y", i, i))
	}
	after := p.scrape()
	if got := qa16Series(after); got != before {
		t.Fatalf("QA-16: %d distinct tag values moved the series count from %d to %d", 200, before, got)
	}
	if strings.Contains(after, "p199") {
		t.Fatal("QA-16: a tag value appears in the Prometheus scrape")
	}
	if !strings.Contains(after, `envoy_llmproxy_chargeback_tags_dropped_total{reason="not_allowed"}`) {
		t.Fatalf("QA-16: no not_allowed drop series:\n%s", after)
	}

	// 5. A tag change applies to the next request, and survives a restart
	// over the persistent auth store.
	p.adminCall("PUT", "/keys/acme-key/tags", `{"tags":{"project":"beta"}}`, http.StatusNoContent)
	p.chat(keys["acme"], "project=gamma")
	p.proc.Terminate()
	if code := p.proc.Wait(20 * time.Second); code != 0 {
		t.Fatalf("QA-16: proxy exited %d\n%s", code, p.proc.Log())
	}
	p = start()
	p.chat(keys["acme"], "")
	all := p.entries(4 + 200 + 2)
	qa16WantTags(t, "after PUT", all[len(all)-2], "acme", map[string]string{"project": "beta"})
	qa16WantTags(t, "after restart", all[len(all)-1], "acme", map[string]string{"project": "beta"})
	var listing struct {
		Keys []struct {
			KeyID string            `json:"key_id"`
			Tags  map[string]string `json:"tags"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(p.adminCall("GET", "/keys", "", http.StatusOK), &listing); err != nil {
		t.Fatal(err)
	}
	for _, k := range listing.Keys {
		if k.KeyID == "acme-key" && !reflect.DeepEqual(k.Tags, map[string]string{"project": "beta"}) {
			t.Fatalf("QA-16: GET /keys shows acme-key tags %v", k.Tags)
		}
	}
	p.proc.Terminate()
	p.proc.Wait(20 * time.Second)
}
