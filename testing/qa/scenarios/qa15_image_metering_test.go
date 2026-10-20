package scenarios

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigneshaigal/llm-proxy/testing/qa/harness"
)

// QA-15: image generation under a tenant spend budget (ADR-0010 phase 2), as
// a tenant and a billing consumer see it, through the real binary's listener
// and admin API only.
//
// A per-image rate card prices the images the provider returned, at the
// dialled provider's entry. The charge reaches the tenant's spend and the
// ledger entry, and the entry says what was bought (2 images, 1024x1024).
// An image model the card does not price is still served, charged $0, and
// named in a warning. Batch stays refused under the same budget.

const (
	qa15AdminToken = "qa15-admin-token"
	qa15Node       = "qa15-node"
	// Example value, not a provider's rate: 0.04 USD per 1024x1024 image.
	qa15ImageNanodollars = 40_000_000
)

type qa15Proxy struct {
	t      *testing.T
	proc   *harness.Proxy
	listen string
	admin  string
	client *http.Client
}

// qa15Upstream answers image generations with two base64 images and no
// usage object, the shape of a per-image provider, and counts every request
// it receives.
func qa15Upstream(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	hits := new(atomic.Int64)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		hits.Add(1)
		if r.URL.Path != "/v1/images/generations" {
			http.Error(w, "mock: unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		// Large enough that the body is far past the text endpoints' JSON
		// buffer: the usage filter must count it without holding it.
		b64 := strings.Repeat("A", 3<<20)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"created":1,"data":[{"b64_json":"%s"},{"b64_json":"%s"}]}`, b64, b64)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, hits
}

func qa15Start(t *testing.T, upstream string) *qa15Proxy {
	t.Helper()
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
	config := fmt.Sprintf(`version: 0
listen: %s
admin: %s
providers:
  openai:
    type: openai
    base_url: %s
    api_key: sk-qa15-provider-key
routes:
  - { model: "*", provider: openai }
auth:
  hmac_secret: "qa15-hmac-secret"
  enforce: { object_ownership: false }
pricing:
  price_list:
    version: qa15
    effective_from: "2026-01-01T00:00:00Z"
    entries:
      - provider_type: openai
        model: gpt-image-1
        basis: images
        image_prices:
          - { size: "1024x1024", nanodollars_per_image: %d }
ledger:
  directory: %s
  encryption_key_file: %s
  encryption_key_id: qa15-key
  max_disk_bytes: 67108864
  group_commit_interval: 10ms
  on_unavailable: reject
`, listen, admin, upstream, qa15ImageNanodollars, filepath.Join(dir, "ledger"), keyFile)
	path := harness.WriteConfig(t, "llmproxy.yaml", config)
	t.Setenv("LLMPROXY_ADMIN_TOKEN", qa15AdminToken)
	proc := harness.Start(t, harness.StartOpts{
		ConfigPath: path,
		ExtraArgs:  []string{"--service-node", qa15Node},
	})
	proc.WaitReady(admin, 10*time.Second)
	proc.WaitReady(listen, 10*time.Second)
	return &qa15Proxy{t: t, proc: proc, listen: listen, admin: admin, client: &http.Client{Timeout: 30 * time.Second}}
}

// call sends one request and returns its status and body.
func (p *qa15Proxy) call(addr, method, path, bearer, body string) (int, string) {
	p.t.Helper()
	req, err := http.NewRequest(method, "http://"+addr+path, strings.NewReader(body))
	if err != nil {
		p.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		p.t.Fatalf("%s %s: %v\n--- proxy log ---\n%s", method, path, err, p.proc.Log())
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (p *qa15Proxy) admin200(method, path, body string, want int) string {
	p.t.Helper()
	status, resp := p.call(p.admin, method, path, qa15AdminToken, body)
	if status != want {
		p.t.Fatalf("%s %s: status %d, want %d: %s", method, path, status, want, resp)
	}
	return resp
}

// tenantKey creates tenant t1 with every model granted and a key for it.
func (p *qa15Proxy) tenantKey() string {
	p.t.Helper()
	var minted struct {
		Key string `json:"key"`
	}
	resp := p.admin200("POST", "/keys", `{"tenant":"t1","key_id":"qa15-key"}`, http.StatusCreated)
	if err := json.Unmarshal([]byte(resp), &minted); err != nil {
		p.t.Fatal(err)
	}
	if status, body := p.call(p.admin, "POST", "/tenants", qa15AdminToken, `{"tenant":"t1"}`); status/100 != 2 {
		p.t.Fatalf("POST /tenants: %d %s", status, body)
	}
	p.admin200("PUT", "/tenants/t1/policy", `{"access":"all"}`, http.StatusNoContent)
	return minted.Key
}

type qa15Entry struct {
	ChargedMicroUSD uint64 `json:"charged_micro_usd"`
	ChargedScopes   []struct {
		Scope string `json:"scope"`
	} `json:"charged_scopes"`
	Record struct {
		Endpoint   string `json:"endpoint"`
		PriceBasis string `json:"price_basis"`
		Usage      struct {
			Images    *uint64 `json:"images"`
			ImageSize string  `json:"image_size"`
		} `json:"usage"`
	} `json:"record"`
}

// entries polls the ledger until it holds want entries.
func (p *qa15Proxy) entries(want int) []qa15Entry {
	p.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var page struct {
			Entries []qa15Entry `json:"entries"`
		}
		resp := p.admin200("GET", "/ledger/entries?after=0&limit=100", "", http.StatusOK)
		if err := json.Unmarshal([]byte(resp), &page); err != nil {
			p.t.Fatal(err)
		}
		if len(page.Entries) >= want {
			return page.Entries
		}
		if time.Now().After(deadline) {
			p.t.Fatalf("ledger holds %d entries, want %d: %s\n--- proxy log ---\n%s", len(page.Entries), want, resp, p.proc.Log())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestQA15_ImageGenerationUnderABudgetIsChargedAndLedgered is the v0.6.0
// ship-gate case for images: a non-zero charge at the dialled provider's rate
// card, in the ledger entry, with an unpriced model loud and batch refused.
func TestQA15_ImageGenerationUnderABudgetIsChargedAndLedgered(t *testing.T) {
	upstream, hits := qa15Upstream(t)
	p := qa15Start(t, upstream.URL)
	key := p.tenantKey()
	p.admin200("PUT", "/tenants/t1/budget", `{"budget":{"max_usd":"100","period":"daily"}}`, http.StatusNoContent)

	status, body := p.call(p.listen, "POST", "/v1/images/generations", key,
		`{"model":"gpt-image-1","prompt":"a cat","n":2,"size":"1024x1024"}`)
	if status != http.StatusOK {
		t.Fatalf("image generation under a budget: %d %s", status, body[:min(len(body), 500)])
	}
	entry := p.entries(1)[0]
	want := uint64(2 * qa15ImageNanodollars / 1000)
	if entry.ChargedMicroUSD != want {
		t.Errorf("charged_micro_usd = %d, want %d (2 images at the card's price)", entry.ChargedMicroUSD, want)
	}
	tenantCharged := false
	for _, scope := range entry.ChargedScopes {
		tenantCharged = tenantCharged || scope.Scope == "tenant"
	}
	if !tenantCharged {
		t.Errorf("the tenant budget was not among the charged scopes: %+v", entry.ChargedScopes)
	}
	if u := entry.Record.Usage; u.Images == nil || *u.Images != 2 || u.ImageSize != "1024x1024" {
		t.Errorf("the entry does not say what was bought: %+v", entry.Record.Usage)
	}
	if entry.Record.Endpoint != "image_generation" || entry.Record.PriceBasis != "images" {
		t.Errorf("endpoint %q, price_basis %q", entry.Record.Endpoint, entry.Record.PriceBasis)
	}
	// An image model the card does not price: served, charged $0, and loud.
	status, body = p.call(p.listen, "POST", "/v1/images/generations", key,
		`{"model":"unpriced-image-model","prompt":"a dog","size":"1024x1024"}`)
	if status != http.StatusOK {
		t.Fatalf("unpriced image model: %d %s", status, body[:min(len(body), 500)])
	}
	if got := p.entries(2)[1].ChargedMicroUSD; got != 0 {
		t.Errorf("an unpriced image was charged %d micro-USD", got)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(p.proc.Log(), "charged $0 because no price applies") {
		if time.Now().After(deadline) {
			t.Fatalf("no unpriced warning for the image model:\n%s", p.proc.Log())
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Batch stays refused under the budget, and is not dialled.
	before := hits.Load()
	status, body = p.call(p.listen, "POST", "/v1/batches", key,
		`{"model":"gpt-image-1","input_file_id":"file_1","endpoint":"/v1/chat/completions","completion_window":"24h"}`)
	if status != http.StatusForbidden || !strings.Contains(body, "cannot be metered") {
		t.Errorf("batch under a budget: %d %s", status, body)
	}
	if hits.Load() != before {
		t.Errorf("a refused batch reached the provider")
	}
}
