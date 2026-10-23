package scenarios

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vigneshaigal/llm-proxy/testing/qa/harness"
	"github.com/vigneshaigal/llm-proxy/testing/qa/mocks"
)

// QA-20: JWT claims set chargeback tags, as an operator and a finance
// consumer see them, through the real binary's listener, admin API and
// ledger only.
//
// The Rust tests drive the claim mapping through the auth filter factory.
// This case checks the documented dialect field (`auth.jwt[].claim_tags`)
// on the real binary: a token signed by the test's own RSA key, the ledger
// entry it produces, the x-cost-tags header failing to override a claim
// tag, and every claim drop counted on the Prometheus scrape without a
// claim value ever becoming a label.

const (
	qa20AdminToken = "qa20-admin-token"
	qa20Issuer     = "https://idp.qa20.example"
	qa20Audience   = "api://llm-proxy"
	qa20Kid        = "qa20-key"
)

type qa20Proxy struct {
	t        *testing.T
	proc     *harness.Proxy
	listen   string
	admin    string
	client   *http.Client
	upstream *mocks.OpenAI
	key      *rsa.PrivateKey
}

func qa20Start(t *testing.T) *qa20Proxy {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())

	upstream := mocks.NewOpenAI()
	t.Cleanup(upstream.Close)
	upstream.NonStreaming = &mocks.ChatCompletion{
		ID: "qa20", Content: "ok",
		Usage: mocks.Usage{PromptTokens: 6, CompletionTokens: 4, TotalTokens: 10},
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "ledger.key")
	ledgerKey := make([]byte, 32)
	if _, err := rand.Read(ledgerKey); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, ledgerKey, 0o600); err != nil {
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
    api_key: sk-qa20-provider-key
routes:
  - { model: "*", provider: openai }
auth:
  hmac_secret: "qa20-hmac-secret"
  chargeback_tags:
    from_header: true
    allowed:
      - key: team
        values: [infra, search]
      - key: project
  jwt:
    - issuer: %s
      audience: %s
      jwks:
        keys:
          - { kid: %s, n: %s, e: %s }
      tenant:
        claim: tid
        values: { tid-acme: acme }
      user:
        claim: oid
      claim_tags:
        - { claim: department, tag: team }
        - { claim: cost_center, tag: project }
ledger:
  directory: %s
  encryption_key_file: %s
  encryption_key_id: qa20-key
  max_disk_bytes: 67108864
  group_commit_interval: 10ms
  on_unavailable: reject
`, listen, admin, upstream.URL(), qa20Issuer, qa20Audience, qa20Kid, n, e,
		filepath.Join(dir, "ledger"), keyFile)
	path := harness.WriteConfig(t, "llmproxy.yaml", config)
	t.Setenv("LLMPROXY_ADMIN_TOKEN", qa20AdminToken)
	proc := harness.Start(t, harness.StartOpts{
		ConfigPath: path,
		ExtraArgs:  []string{"--service-node", "qa20-node", "--drain-time-s", "1"},
	})
	proc.WaitReady(admin, 10*time.Second)
	proc.WaitReady(listen, 10*time.Second)
	return &qa20Proxy{
		t: t, proc: proc, listen: listen, admin: admin, upstream: upstream, key: key,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// token signs an RS256 JWT for tenant acme carrying extra claims.
func (p *qa20Proxy) token(extra map[string]any) string {
	p.t.Helper()
	claims := map[string]any{
		"iss": qa20Issuer,
		"aud": qa20Audience,
		"exp": time.Now().Add(time.Hour).Unix(),
		"tid": "tid-acme",
		"oid": "00000000-0000-0000-0000-0000000qa020",
	}
	for k, v := range extra {
		claims[k] = v
	}
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": qa20Kid})
	payload, err := json.Marshal(claims)
	if err != nil {
		p.t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
	if err != nil {
		p.t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (p *qa20Proxy) adminCall(method, path, body string, want int) []byte {
	p.t.Helper()
	req, _ := http.NewRequest(method, "http://"+p.admin+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+qa20AdminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		p.t.Fatalf("QA-20: %s %s: %v\n--- proxy log ---\n%s", method, path, err, p.proc.Log())
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		p.t.Fatalf("QA-20: %s %s: status %d, want %d: %s", method, path, resp.StatusCode, want, out)
	}
	return out
}

// chat sends one chat completion with the token and, when header is not
// empty, the tag header. A dropped tag never refuses the request.
func (p *qa20Proxy) chat(token, header string) {
	p.t.Helper()
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	req, _ := http.NewRequest(http.MethodPost, "http://"+p.listen+"/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if header != "" {
		req.Header.Set("x-cost-tags", header)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		p.t.Fatalf("QA-20: chat: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		p.t.Fatalf("QA-20: chat with x-cost-tags %q: status %d: %s\n--- proxy log ---\n%s", header, resp.StatusCode, out, p.proc.Log())
	}
}

type qa20Entry struct {
	Record struct {
		TenantID string            `json:"tenant_id"`
		UserID   string            `json:"user_id"`
		Tags     map[string]string `json:"tags"`
	} `json:"record"`
}

// entries waits until the ledger holds n entries and returns them in order.
func (p *qa20Proxy) entries(n int) []qa20Entry {
	p.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var page struct {
			Entries []qa20Entry `json:"entries"`
		}
		out := p.adminCall("GET", "/ledger/entries?after=0&limit=1000", "", http.StatusOK)
		if err := json.Unmarshal(out, &page); err != nil {
			p.t.Fatalf("QA-20: ledger page: %v: %s", err, out)
		}
		if len(page.Entries) >= n {
			return page.Entries
		}
		if time.Now().After(deadline) {
			p.t.Fatalf("QA-20: ledger holds %d entries, want %d", len(page.Entries), n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (p *qa20Proxy) scrape() string {
	p.t.Helper()
	resp, err := p.client.Get("http://" + p.admin + "/stats/prometheus")
	if err != nil {
		p.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return string(out)
}

// qa20Dropped reads every chargeback drop counter from a scrape, by reason.
func qa20Dropped(t *testing.T, scrape string) map[string]int {
	t.Helper()
	const prefix = `envoy_llmproxy_chargeback_tags_dropped_total{reason="`
	out := map[string]int{}
	for _, line := range strings.Split(scrape, "\n") {
		rest, ok := strings.CutPrefix(line, prefix)
		if !ok {
			continue
		}
		reason, value, ok := strings.Cut(rest, `"} `)
		if !ok {
			t.Fatalf("QA-20: unexpected drop series %q", line)
		}
		n, err := strconv.Atoi(value)
		if err != nil {
			t.Fatalf("QA-20: drop series %q: %v", line, err)
		}
		out[reason] = n
	}
	return out
}

func TestQA20JwtClaimTags(t *testing.T) {
	p := qa20Start(t)
	p.adminCall("POST", "/tenants", `{"tenant":"acme"}`, http.StatusCreated)
	p.adminCall("PUT", "/tenants/acme/policy", `{"access":"all"}`, http.StatusNoContent)
	before := qa20Dropped(t, p.scrape())

	// 1. Both claims map to allowed tags; the header cannot override either.
	p.chat(p.token(map[string]any{"department": "infra", "cost_center": "ads"}), "team=search, project=x")
	// 2. A claim value outside the allow-list is dropped, a missing claim is
	// dropped, and the header still cannot fill either tag.
	p.chat(p.token(map[string]any{"department": "marketing"}), "team=search, project=y")
	// 3. A non-string claim and a value outside the tag alphabet are dropped.
	p.chat(p.token(map[string]any{"department": 7, "cost_center": "a,b"}), "")

	entries := p.entries(3)
	for i, want := range []map[string]string{
		{"team": "infra", "project": "ads"},
		{},
		{},
	} {
		got := entries[i].Record
		if got.TenantID != "acme" || !strings.HasPrefix(got.UserID, "jwt:") || !reflect.DeepEqual(got.Tags, want) {
			t.Fatalf("QA-20 request %d: entry tenant %q user %q tags %v, want tenant acme, a jwt: user, tags %v",
				i+1, got.TenantID, got.UserID, got.Tags, want)
		}
	}
	for _, r := range p.upstream.Requests() {
		if v := r.Headers.Get("x-cost-tags"); v != "" {
			t.Fatalf("QA-20: the tag header reached the provider: %q", v)
		}
	}

	after := p.scrape()
	dropped := qa20Dropped(t, after)
	for reason, want := range map[string]int{
		"overridden":    4, // request 1: team and project; request 2: team and project
		"not_allowed":   1, // department=marketing
		"claim_missing": 1, // request 2 has no cost_center
		"malformed":     2, // department=7, cost_center="a,b"
	} {
		if got := dropped[reason] - before[reason]; got != want {
			t.Fatalf("QA-20: %s drops grew by %d, want %d\n%s", reason, got, want, after)
		}
	}

	// 4. Many distinct claim values add no metric series and never appear
	// in the scrape.
	series := func(scrape string) int {
		n := 0
		for _, line := range strings.Split(scrape, "\n") {
			if line != "" && !strings.HasPrefix(line, "#") {
				n++
			}
		}
		return n
	}
	baseline := series(after)
	for i := range 100 {
		p.chat(p.token(map[string]any{"department": "search", "cost_center": fmt.Sprintf("cc%d", i)}), "")
	}
	last := p.entries(3 + 100)[3+99].Record.Tags
	if !reflect.DeepEqual(last, map[string]string{"team": "search", "project": "cc99"}) {
		t.Fatalf("QA-20: last entry tags %v", last)
	}
	final := p.scrape()
	if got := series(final); got != baseline {
		t.Fatalf("QA-20: 100 distinct claim values moved the series count from %d to %d", baseline, got)
	}
	if strings.Contains(final, "cc99") {
		t.Fatal("QA-20: a claim value appears in the Prometheus scrape")
	}
	p.proc.Terminate()
	p.proc.Wait(20 * time.Second)
}
