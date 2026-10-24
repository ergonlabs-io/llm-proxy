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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ergonlabs-io/llm-proxy/testing/qa/harness"
	"github.com/ergonlabs-io/llm-proxy/testing/qa/mocks"
)

// QA-19: a JWT caller whose tenant stored its own provider key (BYOK,
// ADR-0007) as the tenant, the provider and a billing consumer see it,
// through the real binary's listener, admin API and ledger only.
//
// The provider receives the tenant's key and never the operator's. The
// ledger entry says the tenant's credential was used, and the tenant's
// platform-scoped budget is not charged: BYOK traffic is not platform spend.
// A JWT caller whose tenant stored no key is served with the operator's key
// and charged as platform spend, as before.

const (
	qa19AdminToken  = "qa19-admin-token"
	qa19Node        = "qa19-node"
	qa19Issuer      = "https://idp.qa19.test"
	qa19Audience    = "api://llm-proxy"
	qa19Kid         = "qa19-k1"
	qa19OperatorKey = "sk-qa19-OPERATOR"
	qa19TenantKey   = "sk-qa19-TENANT"
)

type qa19Proxy struct {
	t      *testing.T
	proc   *harness.Proxy
	listen string
	admin  string
	client *http.Client
	signer *rsa.PrivateKey
}

func qa19Start(t *testing.T, upstream string) *qa19Proxy {
	t.Helper()
	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write32 := func(name string) string {
		path := filepath.Join(dir, name)
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, key, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	b64 := base64.RawURLEncoding.EncodeToString
	listen := fmt.Sprintf("127.0.0.1:%d", harness.FreePort(t))
	admin := fmt.Sprintf("127.0.0.1:%d", harness.FreePort(t))
	config := fmt.Sprintf(`version: 1
listen: %s
admin: %s
providers:
  openai:
    type: openai
    base_url: %s
    api_key: %s
    tenant_credentials: true
routes:
  - { model: "*", provider: openai }
auth:
  hmac_secret: "qa19-hmac-secret"
  store:
    persistent: { path: %s }
  tenant_credentials:
    encryption_key_file: %s
    encryption_key_id: qa19-kek
  jwt:
    - issuer: %q
      audience: %q
      jwks: { keys: [ { kid: %s, n: %q, e: %q } ] }
      tenant:
        claim: tid
        values: { tid-acme: acme, tid-beta: beta }
      user: { claim: oid }
pricing:
  price_list:
    version: qa19
    effective_from: "2026-01-01T00:00:00Z"
    entries:
      - provider_type: openai
        model: gpt-4o
        tier_mode: whole_request
        tiers:
          - input_nanodollars_per_token: 2500
            cached_input_nanodollars_per_token: 1250
            cache_write_nanodollars_per_token: 0
            output_nanodollars_per_token: 10000
ledger:
  directory: %s
  encryption_key_file: %s
  encryption_key_id: qa19-ledger
  max_disk_bytes: 67108864
  group_commit_interval: 10ms
  on_unavailable: reject
`, listen, admin, upstream, qa19OperatorKey, filepath.Join(dir, "auth.redb"), write32("credential.kek"),
		qa19Issuer, qa19Audience, qa19Kid, b64(signer.N.Bytes()), b64(big.NewInt(int64(signer.E)).Bytes()),
		filepath.Join(dir, "ledger"), write32("ledger.key"))
	path := harness.WriteConfig(t, "llmproxy.yaml", config)
	t.Setenv("LLMPROXY_ADMIN_TOKEN", qa19AdminToken)
	proc := harness.Start(t, harness.StartOpts{
		ConfigPath: path,
		ExtraArgs:  []string{"--service-node", qa19Node},
	})
	proc.WaitReady(admin, 10*time.Second)
	proc.WaitReady(listen, 10*time.Second)
	return &qa19Proxy{
		t: t, proc: proc, listen: listen, admin: admin, signer: signer,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// token signs an RS256 JWT for the IdP tenant id tid.
func (p *qa19Proxy) token(tid string) string {
	p.t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	header := b64([]byte(fmt.Sprintf(`{"alg":"RS256","typ":"JWT","kid":%q}`, qa19Kid)))
	claims, _ := json.Marshal(map[string]any{
		"iss": qa19Issuer, "aud": qa19Audience, "exp": time.Now().Add(time.Hour).Unix(),
		"tid": tid, "oid": "00000000-0000-0000-0000-0000000000" + tid[len(tid)-2:],
	})
	message := header + "." + b64(claims)
	digest := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.signer, crypto.SHA256, digest[:])
	if err != nil {
		p.t.Fatal(err)
	}
	return message + "." + b64(signature)
}

func (p *qa19Proxy) call(addr, method, path, bearer, body string) (int, string) {
	p.t.Helper()
	req, _ := http.NewRequest(method, "http://"+addr+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		p.t.Fatalf("QA-19: %s %s: %v\n--- proxy log ---\n%s", method, path, err, p.proc.Log())
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func (p *qa19Proxy) adminCall(method, path, body string, want int) string {
	p.t.Helper()
	status, out := p.call(p.admin, method, path, qa19AdminToken, body)
	if status != want {
		p.t.Fatalf("QA-19: %s %s: status %d, want %d: %s", method, path, status, want, out)
	}
	return out
}

// chat sends one chat completion as tid's JWT; it must be served.
func (p *qa19Proxy) chat(tid string) {
	p.t.Helper()
	status, out := p.call(p.listen, "POST", "/v1/chat/completions", p.token(tid),
		`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
	if status != http.StatusOK {
		p.t.Fatalf("QA-19: chat as %s: status %d: %s\n--- proxy log ---\n%s", tid, status, out, p.proc.Log())
	}
}

type qa19Entry struct {
	ChargedMicroUSD uint64 `json:"charged_micro_usd"`
	ChargedScopes   []struct {
		Scope string `json:"scope"`
	} `json:"charged_scopes"`
	Record struct {
		TenantID         string `json:"tenant_id"`
		CredentialSource string `json:"credential_source"`
		Cost             *struct {
			Amount uint64 `json:"amount"`
		} `json:"cost"`
	} `json:"record"`
}

// entries polls the ledger until it holds want entries.
func (p *qa19Proxy) entries(want int) []qa19Entry {
	p.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var page struct {
			Entries []qa19Entry `json:"entries"`
		}
		out := p.adminCall("GET", "/ledger/entries?after=0&limit=100", "", http.StatusOK)
		if err := json.Unmarshal([]byte(out), &page); err != nil {
			p.t.Fatalf("QA-19: ledger page: %v: %s", err, out)
		}
		if len(page.Entries) >= want {
			return page.Entries
		}
		if time.Now().After(deadline) {
			p.t.Fatalf("QA-19: ledger holds %d entries, want %d: %s", len(page.Entries), want, out)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// spendUSD is the tenant's spend counter for its budget's period.
func (p *qa19Proxy) spendUSD(tenant string) float64 {
	p.t.Helper()
	var report struct {
		SpendUSD string `json:"spend_usd"`
	}
	out := p.adminCall("GET", "/tenants/"+tenant+"/spend", "", http.StatusOK)
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		p.t.Fatalf("QA-19: spend report: %v: %s", err, out)
	}
	spend, err := strconv.ParseFloat(report.SpendUSD, 64)
	if err != nil {
		p.t.Fatalf("QA-19: spend_usd %q: %v", report.SpendUSD, err)
	}
	return spend
}

func qa19ChargedTenantScope(e qa19Entry) bool {
	for _, scope := range e.ChargedScopes {
		if scope.Scope == "tenant" {
			return true
		}
	}
	return false
}

// TestQA19_JwtByokTenantUsesItsOwnKeyAndIsNotPlatformSpend is the JWT tenant-credentials
// acceptance case.
func TestQA19_JwtByokTenantUsesItsOwnKeyAndIsNotPlatformSpend(t *testing.T) {
	upstream := mocks.NewOpenAI()
	t.Cleanup(upstream.Close)
	upstream.NonStreaming = &mocks.ChatCompletion{
		ID: "qa19", Content: "ok",
		Usage: mocks.Usage{PromptTokens: 100, CompletionTokens: 50, TotalTokens: 150},
	}
	p := qa19Start(t, upstream.URL())
	for _, tenant := range []string{"acme", "beta"} {
		p.adminCall("POST", "/tenants", fmt.Sprintf(`{"tenant":%q}`, tenant), http.StatusCreated)
		p.adminCall("PUT", "/tenants/"+tenant+"/policy", `{"access":"all"}`, http.StatusNoContent)
		// A platform-scoped budget (the default scope): only operator-key
		// spend is added to it (ADR-0007 decision 8).
		p.adminCall("PUT", "/tenants/"+tenant+"/budget",
			`{"budget":{"max_usd":"100","period":"daily"}}`, http.StatusNoContent)
	}
	stored := p.adminCall("PUT", "/tenants/acme/provider_credentials/openai",
		fmt.Sprintf(`{"schema_version":1,"api_key":%q,"verify":false}`, qa19TenantKey), http.StatusOK)
	if strings.Contains(stored, qa19TenantKey) {
		t.Fatalf("QA-19: the admin API echoed the stored key: %s", stored)
	}

	// The BYOK tenant's JWT: the provider sees the tenant's key only.
	p.chat("tid-acme")
	reqs := upstream.Requests()
	if len(reqs) != 1 {
		t.Fatalf("QA-19: provider saw %d requests, want 1", len(reqs))
	}
	if got := reqs[0].Headers.Values("Authorization"); len(got) != 1 || got[0] != "Bearer "+qa19TenantKey {
		t.Errorf("QA-19: BYOK JWT reached the provider with Authorization %q, want only the tenant's key", got)
	}
	for name, values := range reqs[0].Headers {
		for _, v := range values {
			if strings.Contains(v, qa19OperatorKey) {
				t.Errorf("QA-19: the operator key travelled on %s beside the tenant's key", name)
			}
		}
	}
	byok := p.entries(1)[0]
	if byok.Record.TenantID != "acme" || byok.Record.CredentialSource != "tenant" {
		t.Errorf("QA-19: BYOK ledger entry tenant %q credential_source %q, want acme/tenant",
			byok.Record.TenantID, byok.Record.CredentialSource)
	}
	if byok.Record.Cost == nil || byok.Record.Cost.Amount == 0 {
		t.Errorf("QA-19: the BYOK request was not priced (cost 0); the case proves nothing about spend scope")
	}
	if qa19ChargedTenantScope(byok) {
		t.Errorf("QA-19: BYOK spend was charged to the tenant's platform budget: %+v", byok.ChargedScopes)
	}
	if spend := p.spendUSD("acme"); spend != 0 {
		t.Errorf("QA-19: acme's platform spend is %v after a BYOK request, want 0", spend)
	}

	// A JWT tenant with no stored key: the operator key, platform spend.
	p.chat("tid-beta")
	reqs = upstream.Requests()
	if got := reqs[len(reqs)-1].Headers.Values("Authorization"); len(got) != 1 || got[0] != "Bearer "+qa19OperatorKey {
		t.Errorf("QA-19: platform JWT reached the provider with Authorization %q, want only the operator key", got)
	}
	platform := p.entries(2)[1]
	if platform.Record.TenantID != "beta" || platform.Record.CredentialSource != "platform" {
		t.Errorf("QA-19: platform ledger entry tenant %q credential_source %q, want beta/platform",
			platform.Record.TenantID, platform.Record.CredentialSource)
	}
	if !qa19ChargedTenantScope(platform) || platform.ChargedMicroUSD == 0 {
		t.Errorf("QA-19: platform spend was not charged to beta's budget: %d %+v",
			platform.ChargedMicroUSD, platform.ChargedScopes)
	}
	if spend := p.spendUSD("beta"); spend == 0 {
		t.Errorf("QA-19: beta's platform spend is 0 after a platform request")
	}
}
