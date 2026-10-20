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

// QA-18: speech and transcription under a tenant spend budget (ADR-0010
// phase 3), as a tenant and a billing consumer see it, through the real
// binary's listener and admin API only.
//
// Speech is charged ceil(characters x rate) at the dialled provider's entry,
// and the charge reaches the ledger entry, which says what was bought. A
// speech request the provider refuses charges nothing. A transcription form
// is routed on its `model` field and charged its reported audio duration. A
// transcription whose response cannot be counted, and a form without a
// model, are refused under the budget and never reach the provider.

const (
	qa18AdminToken = "qa18-admin-token"
	qa18Node       = "qa18-node"
	// Example values, not a provider's rates. The character price is chosen
	// so the charge is not a whole micro-USD.
	qa18NanodollarsPerCharacter = 15_001
	qa18NanodollarsPerSecond    = 100_000
	qa18Boundary                = "qa18-boundary"
)

type qa18Proxy struct {
	t      *testing.T
	proc   *harness.Proxy
	listen string
	admin  string
	client *http.Client
}

// qa18Upstream answers speech with audio (or a 400 for the voice "bad"),
// transcriptions with a duration usage, and counts every request.
func qa18Upstream(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	hits := new(atomic.Int64)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		hits.Add(1)
		switch r.URL.Path {
		case "/v1/audio/speech":
			if strings.Contains(string(body), `"voice":"bad"`) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"error":{"message":"unknown voice"}}`)
				return
			}
			w.Header().Set("Content-Type", "audio/mpeg")
			_, _ = w.Write([]byte("ID3 mp3 frames"))
		case "/v1/audio/transcriptions":
			if !strings.Contains(string(body), "whisper-1") {
				http.Error(w, "mock: form lost its model", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"text":"hello","usage":{"type":"duration","seconds":2.5}}`)
		default:
			http.Error(w, "mock: unexpected path "+r.URL.Path, http.StatusNotFound)
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, hits
}

func qa18Start(t *testing.T, upstream string) *qa18Proxy {
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
    api_key: sk-qa18-provider-key
routes:
  - { model: "*", provider: openai }
auth:
  hmac_secret: "qa18-hmac-secret"
  # No model policy, so model_authz cannot refuse a form without a model
  # first: the refusal under test is the spend budget's.
  enforce: { model_policy: false, object_ownership: false }
pricing:
  price_list:
    version: qa18
    effective_from: "2026-01-01T00:00:00Z"
    entries:
      - provider_type: openai
        model: tts-1
        basis: characters
        nanodollars_per_character: %d
      - provider_type: openai
        model: whisper-1
        basis: audio_seconds
        nanodollars_per_second: %d
ledger:
  directory: %s
  encryption_key_file: %s
  encryption_key_id: qa18-key
  max_disk_bytes: 67108864
  group_commit_interval: 10ms
  on_unavailable: reject
`, listen, admin, upstream, qa18NanodollarsPerCharacter, qa18NanodollarsPerSecond,
		filepath.Join(dir, "ledger"), keyFile)
	path := harness.WriteConfig(t, "llmproxy.yaml", config)
	t.Setenv("LLMPROXY_ADMIN_TOKEN", qa18AdminToken)
	proc := harness.Start(t, harness.StartOpts{
		ConfigPath: path,
		ExtraArgs:  []string{"--service-node", qa18Node},
	})
	proc.WaitReady(admin, 10*time.Second)
	proc.WaitReady(listen, 10*time.Second)
	return &qa18Proxy{t: t, proc: proc, listen: listen, admin: admin, client: &http.Client{Timeout: 30 * time.Second}}
}

// call sends one request and returns its status and body.
func (p *qa18Proxy) call(addr, method, path, bearer, contentType, body string) (int, string) {
	p.t.Helper()
	req, err := http.NewRequest(method, "http://"+addr+path, strings.NewReader(body))
	if err != nil {
		p.t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
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

func (p *qa18Proxy) adminCall(method, path, body string, want int) string {
	p.t.Helper()
	status, resp := p.call(p.admin, method, path, qa18AdminToken, "application/json", body)
	if status != want {
		p.t.Fatalf("%s %s: status %d, want %d: %s", method, path, status, want, resp)
	}
	return resp
}

// tenantKey creates tenant t1 and a key for it.
func (p *qa18Proxy) tenantKey() string {
	p.t.Helper()
	var minted struct {
		Key string `json:"key"`
	}
	resp := p.adminCall("POST", "/keys", `{"tenant":"t1","key_id":"qa18-key"}`, http.StatusCreated)
	if err := json.Unmarshal([]byte(resp), &minted); err != nil {
		p.t.Fatal(err)
	}
	if status, body := p.call(p.admin, "POST", "/tenants", qa18AdminToken, "application/json", `{"tenant":"t1"}`); status/100 != 2 {
		p.t.Fatalf("POST /tenants: %d %s", status, body)
	}
	return minted.Key
}

type qa18Entry struct {
	ChargedMicroUSD uint64 `json:"charged_micro_usd"`
	ChargedScopes   []struct {
		Scope string `json:"scope"`
	} `json:"charged_scopes"`
	Record struct {
		Endpoint   string `json:"endpoint"`
		PriceBasis string `json:"price_basis"`
		Usage      struct {
			InputCharacters   *uint64 `json:"input_characters"`
			AudioMilliseconds *uint64 `json:"audio_milliseconds"`
		} `json:"usage"`
	} `json:"record"`
}

// entries polls the ledger until it holds want entries.
func (p *qa18Proxy) entries(want int) []qa18Entry {
	p.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var page struct {
			Entries []qa18Entry `json:"entries"`
		}
		resp := p.adminCall("GET", "/ledger/entries?after=0&limit=100", "", http.StatusOK)
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

// qa18Form builds a multipart form with the given text fields, then an
// audio file part.
func qa18Form(fields ...[2]string) string {
	var b strings.Builder
	for _, f := range fields {
		fmt.Fprintf(&b, "--%s\r\nContent-Disposition: form-data; name=%q\r\n\r\n%s\r\n", qa18Boundary, f[0], f[1])
	}
	fmt.Fprintf(&b, "--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.mp3\"\r\nContent-Type: audio/mpeg\r\n\r\nID3 audio\r\n--%s--\r\n", qa18Boundary, qa18Boundary)
	return b.String()
}

// TestQA18_SpeechUnderABudgetIsChargedAndLedgered is the v0.6.0 ship-gate
// case for speech, with the transcription admission rules beside it.
func TestQA18_SpeechUnderABudgetIsChargedAndLedgered(t *testing.T) {
	upstream, hits := qa18Upstream(t)
	p := qa18Start(t, upstream.URL)
	key := p.tenantKey()
	p.adminCall("PUT", "/tenants/t1/budget", `{"budget":{"max_usd":"100","period":"daily"}}`, http.StatusNoContent)

	// 11 characters; the JSON escape is one of them.
	status, body := p.call(p.listen, "POST", "/v1/audio/speech", key, "application/json",
		`{"model":"tts-1","input":"hello wörld","voice":"alloy"}`)
	if status != http.StatusOK || body != "ID3 mp3 frames" {
		t.Fatalf("speech under a budget: %d %q", status, body)
	}
	entry := p.entries(1)[0]
	want := uint64((11*qa18NanodollarsPerCharacter + 999) / 1000)
	if want != 166 || entry.ChargedMicroUSD != want {
		t.Errorf("charged_micro_usd = %d, want %d (11 characters, rounded up)", entry.ChargedMicroUSD, want)
	}
	tenantCharged := false
	for _, scope := range entry.ChargedScopes {
		tenantCharged = tenantCharged || scope.Scope == "tenant"
	}
	if !tenantCharged {
		t.Errorf("the tenant budget was not among the charged scopes: %+v", entry.ChargedScopes)
	}
	if u := entry.Record.Usage; u.InputCharacters == nil || *u.InputCharacters != 11 {
		t.Errorf("the entry does not say what was bought: %+v", entry.Record.Usage)
	}
	if entry.Record.Endpoint != "speech" || entry.Record.PriceBasis != "characters" {
		t.Errorf("endpoint %q, price_basis %q", entry.Record.Endpoint, entry.Record.PriceBasis)
	}

	// The provider refuses the request: nothing is charged.
	status, _ = p.call(p.listen, "POST", "/v1/audio/speech", key, "application/json",
		`{"model":"tts-1","input":"hello","voice":"bad"}`)
	if status != http.StatusBadRequest {
		t.Fatalf("a refused speech request: %d", status)
	}
	if got := p.entries(2)[1].ChargedMicroUSD; got != 0 {
		t.Errorf("a non-2xx speech response was charged %d micro-USD", got)
	}

	// A transcription form is routed on its model and charged its duration.
	formType := "multipart/form-data; boundary=" + qa18Boundary
	status, body = p.call(p.listen, "POST", "/v1/audio/transcriptions", key, formType,
		qa18Form([2]string{"model", "whisper-1"}))
	if status != http.StatusOK {
		t.Fatalf("transcription under a budget: %d %s", status, body)
	}
	transcription := p.entries(3)[2]
	if got, want := transcription.ChargedMicroUSD, uint64(2500*qa18NanodollarsPerSecond/1000/1000); got != want {
		t.Errorf("transcription charged %d micro-USD, want %d (2.5 s)", got, want)
	}
	if ms := transcription.Record.Usage.AudioMilliseconds; ms == nil || *ms != 2500 {
		t.Errorf("transcription audio_milliseconds = %v, want 2500", ms)
	}

	// Uncountable shapes are refused under the budget and not dialled.
	before := hits.Load()
	for name, form := range map[string]string{
		"response_format text": qa18Form([2]string{"model", "whisper-1"}, [2]string{"response_format", "text"}),
		"no model":             qa18Form([2]string{"language", "en"}),
	} {
		status, body = p.call(p.listen, "POST", "/v1/audio/transcriptions", key, formType, form)
		if status != http.StatusForbidden || !strings.Contains(body, "cannot be metered") {
			t.Errorf("transcription with %s under a budget: %d %s", name, status, body)
		}
	}
	if hits.Load() != before {
		t.Errorf("a refused transcription reached the provider")
	}
}
