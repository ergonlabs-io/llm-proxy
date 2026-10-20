package scenarios

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vigneshaigal/llm-proxy/testing/qa/harness"
	"github.com/vigneshaigal/llm-proxy/testing/qa/mocks"
)

// QA-15: a weighted `models` alias splits traffic by weight, keeps each
// provider's key and upstream model on that provider, and stops sending
// first picks to a provider its outlier detection ejected (SCENARIOS.md —
// "Weighted alias splits by weight and skips an ejected provider").
//
// Phase 1 sends 400 requests at weights 3:1. The pick is a uniform draw per
// request, so provider b's count is Binomial(400, 0.25): mean 100, standard
// deviation 8.7. The tolerance is +-50 (5.8 standard deviations), which a
// correct split misses with probability below 1e-8.
//
// Phase 2 makes b fail. Its first failing request ejects it
// (`consecutive_5xx: 1`, 300 s ejection) and fails over to a, so every client
// request still succeeds. Phase 3 then asserts b gets nothing more.
func TestQA15_WeightedAliasSplitsAndSkipsAnEjectedProvider(t *testing.T) {
	const (
		keyA = "sk-test-qa15-provider-a"
		keyB = "sk-test-qa15-provider-b"
	)

	a := mocks.NewOpenAI()
	defer a.Close()
	b := mocks.NewOpenAI()
	defer b.Close()
	for _, m := range []*mocks.OpenAI{a, b} {
		m.NonStreaming = &mocks.ChatCompletion{
			ID:      "chatcmpl-qa15",
			Content: "ok",
			Usage:   mocks.Usage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2},
		}
	}

	port := harness.FreePort(t)
	cfg := fmt.Sprintf(`
version: 0
listen: 127.0.0.1:%d
providers:
  a:
    type: openai-compatible
    base_url: %s
    api_key: %s
  b:
    type: openai-compatible
    base_url: %s
    api_key: %s
    outlier_detection: { consecutive_5xx: 1, base_ejection_time: 300s }
routes: []
models:
  gpt-qa15:
    providers:
      - { provider: a, model: a-upstream-model, weight: 3 }
      - { provider: b, model: b-upstream-model, weight: 1 }
`, port, a.URL(), keyA, b.URL(), keyB)

	configPath := harness.WriteConfig(t, "llmproxy.yaml", cfg)
	proxy := harness.Start(t, harness.StartOpts{ConfigPath: configPath, Concurrency: 2})
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	proxy.WaitReady(addr, 10*time.Second)

	client := &http.Client{Timeout: 5 * time.Second}
	send := func(phase string, i int) {
		reqBody, _ := json.Marshal(map[string]any{
			"model":    "gpt-qa15",
			"messages": []map[string]string{{"role": "user", "content": "hi"}},
		})
		req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/v1/chat/completions", bytes.NewReader(reqBody))
		if err != nil {
			t.Fatalf("QA-15: build request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("QA-15 %s request %d: %v\n--- proxy log ---\n%s", phase, i, err, proxy.Log())
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("QA-15 %s request %d: status %d: %s\n--- proxy log ---\n%s",
				phase, i, resp.StatusCode, body, proxy.Log())
		}
	}

	// --- phase 1: the split follows the weights ---
	const n = 400
	for i := 0; i < n; i++ {
		send("split", i)
	}
	aReqs, bReqs := a.Requests(), b.Requests()
	if len(aReqs)+len(bReqs) != n {
		t.Fatalf("QA-15: %d requests reached the providers, want %d (one each)", len(aReqs)+len(bReqs), n)
	}
	if got := len(bReqs); got < 50 || got > 150 {
		t.Errorf("QA-15: provider b served %d of %d; weights 3:1 expect 100 +- 50", got, n)
	}
	check := func(name string, reqs []mocks.RecordedRequest, key, otherKey, model string) {
		for i, r := range reqs {
			if got := r.Headers.Get("Authorization"); got != "Bearer "+key {
				t.Errorf("QA-15: %s request %d Authorization %q, want its own key", name, i, got)
			}
			for header, values := range r.Headers {
				for _, v := range values {
					if strings.Contains(v, otherKey) {
						t.Errorf("QA-15: CREDENTIAL LEAK — %s received the other provider's key in %s", name, header)
					}
				}
			}
			if got, _ := r.Body["model"].(string); got != model {
				t.Errorf("QA-15: %s request %d model %q, want %q", name, i, got, model)
			}
		}
	}
	check("a", aReqs, keyA, keyB, "a-upstream-model")
	check("b", bReqs, keyB, keyA, "b-upstream-model")

	// --- phase 2: b fails once and is ejected ---
	b.SetFailStatus(http.StatusInternalServerError)
	before := len(b.Requests())
	for i := 0; len(b.Requests()) == before; i++ {
		if i == 200 {
			t.Fatalf("QA-15: 200 requests and none picked b at weight 1 of 4\n--- proxy log ---\n%s", proxy.Log())
		}
		send("eject", i)
	}

	// --- phase 3: the ejected provider gets no traffic ---
	ejectedAt := len(b.Requests())
	for i := 0; i < 200; i++ {
		send("ejected", i)
	}
	if got := len(b.Requests()); got != ejectedAt {
		t.Errorf("QA-15: ejected provider b received %d more requests, want 0", got-ejectedAt)
	}
}
