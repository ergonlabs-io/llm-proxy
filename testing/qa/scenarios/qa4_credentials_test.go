package scenarios

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vigneshaigal/llm-proxy/testing/qa/harness"
	"github.com/vigneshaigal/llm-proxy/testing/qa/mocks"
)

// QA-4: provider credentials reach the upstream on every request, and never
// reach the access log (SCENARIOS.md — "Provider credentials reach the
// upstream on every request, and never reach the access log").
//
// Two shipped P0s share this one request path, and they fail in OPPOSITE
// directions, which is why both are asserted in a single case:
//
//   - `request_headers_to_add` was once lowered by both front-ends and read
//     by nothing, so every request reached its provider with no credentials
//     at all.
//   - Access logging deliberately snapshots request headers BEFORE the router
//     terminal injects those credentials, specifically so a key can never be
//     written to a log file.
//
// A change that "fixes" one by breaking the other would pass either
// assertion alone. Both providers are exercised because the dialect injects
// different header shapes per provider type (`authorization: Bearer <key>`
// for OpenAI-style, `x-api-key: <key>` for Anthropic), so a bug confined to
// one shape would hide behind the other.
func TestQA4_CredentialsReachUpstreamButNotTheLog(t *testing.T) {
	const (
		openaiCanary    = "sk-test-openai-canary-4f3a91"
		anthropicCanary = "sk-test-anthropic-canary-8b2e77"
	)

	openaiMock := mocks.NewOpenAI()
	defer openaiMock.Close()
	anthropicMock := mocks.NewAnthropic()
	defer anthropicMock.Close()

	openaiMock.NonStreaming = &mocks.ChatCompletion{
		ID:      "chatcmpl-qa4",
		Content: "ok",
		Usage:   mocks.Usage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2},
	}
	anthropicMock.NonStreaming = &mocks.AnthropicMessage{
		ID:      "msg-qa4",
		Content: "ok",
		Usage:   mocks.AnthropicUsage{InputTokens: 1, OutputTokens: 1},
	}

	port := harness.FreePort(t)
	logPath := harness.TempFilePath(t, "access.log")

	cfg := fmt.Sprintf(`
version: 0
listen: 127.0.0.1:%d
providers:
  openai:
    api_key: %s
    base_url: %s
  anthropic:
    api_key: %s
    base_url: %s
routes:
  - model: "gpt-*"
    provider: openai
  - model: "claude-*"
    provider: anthropic
observability:
  access_logs:
    output: %s
    format: json
`, port, openaiCanary, openaiMock.URL(), anthropicCanary, anthropicMock.URL(), logPath)

	configPath := harness.WriteConfig(t, "llmproxy.yaml", cfg)
	proxy := harness.Start(t, harness.StartOpts{ConfigPath: configPath})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	proxy.WaitReady(addr, 10*time.Second)

	client := &http.Client{Timeout: 5 * time.Second}
	send := func(path, model string) {
		reqBody, _ := json.Marshal(map[string]any{
			"model":    model,
			"messages": []map[string]string{{"role": "user", "content": "hi"}},
		})
		req, err := http.NewRequest(http.MethodPost, "http://"+addr+path, bytes.NewReader(reqBody))
		if err != nil {
			t.Fatalf("QA-4: build request for %s: %v", model, err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-llmproxy-model", model)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("QA-4: request for %s: %v\n--- proxy log ---\n%s", model, err, proxy.Log())
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("QA-4: %s got status %d: %s\n--- proxy log ---\n%s",
				model, resp.StatusCode, body, proxy.Log())
		}
	}

	send("/v1/chat/completions", "gpt-5")
	send("/v1/messages", "claude-sonnet-5")

	// --- direction 1: the credential must actually reach the upstream ---

	openaiReqs := openaiMock.Requests()
	if len(openaiReqs) != 1 {
		t.Fatalf("QA-4: expected 1 openai request, got %d", len(openaiReqs))
	}
	if got, want := openaiReqs[0].Headers.Get("Authorization"), "Bearer "+openaiCanary; got != want {
		t.Errorf("QA-4: openai upstream Authorization: want %q, got %q (all headers: %v)",
			want, got, openaiReqs[0].Headers)
	}

	anthropicReqs := anthropicMock.Requests()
	if len(anthropicReqs) != 1 {
		t.Fatalf("QA-4: expected 1 anthropic request, got %d", len(anthropicReqs))
	}
	if got := anthropicReqs[0].Headers.Get("x-api-key"); got != anthropicCanary {
		t.Errorf("QA-4: anthropic upstream x-api-key: want %q, got %q (all headers: %v)",
			anthropicCanary, got, anthropicReqs[0].Headers)
	}

	// --- direction 2: the credential must never reach the access log ---

	// Read the log as RAW TEXT rather than parsed JSON: a key could leak
	// through any field (a header operator, an echoed request line, a future
	// %REQ(AUTHORIZATION)% someone adds to the default format), and a
	// substring search over the whole file catches all of them. Parsing first
	// would only check the fields we thought to look at.
	if !harness.WaitForFile(logPath, 5*time.Second) {
		t.Fatalf("QA-4: access log %s was never created\n--- proxy log ---\n%s", logPath, proxy.Log())
	}
	lines := harness.WaitForAccessLogLines(t, logPath, 2, 5*time.Second)
	// Guard against a vacuous pass: "the log contains no key" is trivially
	// true of an empty or missing log, which would make this half of the
	// case meaningless exactly when logging is broken.
	if len(lines) < 2 {
		t.Fatalf("QA-4: expected 2 access-log lines before checking for leaks, got %d: %v",
			len(lines), lines)
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("QA-4: read access log: %v", err)
	}
	for _, canary := range []string{openaiCanary, anthropicCanary} {
		if strings.Contains(string(raw), canary) {
			t.Errorf("QA-4: CREDENTIAL LEAK — access log %s contains the canary key %q.\n"+
				"Access logging must snapshot request headers BEFORE the router terminal "+
				"injects provider credentials.\n--- access log ---\n%s",
				logPath, canary, raw)
		}
	}

	// The proxy's own stderr is a log destination too, and a debug line
	// echoing request headers would leak just as effectively as the access
	// log would.
	if proxyLog := proxy.Log(); strings.Contains(proxyLog, openaiCanary) ||
		strings.Contains(proxyLog, anthropicCanary) {
		t.Errorf("QA-4: CREDENTIAL LEAK — the proxy's own stderr contains a canary key.\n"+
			"--- proxy log ---\n%s", proxyLog)
	}
}
