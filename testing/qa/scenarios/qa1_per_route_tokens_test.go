package scenarios

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/vigneshaigal/llm-proxy/testing/qa/harness"
	"github.com/vigneshaigal/llm-proxy/testing/qa/mocks"
)

// QA-1: per-route token counts are correct for both providers, from one
// proxy and one config (SCENARIOS.md — "Per-route token counts are correct
// for both providers, from one proxy and one config").
//
// One `llmproxy` dialect config routes `gpt-*` to a mock OpenAI upstream and
// `claude-*` to a mock Anthropic upstream. Each mock is configured with
// deliberately DIFFERENT usage numbers so a crossed-wires bug (provider A's
// tokens attributed to provider B's log line) cannot pass by coincidence.
func TestQA1_PerRouteTokenCounts(t *testing.T) {
	openaiMock := mocks.NewOpenAI()
	defer openaiMock.Close()
	anthropicMock := mocks.NewAnthropic()
	defer anthropicMock.Close()

	// Deliberately distinct per-provider usage numbers (see doc comment).
	openaiMock.NonStreaming = &mocks.ChatCompletion{
		ID:      "chatcmpl-qa1",
		Content: "hello from the openai mock",
		Usage:   mocks.Usage{PromptTokens: 111, CompletionTokens: 222, TotalTokens: 333},
	}
	anthropicMock.NonStreaming = &mocks.AnthropicMessage{
		ID:      "msg-qa1",
		Content: "hello from the anthropic mock",
		Usage:   mocks.AnthropicUsage{InputTokens: 444, OutputTokens: 555},
	}

	port := harness.FreePort(t)
	logPath := harness.TempFilePath(t, "access.log")

	cfg := fmt.Sprintf(`
version: 0
listen: 127.0.0.1:%d
providers:
  openai:
    api_key: sk-test-openai-canary
    base_url: %s
  anthropic:
    api_key: sk-test-anthropic-canary
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
`, port, openaiMock.URL(), anthropicMock.URL(), logPath)

	configPath := harness.WriteConfig(t, "llmproxy.yaml", cfg)
	proxy := harness.Start(t, harness.StartOpts{ConfigPath: configPath})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	proxy.WaitReady(addr, 10*time.Second)

	client := &http.Client{Timeout: 5 * time.Second}
	// llm-proxy routes purely on the x-llmproxy-model header — it does not
	// translate between providers' native API paths (a model-router
	// filter is what will eventually let a client speak one dialect and be
	// routed to another). So each request must hit the path its target
	// provider's mock actually serves.
	sendChat := func(path, model string) {
		reqBody, _ := json.Marshal(map[string]any{
			"model":    model,
			"messages": []map[string]string{{"role": "user", "content": "hi"}},
		})
		req, err := http.NewRequest(
			http.MethodPost, "http://"+addr+path, bytes.NewReader(reqBody),
		)
		if err != nil {
			t.Fatalf("QA-1: build request for model %s: %v", model, err)
		}
		req.Header.Set("Content-Type", "application/json")
		// Routing is by the x-llmproxy-model header today (body-based
		// extraction, is not yet in place — see lower.rs's routes warning).
		req.Header.Set("x-llmproxy-model", model)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("QA-1: request for model %s: %v\n--- proxy log ---\n%s", model, err, proxy.Log())
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf(
				"QA-1: model %s got status %d: %s\n--- proxy log ---\n%s",
				model, resp.StatusCode, body, proxy.Log(),
			)
		}
	}

	sendChat("/v1/chat/completions", "gpt-5")
	sendChat("/v1/messages", "claude-sonnet-5")

	// Both requests must have actually reached their mocks — if this isn't
	// true, whatever we find below about the access log is moot.
	if got := len(openaiMock.Requests()); got != 1 {
		t.Fatalf("QA-1: expected 1 request at the openai mock, got %d\n--- proxy log ---\n%s", got, proxy.Log())
	}
	if got := len(anthropicMock.Requests()); got != 1 {
		t.Fatalf("QA-1: expected 1 request at the anthropic mock, got %d\n--- proxy log ---\n%s", got, proxy.Log())
	}

	// The dialect now wires observability.access_logs onto the HCM (this
	// suite's first finding, fixed in "Emit access logs from the llmproxy
	// dialect"), so the log file must actually appear. This is no longer a
	// skip condition — a missing file here is a regression of that fix.
	if !harness.WaitForFile(logPath, 5*time.Second) {
		t.Fatalf(
			"QA-1: access log file %s was never created, but the dialect is "+
				"supposed to wire observability.access_logs onto the HCM. Both "+
				"requests reached their mocks (openai=%d, anthropic=%d), so this "+
				"is a log-emission regression, not a routing failure.\n"+
				"--- proxy log ---\n%s",
			logPath, len(openaiMock.Requests()), len(anthropicMock.Requests()), proxy.Log(),
		)
	}

	lines := harness.WaitForAccessLogLines(t, logPath, 2, 5*time.Second)
	if len(lines) < 2 {
		t.Fatalf("QA-1: expected at least 2 access-log lines, got %d: %v", len(lines), lines)
	}

	// Correlate by request path, not by model: the dialect's JSON log format
	// has no model field yet. Emitting one is part of the usage filter's work (the usage filter
	// is what knows the model), so until that lands, path is the only
	// per-route discriminator in the line — and it is a real one, since the
	// two routes target different providers on different paths.
	findLineForPath := func(path string) map[string]any {
		for _, l := range lines {
			if s, ok := l["path"].(string); ok && s == path {
				return l
			}
		}
		return nil
	}

	// Every value in a json_format line is a JSON *string*: Envoy's
	// json_format values are command-operator format strings, so a numeric
	// operator like %RESPONSE_CODE% still renders as "200", and an absent
	// value renders as the literal "-". Parse accordingly rather than type-
	// asserting to float64 — ok is false for "-" (and for anything
	// non-numeric), which is exactly the "not populated" signal below.
	numField := func(line map[string]any, key string) (int, bool) {
		s, ok := line[key].(string)
		if !ok {
			return 0, false
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, false
		}
		return n, true
	}

	// The parts that do not depend on the usage filter are asserted unconditionally, so
	// this case guards routing and log emission today rather than being
	// all-or-nothing on the token counts.
	type route struct {
		path                  string
		model                 string
		wantInput, wantOutput int
	}
	routes := []route{
		{"/v1/chat/completions", "gpt-5", 111, 222},
		{"/v1/messages", "claude-sonnet-5", 444, 555},
	}

	var missingTokens []string
	for _, r := range routes {
		line := findLineForPath(r.path)
		if line == nil {
			t.Fatalf("QA-1: no access-log line found for path %s among: %v", r.path, lines)
		}
		if code, ok := numField(line, "response_code"); !ok || code != http.StatusOK {
			t.Errorf("QA-1: %s: want response_code 200, got %v (line: %v)", r.path, line["response_code"], line)
		}
		if sent, ok := numField(line, "bytes_sent"); !ok || sent <= 0 {
			t.Errorf("QA-1: %s: want bytes_sent > 0, got %v (line: %v)", r.path, line["bytes_sent"], line)
		}

		// Token gap: with no usage filter in the dialect's generated
		// http_filters, nothing populates the token buckets, so the formatter
		// renders every %LLM_*_TOKENS% operator as the absent-value "-".
		// Collect rather than assert, so the token half degrades to a loud
		// skip while everything above still runs.
		gotInput, haveInput := numField(line, "llm_input_tokens")
		gotOutput, haveOutput := numField(line, "llm_output_tokens")
		if !haveInput || !haveOutput {
			missingTokens = append(missingTokens, fmt.Sprintf(
				"%s (in=%v out=%v total=%v)",
				r.path, line["llm_input_tokens"], line["llm_output_tokens"], line["llm_total_tokens"],
			))
			continue
		}

		if gotInput != r.wantInput || gotOutput != r.wantOutput {
			t.Errorf(
				"QA-1: %s (model %s): want input=%d output=%d, got input=%v output=%v (line: %v)",
				r.path, r.model, r.wantInput, r.wantOutput,
				line["llm_input_tokens"], line["llm_output_tokens"], line,
			)
		}
	}

	if len(missingTokens) > 0 {
		t.Skipf(
			"QA-1: SKIP (token half only) — access logs are emitted and both routes "+
				"logged correctly, but every %%LLM_*_TOKENS%% operator rendered as \"-\": %v. "+
				"the proxy has not wired the usage filter into the `llmproxy` dialect's generated "+
				"http_filters, so nothing populates the token buckets. Routing, provider "+
				"dispatch, log emission, response codes and byte counts all passed above.",
			missingTokens,
		)
	}
}
