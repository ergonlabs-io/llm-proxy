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

	"github.com/ergonlabs-io/llm-proxy/testing/qa/harness"
	"github.com/ergonlabs-io/llm-proxy/testing/qa/mocks"
)

// QA-5: non-streaming responses log real byte counts and token usage, not
// defaults (SCENARIOS.md — "Non-streaming responses log real byte counts and
// token usage, not defaults").
//
// The mock answers a `stream: false` request with a content-length body, the
// response shape whose end-of-stream logic once never ran. The log line must
// carry the exact byte count the client received and the mock's exact usage.
func TestQA5_NonStreamingLogsBytesAndTokens(t *testing.T) {
	upstream := mocks.NewOpenAI()
	defer upstream.Close()
	// Distinct, non-zero values, so a default (0 or "-") or a swapped field
	// cannot match by coincidence.
	upstream.NonStreaming = &mocks.ChatCompletion{
		ID:      "chatcmpl-qa5",
		Content: "a non-streaming answer of known length",
		Usage:   mocks.Usage{PromptTokens: 37, CompletionTokens: 59, TotalTokens: 96},
	}

	port := harness.FreePort(t)
	logPath := harness.TempFilePath(t, "access.log")

	// As QA-1. The dialect's default json format already includes
	// bytes_sent ('%BYTES_SENT%'), so no hand-written format is needed.
	cfg := fmt.Sprintf(`
version: 1
listen: 127.0.0.1:%d
providers:
  openai:
    api_key: sk-test-openai-canary
    base_url: %s
routes:
  - model: "gpt-*"
    provider: openai
observability:
  access_logs:
    output: %s
    format: json
`, port, upstream.URL(), logPath)

	configPath := harness.WriteConfig(t, "llmproxy.yaml", cfg)
	proxy := harness.Start(t, harness.StartOpts{ConfigPath: configPath})
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	proxy.WaitReady(addr, 10*time.Second)

	reqBody, _ := json.Marshal(map[string]any{
		"model":    "gpt-5",
		"stream":   false,
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/v1/chat/completions", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("QA-5: build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-llmproxy-model", "gpt-5")

	// DisableCompression: Go's transport otherwise asks for gzip and
	// decompresses transparently, and the decoded length would not be the
	// byte count the proxy sent.
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableCompression: true}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("QA-5: request: %v\n--- proxy log ---\n%s", err, proxy.Log())
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("QA-5: read response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("QA-5: want 200, got %d: %s\n--- proxy log ---\n%s", resp.StatusCode, body, proxy.Log())
	}
	// The case is about content-length responses; a chunked reply would
	// exercise a different path and pass for the wrong reason.
	if resp.ContentLength != int64(len(body)) {
		t.Fatalf("QA-5: want a content-length response of %d bytes, got Content-Length %d (transfer-encoding %v)",
			len(body), resp.ContentLength, resp.TransferEncoding)
	}

	lines := harness.WaitForAccessLogLines(t, logPath, 1, 5*time.Second)
	if len(lines) != 1 {
		t.Fatalf("QA-5: want exactly 1 access-log line, got %d: %v", len(lines), lines)
	}
	line := lines[0]

	// json_format values are strings; an absent value renders as "-", which
	// Atoi rejects.
	field := func(key string) (int, bool) {
		s, ok := line[key].(string)
		if !ok {
			return 0, false
		}
		n, err := strconv.Atoi(s)
		return n, err == nil
	}

	if got, ok := field("bytes_sent"); !ok || got != len(body) {
		t.Errorf("QA-5: bytes_sent: want %d (the body the client received), got %v (line: %v)",
			len(body), line["bytes_sent"], line)
	}
	for _, f := range []struct {
		key  string
		want int
	}{
		{"llm_input_tokens", 37},
		{"llm_output_tokens", 59},
		{"llm_total_tokens", 96},
	} {
		if got, ok := field(f.key); !ok || got != f.want {
			t.Errorf("QA-5: %s: want %d (the mock's usage), got %v (line: %v)", f.key, f.want, line[f.key], line)
		}
	}
}
