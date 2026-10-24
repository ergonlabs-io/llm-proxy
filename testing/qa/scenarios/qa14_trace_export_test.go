package scenarios

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ergonlabs-io/llm-proxy/testing/qa/harness"
	"github.com/ergonlabs-io/llm-proxy/testing/qa/mocks"
)

// QA-14: trace export captures an opted-in tenant's streamed request and
// produces nothing for a tenant that did not opt in (SCENARIOS.md).
//
// Black box: a dialect config with `auth` and `observability.traces`
// writing to a directory, two tenants created and given keys over the
// admin API, one opted in. Each sends the same streaming chat request. After
// SIGTERM the exporter seals its segments; the test reads them as a
// consumer would (gzip JSON lines) and checks there is exactly one line, for
// the opted-in tenant, whose request is the body the client sent and whose
// response is the stream reassembled into one chat completion.
func TestQA14_TraceExportCapturesOnlyAnOptedInTenant(t *testing.T) {
	const adminToken = "qa14-admin-token"
	t.Setenv("LLMPROXY_ADMIN_TOKEN", adminToken)

	chunks := []string{"Hel", "lo", " there"}
	openaiMock := mocks.NewOpenAI()
	defer openaiMock.Close()
	openaiMock.Stream = &mocks.StreamConfig{
		Chunks: chunks,
		Usage:  mocks.Usage{PromptTokens: 5, CompletionTokens: 3, TotalTokens: 8},
	}

	port := harness.FreePort(t)
	adminPort := harness.FreePort(t)
	traceDir := filepath.Join(t.TempDir(), "traces")
	cfg := fmt.Sprintf(`
version: 1
listen: 127.0.0.1:%d
admin: 127.0.0.1:%d
providers:
  openai:
    api_key: sk-test
    base_url: %s
routes:
  - model: "*"
    provider: openai
auth:
  hmac_secret: qa14-hmac-secret
observability:
  traces:
    directory: %s
    max_disk_bytes: 1073741824
    max_open_segments: 4
`, port, adminPort, openaiMock.URL(), traceDir)

	proxy := harness.Start(t, harness.StartOpts{
		ConfigPath: harness.WriteConfig(t, "llmproxy.yaml", cfg),
		ExtraArgs:  []string{"--service-node", "qa14-node", "--drain-time-s", "1"},
	})
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	admin := fmt.Sprintf("http://127.0.0.1:%d", adminPort)
	proxy.WaitReady(addr, 10*time.Second)
	proxy.WaitReady(fmt.Sprintf("127.0.0.1:%d", adminPort), 10*time.Second)

	adminCall := func(method, path, body string, want int) []byte {
		t.Helper()
		req, err := http.NewRequest(method, admin+path, strings.NewReader(body))
		if err != nil {
			t.Fatalf("QA-14: build %s %s: %v", method, path, err)
		}
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("QA-14: %s %s: %v\n--- proxy log ---\n%s", method, path, err, proxy.Log())
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("QA-14: %s %s: status %d, want %d: %s", method, path, resp.StatusCode, want, out)
		}
		return out
	}
	keys := map[string]string{}
	for _, tenant := range []string{"opted-in", "not-opted-in"} {
		adminCall("POST", "/tenants", fmt.Sprintf(`{"tenant":%q}`, tenant), http.StatusCreated)
		adminCall("PUT", "/tenants/"+tenant+"/policy", `{"access":"all"}`, http.StatusNoContent)
		var minted struct {
			Key string `json:"key"`
		}
		out := adminCall("POST", "/keys", fmt.Sprintf(`{"tenant":%q,"key_id":"key-%s"}`, tenant, tenant), http.StatusCreated)
		if err := json.Unmarshal(out, &minted); err != nil || minted.Key == "" {
			t.Fatalf("QA-14: POST /keys returned no key: %s", out)
		}
		keys[tenant] = minted.Key
	}
	adminCall("PUT", "/tenants/opted-in/trace_export", `{"schema_version":1,"enabled":true}`, http.StatusNoContent)

	reqBody := `{"model":"gpt-5","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	for _, tenant := range []string{"opted-in", "not-opted-in"} {
		req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/v1/chat/completions", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+keys[tenant])
		resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("QA-14: %s request: %v", tenant, err)
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("QA-14: %s request: status %d: %s", tenant, resp.StatusCode, body)
		}
		// Read the stream to its end, as a client would.
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
		}
		resp.Body.Close()
	}

	proxy.Signal(syscall.SIGTERM)
	if code := proxy.Wait(20 * time.Second); code != 0 {
		t.Fatalf("QA-14: proxy exited %d after SIGTERM\n--- proxy log ---\n%s", code, proxy.Log())
	}

	var lines []map[string]any
	err := filepath.Walk(traceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || strings.HasPrefix(info.Name(), ".") || !strings.HasSuffix(info.Name(), ".jsonl.gz") {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		scanner := bufio.NewScanner(gz)
		scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
		for scanner.Scan() {
			var line map[string]any
			if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
				return err
			}
			lines = append(lines, line)
		}
		return scanner.Err()
	})
	if err != nil {
		t.Fatalf("QA-14: read segments: %v", err)
	}
	if len(lines) != 1 {
		t.Fatalf("QA-14: want exactly one trace line (the opted-in tenant), got %d: %v", len(lines), lines)
	}
	line := lines[0]
	record, _ := line["record"].(map[string]any)
	if record["tenant_id"] != "opted-in" {
		t.Fatalf("QA-14: trace is for tenant %v, want opted-in", record["tenant_id"])
	}
	if line["event_id"] == nil || line["event_id"] != record["event_id"] {
		t.Fatalf("QA-14: event_id %v does not match the record's %v", line["event_id"], record["event_id"])
	}
	request, _ := line["request"].(map[string]any)
	sent := map[string]any{}
	_ = json.Unmarshal([]byte(reqBody), &sent)
	if got, _ := json.Marshal(request["body"]); string(got) != mustJSON(sent) {
		t.Fatalf("QA-14: captured request %s, want the body the client sent %s", got, mustJSON(sent))
	}
	response, _ := line["response"].(map[string]any)
	body, _ := response["body"].(map[string]any)
	choices, _ := body["choices"].([]any)
	if response["streamed"] != true || len(choices) != 1 {
		t.Fatalf("QA-14: response is not one reassembled completion: %v", response)
	}
	message, _ := choices[0].(map[string]any)["message"].(map[string]any)
	if message["content"] != strings.Join(chunks, "") {
		t.Fatalf("QA-14: reassembled content %q, want %q", message["content"], strings.Join(chunks, ""))
	}
	capture, _ := line["capture"].(map[string]any)
	if capture["state"] != "complete" {
		t.Fatalf("QA-14: capture state %v (%v), want complete", capture["state"], capture["reasons"])
	}
}

func mustJSON(v any) string {
	out, _ := json.Marshal(v)
	return string(out)
}
