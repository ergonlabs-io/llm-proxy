package scenarios

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ergonlabs-io/llm-proxy/testing/qa/harness"
	"github.com/ergonlabs-io/llm-proxy/testing/qa/mocks"
)

// QA-8: a circuit-breaker-rejected request fails fast rather than queueing
// (SCENARIOS.md — "A circuit-breaker-rejected request fails fast rather than
// queueing").
//
// An Envoy-mode bootstrap, because the dialect has no circuit_breakers field:
// the cluster allows one request in flight. The first request is held at the
// mock for upstreamDelay; a second request sent while it is held must be
// rejected locally (503, x-envoy-overloaded, UO), never reach the mock, and
// come back while the first is still in flight. That last point is the
// queued baseline: a queueing breaker could only answer the second request
// after the first released its slot.
func TestQA8_CircuitBreakerRejectsFast(t *testing.T) {
	const upstreamDelay = 2 * time.Second

	upstream := mocks.NewOpenAI()
	defer upstream.Close()
	upstream.NonStreaming = &mocks.ChatCompletion{
		ID:      "chatcmpl-qa8",
		Content: "the slow first answer",
		Usage:   mocks.Usage{PromptTokens: 3, CompletionTokens: 4, TotalTokens: 7},
	}
	upstream.NonStreamingDelay = upstreamDelay

	host, upPort, err := net.SplitHostPort(strings.TrimPrefix(upstream.URL(), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	listener := harness.FreePort(t)
	logPath := harness.TempFilePath(t, "access.log")

	bootstrap := fmt.Sprintf(`
static_resources:
  clusters:
  - name: openai
    type: STATIC
    connect_timeout: 1s
    circuit_breakers:
      thresholds:
      - priority: DEFAULT
        max_requests: 1
    load_assignment:
      cluster_name: openai
      endpoints:
      - lb_endpoints:
        - endpoint:
            address: {socket_address: {address: %s, port_value: %s}}
  listeners:
  - name: qa8
    address: {socket_address: {address: 127.0.0.1, port_value: %d}}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          '@type': type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: qa8
          access_log:
          - name: envoy.access_loggers.file
            typed_config:
              '@type': type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
              path: %s
              log_format:
                json_format:
                  path: '%%REQ(:PATH)%%'
                  response_code: '%%RESPONSE_CODE%%'
                  response_flags: '%%RESPONSE_FLAGS%%'
          route_config:
            name: qa8
            virtual_hosts:
            - name: qa8
              domains: ['*']
              routes:
              - match: {prefix: /}
                route: {cluster: openai}
          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              '@type': type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
`, host, upPort, listener, logPath)

	path := harness.WriteConfig(t, "bootstrap.yaml", bootstrap)
	proxy := harness.Start(t, harness.StartOpts{BootstrapPath: path})
	addr := fmt.Sprintf("127.0.0.1:%d", listener)
	proxy.WaitReady(addr, 10*time.Second)

	type result struct {
		status  int
		header  http.Header
		body    []byte
		elapsed time.Duration
		err     error
	}
	// Separate clients, so the second request cannot wait behind the first
	// on a shared client-side connection.
	send := func() result {
		reqBody, _ := json.Marshal(map[string]any{
			"model":    "gpt-5",
			"messages": []map[string]string{{"role": "user", "content": "hi"}},
		})
		req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/v1/chat/completions", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{}}
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			return result{err: err, elapsed: time.Since(start)}
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		return result{status: resp.StatusCode, header: resp.Header, body: body, err: err, elapsed: time.Since(start)}
	}

	firstDone := make(chan result, 1)
	go func() { firstDone <- send() }()

	// Send the second request only once the first holds the breaker's one
	// slot: the mock records a request before it starts the delay.
	deadline := time.Now().Add(5 * time.Second)
	for len(upstream.Requests()) < 1 {
		if time.Now().After(deadline) {
			t.Fatalf("QA-8: first request never reached the mock\n--- proxy log ---\n%s", proxy.Log())
		}
		time.Sleep(10 * time.Millisecond)
	}

	second := send()
	var first result
	firstStillRunning := false
	select {
	case first = <-firstDone:
	default:
		firstStillRunning = true
		first = <-firstDone
	}

	if first.err != nil {
		t.Fatalf("QA-8: first request: %v\n--- proxy log ---\n%s", first.err, proxy.Log())
	}
	if second.err != nil {
		t.Fatalf("QA-8: second request: %v\n--- proxy log ---\n%s", second.err, proxy.Log())
	}

	// The second request is rejected locally and fast.
	if second.status < 500 || second.status > 599 {
		t.Errorf("QA-8: second request: want a 503-class status, got %d: %s", second.status, second.body)
	}
	if second.header.Get("x-envoy-overloaded") == "" {
		t.Errorf("QA-8: second request: want x-envoy-overloaded, got headers %v", second.header)
	}
	if !firstStillRunning {
		t.Errorf("QA-8: second request (%s) finished only after the first (%s) released its slot: it queued",
			second.elapsed, first.elapsed)
	}
	// Wide bound: the rejection is local, so anything near the upstream
	// delay means it waited on the upstream.
	if second.elapsed >= upstreamDelay {
		t.Errorf("QA-8: second request took %s, want well under the %s upstream delay", second.elapsed, upstreamDelay)
	}
	if got := len(upstream.Requests()); got != 1 {
		t.Errorf("QA-8: want exactly 1 request at the mock (the rejected one never dialled), got %d", got)
	}

	// The first request completes normally with its full body.
	if first.status != http.StatusOK {
		t.Errorf("QA-8: first request: want 200, got %d: %s", first.status, first.body)
	}
	var completion struct {
		ID      string `json:"id"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(first.body, &completion); err != nil || completion.ID != "chatcmpl-qa8" ||
		len(completion.Choices) != 1 || completion.Choices[0].Message.Content != "the slow first answer" {
		t.Errorf("QA-8: first request: want the mock's full completion, got %s (decode error %v)", first.body, err)
	}

	// The rejected request's log line carries UO.
	lines := harness.WaitForAccessLogLines(t, logPath, 2, 5*time.Second)
	var rejected []map[string]any
	for _, l := range lines {
		if l["response_code"] == fmt.Sprint(second.status) {
			rejected = append(rejected, l)
		}
	}
	if len(rejected) != 1 {
		t.Fatalf("QA-8: want exactly 1 access-log line with response_code %d, got %d: %v", second.status, len(rejected), lines)
	}
	if flags, _ := rejected[0]["response_flags"].(string); !strings.Contains(flags, "UO") {
		t.Errorf("QA-8: rejected request's response_flags: want UO, got %q (line: %v)", flags, rejected[0])
	}
}
