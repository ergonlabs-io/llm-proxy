package scenarios

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vigneshaigal/llm-proxy/testing/qa/harness"
	"github.com/vigneshaigal/llm-proxy/testing/qa/mocks"
)

// QA-7: SIGTERM during an active stream drains it to completion
// (SCENARIOS.md — commit 6153e6d fixed shutdown handlers being installed too
// late, so a signal arriving in the startup window killed the process
// outright with no drain; its regression test only exercised a plain TCP
// accept, never an in-flight stream, which is the case the drain path
// exists for).
//
// The mock is paced at ~200ms/chunk over 10 chunks. Once at least 3 content
// chunks have reached the client, SIGTERM is sent to the proxy -- gated on
// frames actually received, not a sleep, so the signal genuinely lands
// mid-stream regardless of scheduling jitter. The proxy is started with a
// drain window comfortably longer than the stream's remaining runtime so the
// drain sequence has time to let the in-flight connection finish naturally
// rather than being cut off by the drain deadline.
//
// This is the mirror image of QA-6: QA-6 proves the client can observe a
// truncated stream (an ordinary upstream failure). QA-7 proves a graceful
// shutdown produces NO such signal -- the read must look exactly like a
// fully successful stream, terminal [DONE] frame included, with no read
// error, despite a SIGTERM having landed mid-flight.
func TestQA7_SigtermDuringStreamDrainsToCompletion(t *testing.T) {
	const (
		numChunks       = 10
		ttft            = 50 * time.Millisecond
		interChunkDelay = 200 * time.Millisecond
		signalAfter     = 3 // content chunks received before SIGTERM is sent
		drainTimeS      = 5 // comfortably longer than the ~1.5s of stream left at signalAfter
	)

	chunks := make([]string, numChunks)
	for i := range chunks {
		chunks[i] = fmt.Sprintf("tok%d", i)
	}

	openaiMock := mocks.NewOpenAI()
	defer openaiMock.Close()
	openaiMock.Stream = &mocks.StreamConfig{
		Chunks:          chunks,
		TTFT:            ttft,
		InterChunkDelay: interChunkDelay,
		Usage:           mocks.Usage{PromptTokens: 10, CompletionTokens: numChunks, TotalTokens: 10 + numChunks},
	}

	port := harness.FreePort(t)
	logPath := harness.TempFilePath(t, "access.log")

	cfg := fmt.Sprintf(`
version: 1
listen: 127.0.0.1:%d
providers:
  openai:
    api_key: sk-test
    base_url: %s
routes:
  - model: "*"
    provider: openai
observability:
  access_logs:
    output: %s
    format: json
`, port, openaiMock.URL(), logPath)

	configPath := harness.WriteConfig(t, "llmproxy.yaml", cfg)
	proxy := harness.Start(t, harness.StartOpts{
		ConfigPath: configPath,
		ExtraArgs:  []string{"--drain-time-s", fmt.Sprintf("%d", drainTimeS)},
	})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	proxy.WaitReady(addr, 10*time.Second)

	reqBody := `{"model":"gpt-5","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/v1/chat/completions", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("QA-7: build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-llmproxy-model", "gpt-5")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("QA-7: request: %v\n--- proxy log ---\n%s", err, proxy.Log())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("QA-7: got status %d\n--- proxy log ---\n%s", resp.StatusCode, proxy.Log())
	}

	// sseChunk mirrors the shape mocks.OpenAI's serveStream writes, just
	// enough to tell a content-delta chunk apart from the leading role-delta,
	// the finish-reason chunk, and the trailing usage-only chunk.
	type sseChunk struct {
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}

	var frames []string
	var contentTokens []string
	signaled := false

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		frame := strings.TrimPrefix(line, "data: ")
		frames = append(frames, frame)

		if frame != "[DONE]" {
			var c sseChunk
			if err := json.Unmarshal([]byte(frame), &c); err == nil && len(c.Choices) > 0 && c.Choices[0].Delta.Content != "" {
				contentTokens = append(contentTokens, c.Choices[0].Delta.Content)
			}
		}

		// Gate the signal on frames actually received, not a sleep: if it
		// arrived after the last chunk the case would silently test nothing.
		if !signaled && len(contentTokens) >= signalAfter {
			proxy.Terminate()
			signaled = true
		}
	}
	scanErr := scanner.Err()
	if !signaled {
		t.Fatalf(
			"QA-7: never reached %d content chunks before the stream ended -- SIGTERM was never "+
				"sent, so this run tested nothing. contentTokens=%v frames=%v\n--- proxy log ---\n%s",
			signalAfter, contentTokens, frames, proxy.Log(),
		)
	}

	// Property 1 (load-bearing): the client must see a fully successful
	// stream -- all 10 content tokens, in order, terminated by "[DONE]",
	// with no read error. Unlike QA-6 (where an observable failure is the
	// correct outcome), here ANY sign of truncation is the bug: SIGTERM
	// landing mid-stream must be invisible to the client that was already
	// being served.
	if scanErr != nil {
		t.Fatalf(
			"QA-7: reading the stream errored after SIGTERM -- a graceful drain must not truncate "+
				"an in-flight stream: %v\ncontentTokens=%v frames=%v\n--- proxy log ---\n%s",
			scanErr, contentTokens, frames, proxy.Log(),
		)
	}
	if len(frames) == 0 || frames[len(frames)-1] != "[DONE]" {
		t.Fatalf(
			"QA-7: stream did not end with a clean [DONE] frame after SIGTERM -- got frames=%v\n"+
				"--- proxy log ---\n%s",
			frames, proxy.Log(),
		)
	}
	if len(contentTokens) != numChunks {
		t.Fatalf(
			"QA-7: expected all %d content chunks, got %d: %v\n--- proxy log ---\n%s",
			numChunks, len(contentTokens), contentTokens, proxy.Log(),
		)
	}
	for i, tok := range contentTokens {
		want := chunks[i]
		if tok != want {
			t.Fatalf("QA-7: content chunk %d = %q, want %q (order/content mismatch): %v", i, tok, want, contentTokens)
		}
	}

	// Property 2: the process exits 0 within the drain timeout -- a drain
	// that never converges (or crashes instead of exiting cleanly) is its
	// own bug distinct from truncating the stream.
	exitCode := proxy.Wait(time.Duration(drainTimeS+5) * time.Second)
	if exitCode != 0 {
		t.Fatalf("QA-7: proxy exited %d after SIGTERM, want 0\n--- proxy log ---\n%s", exitCode, proxy.Log())
	}

	// Property 3: an access-log line was written for the completed request.
	if !harness.WaitForFile(logPath, 5*time.Second) {
		t.Fatalf("QA-7: access log %s was never created\n--- proxy log ---\n%s", logPath, proxy.Log())
	}
	lines := harness.WaitForAccessLogLines(t, logPath, 1, 5*time.Second)
	if len(lines) < 1 {
		t.Fatalf("QA-7: expected at least 1 access-log line, got %d", len(lines))
	}
}
