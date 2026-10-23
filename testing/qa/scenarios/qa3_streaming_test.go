package scenarios

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vigneshaigal/llm-proxy/testing/qa/harness"
	"github.com/vigneshaigal/llm-proxy/testing/qa/mocks"
)

// QA-3: a streamed response reaches the client incrementally, not in one
// flush (SCENARIOS.md — "streaming is the product; a response that arrives
// correctly but all at once passes every naive assertion while being a
// serious bug").
//
// The mock is paced with a large time-to-first-token and a small
// inter-chunk delay across several chunks. Two properties are asserted:
//  1. the first frame arrives no earlier than roughly TTFT (the proxy isn't
//     racing ahead of the upstream — a sanity check on the harness/mock
//     pairing more than the proxy itself);
//  2. the LAST frame arrives at least (chunks-1) * interChunkDelay after the
//     FIRST frame. This second half is load-bearing: a proxy that buffered
//     the entire upstream response before writing anything to the client
//     would deliver every frame back-to-back regardless of how the mock
//     paced them, and only this delta-between-first-and-last check catches
//     that. Tight equality is deliberately avoided throughout — scheduler
//     jitter, GC pauses, and the two extra process hops (client -> proxy ->
//     mock) all add slack that has nothing to do with correctness.
func TestQA3_StreamingArrivesIncrementally(t *testing.T) {
	const (
		ttft            = 400 * time.Millisecond
		interChunkDelay = 150 * time.Millisecond
		numChunks       = 5
	)

	openaiMock := mocks.NewOpenAI()
	defer openaiMock.Close()

	chunks := make([]string, numChunks)
	for i := range chunks {
		chunks[i] = fmt.Sprintf("tok%d", i)
	}
	openaiMock.Stream = &mocks.StreamConfig{
		Chunks:          chunks,
		TTFT:            ttft,
		InterChunkDelay: interChunkDelay,
		Usage:           mocks.Usage{PromptTokens: 10, CompletionTokens: numChunks, TotalTokens: 10 + numChunks},
	}

	port := harness.FreePort(t)
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
`, port, openaiMock.URL())

	configPath := harness.WriteConfig(t, "llmproxy.yaml", cfg)
	proxy := harness.Start(t, harness.StartOpts{ConfigPath: configPath})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	proxy.WaitReady(addr, 10*time.Second)

	reqBody, _ := json.Marshal(map[string]any{
		"model":    "gpt-5",
		"stream":   true,
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/v1/chat/completions", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("QA-3: build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-llmproxy-model", "gpt-5")

	client := &http.Client{Timeout: 30 * time.Second}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("QA-3: request: %v\n--- proxy log ---\n%s", err, proxy.Log())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("QA-3: got status %d\n--- proxy log ---\n%s", resp.StatusCode, proxy.Log())
	}

	// Timestamp every SSE "data: " frame as it arrives off the wire.
	var frameTimes []time.Time
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		frameTimes = append(frameTimes, time.Now())
		if strings.TrimPrefix(line, "data: ") == "[DONE]" {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("QA-3: reading stream: %v\n--- proxy log ---\n%s", err, proxy.Log())
	}

	// role-delta + numChunks content deltas + finish + usage + [DONE].
	wantFrames := 1 + numChunks + 1 + 1 + 1
	if len(frameTimes) != wantFrames {
		t.Fatalf("QA-3: expected %d SSE frames, got %d\n--- proxy log ---\n%s", wantFrames, len(frameTimes), proxy.Log())
	}

	firstFrame := frameTimes[0]
	lastFrame := frameTimes[len(frameTimes)-1]

	// Property 1: the first frame shouldn't arrive suspiciously early —
	// generous tolerance (half of TTFT) to absorb scheduling jitter and the
	// client -> proxy -> mock round trip, while still catching a proxy that
	// (for example) synthesized its own immediate response instead of
	// actually waiting on the upstream.
	firstFrameDelay := firstFrame.Sub(start)
	minFirstFrameDelay := ttft / 2
	if firstFrameDelay < minFirstFrameDelay {
		t.Errorf(
			"QA-3: first frame arrived after %s, expected at least ~%s (configured TTFT %s)",
			firstFrameDelay, minFirstFrameDelay, ttft,
		)
	}

	// Property 2 (load-bearing): the last frame must land a meaningful
	// amount of time after the first — this is what a buffering proxy
	// fails, since it would deliver every frame at effectively the same
	// instant regardless of how the mock paced them. There are
	// numChunks-1 gaps between the numChunks content-delta frames; use a
	// generous 50% tolerance on the expected minimum spread rather than the
	// exact value, since this is a timing property, not an exact schedule.
	minSpread := time.Duration(float64(numChunks-1) * float64(interChunkDelay) * 0.5)
	spread := lastFrame.Sub(firstFrame)
	if spread < minSpread {
		t.Errorf(
			"QA-3: frames arrived too close together (spread=%s), expected at least ~%s "+
				"[(chunks-1) * interChunkDelay * 0.5 = (%d-1) * %s * 0.5] — this is the "+
				"signature of a proxy that buffered the whole response instead of streaming it",
			spread, minSpread, numChunks, interChunkDelay,
		)
	}
}
