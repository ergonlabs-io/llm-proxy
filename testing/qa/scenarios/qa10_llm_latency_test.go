package scenarios

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vigneshaigal/llm-proxy/testing/qa/harness"
	"github.com/vigneshaigal/llm-proxy/testing/qa/mocks"
)

// QA-10: TTFT and TPOT reach the access log, with values that match the
// upstream's pacing (SCENARIOS.md — "TTFT and TPOT reach the access log,
// with values that match the upstream's pacing").
//
// TPOT has already shipped one silent bug of exactly the shape a black-box
// test is meant to catch: it divided in integer milliseconds, so it
// rendered 0 for fast providers (1000-2000 tok/s) -- reading zero precisely
// when performance was best. A `0` looks entirely plausible sitting in a
// log line next to other numbers, so `llm_tpot_ms` being strictly greater
// than zero is the load-bearing assertion here, not just "the field is
// present". The config below uses the dialect's DEFAULT json access-log
// format (no hand-written format naming the operators), since part of the
// point is proving the default carries these fields at all.
func TestQA10_LLMLatencyReachesAccessLog(t *testing.T) {
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
	logPath := harness.TempFilePath(t, "access.log")

	// Deliberately no hand-written `format` operator list: the dialect's
	// default json format is what's under test, per SCENARIOS.md.
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
		t.Fatalf("QA-10: build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-llmproxy-model", "gpt-5")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("QA-10: request: %v\n--- proxy log ---\n%s", err, proxy.Log())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("QA-10: got status %d\n--- proxy log ---\n%s", resp.StatusCode, proxy.Log())
	}

	// Drain the stream to completion so the request finishes and its
	// access-log line is written.
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var sawDone bool
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimPrefix(line, "data: ") == "[DONE]" {
			sawDone = true
			break
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("QA-10: reading stream: %v\n--- proxy log ---\n%s", err, proxy.Log())
	}
	if !sawDone {
		t.Fatalf("QA-10: stream ended without [DONE]\n--- proxy log ---\n%s", proxy.Log())
	}

	if !harness.WaitForFile(logPath, 5*time.Second) {
		t.Fatalf("QA-10: access log file %s was never created\n--- proxy log ---\n%s", logPath, proxy.Log())
	}
	lines := harness.WaitForAccessLogLines(t, logPath, 1, 5*time.Second)
	if len(lines) < 1 {
		t.Fatalf("QA-10: expected at least 1 access-log line, got %d: %v", len(lines), lines)
	}
	line := lines[0]

	// Every value in a json_format line is a JSON *string*, including
	// numeric ones -- see SCENARIOS.md's standing note on this. Parse,
	// don't type-assert.
	numField := func(key string) (int, bool) {
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

	ttftMs, haveTTFT := numField("llm_ttft_ms")
	if !haveTTFT {
		t.Fatalf("QA-10: llm_ttft_ms missing or non-numeric: %v (line: %v)", line["llm_ttft_ms"], line)
	}
	// Generous lower bound only -- half the configured TTFT -- to absorb
	// scheduling jitter and the client -> proxy -> mock round trip, per
	// this suite's standing rule against tight timing equality (QA-3 uses
	// the same fraction for the same reason).
	minTTFT := int(ttft.Milliseconds()) / 2
	if ttftMs < minTTFT {
		t.Errorf("QA-10: llm_ttft_ms=%d, expected at least ~%dms (configured TTFT %s)", ttftMs, minTTFT, ttft)
	}

	// The load-bearing assertion: llm_tpot_ms must be strictly greater than
	// zero. This is the exact regression that already shipped once --
	// integer-millisecond division rendered 0 for fast providers, and a 0
	// sitting in a log line looks entirely plausible to a reader. "Present"
	// is not enough; it must be a real, non-zero measurement.
	//
	// TPOT renders fractional milliseconds ("<ms>.<micros>", e.g.
	// "121.965") rather than a plain integer like the other *_ms fields --
	// that's the whole point of the operator (see access_logging.rs's
	// llm_tpot_reaches_the_rendered_line_via_real_stream_info) -- so it
	// needs float parsing, not numField's strconv.Atoi.
	tpotStr, ok := line["llm_tpot_ms"].(string)
	if !ok {
		t.Fatalf("QA-10: llm_tpot_ms missing or not a string: %v (line: %v)", line["llm_tpot_ms"], line)
	}
	tpotMs, err := strconv.ParseFloat(tpotStr, 64)
	if err != nil {
		t.Fatalf("QA-10: llm_tpot_ms=%q not parseable as a number: %v (line: %v)", tpotStr, err, line)
	}
	if tpotMs <= 0 {
		t.Errorf(
			"QA-10: llm_tpot_ms=%v, expected strictly > 0 -- this is the exact shape of the "+
				"integer-millisecond-division bug that once rendered 0 for fast providers (line: %v)",
			tpotMs, line,
		)
	}
	// A wide band around the configured inter-chunk delay: a quarter of it
	// as the lower bound, four times it as the upper bound. TPOT is a mean
	// over several gaps that include the role-delta -> first-content-chunk
	// transition (paced at TTFT, not interChunkDelay) as one of its inputs
	// to `max_inter_chunk`/timing bookkeeping, and scheduler jitter across
	// process hops adds more slack -- so this asserts "in the neighbourhood
	// of interChunkDelay", never tight equality, per this document's
	// standing rule.
	minTPOT := float64(interChunkDelay.Milliseconds()) / 4
	maxTPOT := float64(interChunkDelay.Milliseconds()) * 4
	if tpotMs < minTPOT || tpotMs > maxTPOT {
		t.Errorf(
			"QA-10: llm_tpot_ms=%v, expected roughly in [%v, %v]ms (configured inter-chunk delay %s)",
			tpotMs, minTPOT, maxTPOT, interChunkDelay,
		)
	}

	// response_chunks counts every NON-EMPTY body frame the usage filter
	// observed arriving from upstream: the role-delta chunk, one per content
	// token, the finish-reason chunk, the trailing usage chunk, and the
	// closing `data: [DONE]` frame -- see mocks.OpenAI.serveStream's exact
	// write sequence. Unlike TTFT/TPOT this is a count, not a timing, so it
	// is asserted exactly.
	//
	// This assertion found a real defect on 2026-08-08, which is why the
	// arithmetic below is 9 and not 10. filter_manager.rs delivers a final
	// synthetic `end_stream = true` EMPTY frame after the real body ends, so
	// a filter that gated on end-of-stream can release its buffer — and
	// record_chunk_timing was counting it. That made %LLM_RESPONSE_CHUNKS%
	// over-report by exactly one on every response with a body, and fed the
	// gap before that phantom frame into %LLM_MAX_STALL% as a stall no
	// client ever waited through. Fixed in usage_filter.rs by skipping
	// zero-length frames; if this assertion ever wants "+1" again, that
	// guard has been lost.
	wantChunks := 1 + numChunks + 1 + 1 + 1
	gotChunks, haveChunks := numField("llm_response_chunks")
	if !haveChunks {
		t.Fatalf("QA-10: llm_response_chunks missing or non-numeric: %v (line: %v)", line["llm_response_chunks"], line)
	}
	if gotChunks != wantChunks {
		t.Errorf("QA-10: llm_response_chunks=%d, want exactly %d (line: %v)", gotChunks, wantChunks, line)
	}
}
