package mocks

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"
)

// Usage mirrors OpenAI's chat-completions `usage` object.
type Usage struct {
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
}

// ChatCompletion is a canned non-streaming /v1/chat/completions response.
// Field names/shape match the real OpenAI response format.
type ChatCompletion struct {
	ID      string
	Content string
	Usage   Usage
}

// StreamConfig paces an SSE chat-completion stream in OpenAI's real event
// framing: a leading role-delta chunk, one `data: {...}` chunk per token in
// Chunks, a closing finish-reason chunk, a trailing usage-only chunk (the
// `stream_options.include_usage` shape), then `data: [DONE]`.
type StreamConfig struct {
	Chunks          []string // one delta.content token per chunk
	TTFT            time.Duration
	InterChunkDelay time.Duration
	Usage           Usage

	// AbortAfterChunks, when non-nil, cuts the stream short after that many
	// entries of Chunks have been written: instead of continuing on to the
	// finish-reason/usage/[DONE] frames, the handler reaches for the
	// underlying TCP connection via http.Hijacker and closes it raw. This is
	// deliberately NOT a plain early `return` from the handler — returning
	// normally still lets net/http write a clean terminating chunk, which
	// produces an ordinary chunked-EOF the client can't distinguish from a
	// short-but-successful response. Hijacking and closing the raw
	// connection mid-chunk is what actually reproduces "upstream died
	// mid-stream" (QA-6).
	AbortAfterChunks *int
}

// OpenAI is a mock OpenAI-compatible upstream serving POST /v1/chat/completions.
type OpenAI struct {
	Server *httptest.Server

	mu       sync.Mutex
	requests []RecordedRequest

	// NonStreaming is served for any request with "stream" absent or false.
	NonStreaming *ChatCompletion
	// Stream is served for any request with "stream": true.
	Stream *StreamConfig
	// NonStreamingDelay holds each non-streaming request (after it is
	// recorded) before the response is written, so a scenario can keep a
	// request in flight at the upstream (QA-8).
	NonStreamingDelay time.Duration

	// failStatus, when non-zero, answers every request with that status and
	// a JSON error body instead of a completion (QA-17). Set it with
	// SetFailStatus; it is read under mu because the proxy's requests arrive
	// on server goroutines while the scenario changes it.
	failStatus int
}

// SetFailStatus makes every later request fail with status (0 restores
// normal responses). The request is still recorded first.
func (m *OpenAI) SetFailStatus(status int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failStatus = status
}

func NewOpenAI() *OpenAI {
	m := &OpenAI{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", m.handleChatCompletions)
	m.Server = httptest.NewServer(mux)
	return m
}

func (m *OpenAI) Close() { m.Server.Close() }

// URL is the mock's base URL, suitable for a provider's `base_url`.
func (m *OpenAI) URL() string { return m.Server.URL }

// Requests returns every request recorded so far, in arrival order.
func (m *OpenAI) Requests() []RecordedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]RecordedRequest, len(m.requests))
	copy(out, m.requests)
	return out
}

func (m *OpenAI) record(r *http.Request, body map[string]any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, RecordedRequest{
		Method:  r.Method,
		Path:    r.URL.Path,
		Headers: r.Header.Clone(),
		Body:    body,
	})
}

func (m *OpenAI) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var body map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	m.record(r, body)

	m.mu.Lock()
	failStatus := m.failStatus
	m.mu.Unlock()
	if failStatus != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(failStatus)
		_, _ = w.Write([]byte(`{"error":{"message":"mock: forced failure","type":"server_error"}}`))
		return
	}

	if streaming, _ := body["stream"].(bool); streaming {
		m.serveStream(w, body)
		return
	}
	m.serveNonStreaming(w, body)
}

func (m *OpenAI) serveNonStreaming(w http.ResponseWriter, body map[string]any) {
	if m.NonStreaming == nil {
		http.Error(w, "mock: no NonStreaming response configured", http.StatusInternalServerError)
		return
	}
	c := m.NonStreaming
	model, _ := body["model"].(string)
	time.Sleep(m.NonStreamingDelay)

	resp := map[string]any{
		"id":      c.ID,
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []map[string]any{
			{
				"index":         0,
				"message":       map[string]any{"role": "assistant", "content": c.Content},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]any{
			"prompt_tokens":     c.Usage.PromptTokens,
			"completion_tokens": c.Usage.CompletionTokens,
			"total_tokens":      c.Usage.TotalTokens,
		},
	}
	enc, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(enc)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(enc)
}

func (m *OpenAI) serveStream(w http.ResponseWriter, body map[string]any) {
	if m.Stream == nil {
		http.Error(w, "mock: no Stream response configured", http.StatusInternalServerError)
		return
	}
	s := m.Stream
	model, _ := body["model"].(string)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "mock: ResponseWriter does not support flushing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	id := fmt.Sprintf("chatcmpl-mock-%d", time.Now().UnixNano())
	created := time.Now().Unix()

	writeChunk := func(delta map[string]any, finishReason any) {
		chunk := map[string]any{
			"id":      id,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   model,
			"choices": []map[string]any{
				{"index": 0, "delta": delta, "finish_reason": finishReason},
			},
		}
		enc, _ := json.Marshal(chunk)
		fmt.Fprintf(w, "data: %s\n\n", enc)
		flusher.Flush()
	}

	time.Sleep(s.TTFT)
	writeChunk(map[string]any{"role": "assistant"}, nil)

	for i, tok := range s.Chunks {
		if i > 0 {
			time.Sleep(s.InterChunkDelay)
		}
		writeChunk(map[string]any{"content": tok}, nil)

		if s.AbortAfterChunks != nil && i+1 == *s.AbortAfterChunks {
			// Note: reaching for http.Hijacker takes
			// over the raw net.Conn from net/http, so nothing further --
			// not even a terminating "0\r\n\r\n" chunk -- ever reaches the
			// client. See the AbortAfterChunks doc comment for why a plain
			// return isn't equivalent.
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				panic("mock: ResponseWriter does not support hijacking")
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				panic(fmt.Sprintf("mock: hijack failed: %v", err))
			}
			_ = conn.Close()
			return
		}
	}

	writeChunk(map[string]any{}, "stop")

	// Trailing usage-only chunk: real OpenAI (with
	// stream_options.include_usage) sends one final chunk with an empty
	// choices array and the usage totals, just before [DONE].
	usageChunk := map[string]any{
		"id":      id,
		"object":  "chat.completion.chunk",
		"created": created,
		"model":   model,
		"choices": []any{},
		"usage": map[string]any{
			"prompt_tokens":     s.Usage.PromptTokens,
			"completion_tokens": s.Usage.CompletionTokens,
			"total_tokens":      s.Usage.TotalTokens,
		},
	}
	enc, _ := json.Marshal(usageChunk)
	fmt.Fprintf(w, "data: %s\n\n", enc)
	flusher.Flush()

	fmt.Fprint(w, "data: [DONE]\n\n")
	flusher.Flush()
}
