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

// AnthropicUsage mirrors Anthropic's `usage` object.
type AnthropicUsage struct {
	InputTokens              int
	OutputTokens             int
	CacheReadInputTokens     int
	CacheCreationInputTokens int
}

// AnthropicMessage is a canned non-streaming /v1/messages response. Field
// names/shape match the real Anthropic Messages API format.
type AnthropicMessage struct {
	ID      string
	Content string
	Usage   AnthropicUsage
}

// AnthropicStreamConfig paces an SSE stream in Anthropic's real event
// framing: message_start (carries input/cache usage) -> content_block_start
// -> repeated content_block_delta -> content_block_stop -> message_delta
// (carries the output token count) -> message_stop.
type AnthropicStreamConfig struct {
	Chunks          []string
	TTFT            time.Duration
	InterChunkDelay time.Duration
	Usage           AnthropicUsage
}

// Anthropic is a mock Anthropic-compatible upstream serving POST /v1/messages.
type Anthropic struct {
	Server *httptest.Server

	mu       sync.Mutex
	requests []RecordedRequest

	NonStreaming *AnthropicMessage
	Stream       *AnthropicStreamConfig
}

func NewAnthropic() *Anthropic {
	m := &Anthropic{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/messages", m.handleMessages)
	m.Server = httptest.NewServer(mux)
	return m
}

func (m *Anthropic) Close() { m.Server.Close() }

// URL is the mock's base URL, suitable for a provider's `base_url`.
func (m *Anthropic) URL() string { return m.Server.URL }

// Requests returns every request recorded so far, in arrival order.
func (m *Anthropic) Requests() []RecordedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]RecordedRequest, len(m.requests))
	copy(out, m.requests)
	return out
}

func (m *Anthropic) record(r *http.Request, body map[string]any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, RecordedRequest{
		Method:  r.Method,
		Path:    r.URL.Path,
		Headers: r.Header.Clone(),
		Body:    body,
	})
}

func (m *Anthropic) handleMessages(w http.ResponseWriter, r *http.Request) {
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

	if streaming, _ := body["stream"].(bool); streaming {
		m.serveStream(w, body)
		return
	}
	m.serveNonStreaming(w, body)
}

func (m *Anthropic) serveNonStreaming(w http.ResponseWriter, body map[string]any) {
	if m.NonStreaming == nil {
		http.Error(w, "mock: no NonStreaming response configured", http.StatusInternalServerError)
		return
	}
	c := m.NonStreaming
	model, _ := body["model"].(string)

	resp := map[string]any{
		"id":            c.ID,
		"type":          "message",
		"role":          "assistant",
		"model":         model,
		"content":       []map[string]any{{"type": "text", "text": c.Content}},
		"stop_reason":   "end_turn",
		"stop_sequence": nil,
		"usage": map[string]any{
			"input_tokens":                c.Usage.InputTokens,
			"output_tokens":               c.Usage.OutputTokens,
			"cache_read_input_tokens":     c.Usage.CacheReadInputTokens,
			"cache_creation_input_tokens": c.Usage.CacheCreationInputTokens,
		},
	}
	enc, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(enc)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(enc)
}

func (m *Anthropic) serveStream(w http.ResponseWriter, body map[string]any) {
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

	id := fmt.Sprintf("msg_mock_%d", time.Now().UnixNano())

	writeEvent := func(event string, data map[string]any) {
		enc, _ := json.Marshal(data)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, enc)
		flusher.Flush()
	}

	time.Sleep(s.TTFT)
	writeEvent("message_start", map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"id":            id,
			"type":          "message",
			"role":          "assistant",
			"model":         model,
			"content":       []any{},
			"stop_reason":   nil,
			"stop_sequence": nil,
			"usage": map[string]any{
				"input_tokens":                s.Usage.InputTokens,
				"cache_read_input_tokens":     s.Usage.CacheReadInputTokens,
				"cache_creation_input_tokens": s.Usage.CacheCreationInputTokens,
				"output_tokens":               0,
			},
		},
	})

	writeEvent("content_block_start", map[string]any{
		"type":          "content_block_start",
		"index":         0,
		"content_block": map[string]any{"type": "text", "text": ""},
	})

	for i, tok := range s.Chunks {
		if i > 0 {
			time.Sleep(s.InterChunkDelay)
		}
		writeEvent("content_block_delta", map[string]any{
			"type":  "content_block_delta",
			"index": 0,
			"delta": map[string]any{"type": "text_delta", "text": tok},
		})
	}

	writeEvent("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})

	writeEvent("message_delta", map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil},
		"usage": map[string]any{"output_tokens": s.Usage.OutputTokens},
	})

	writeEvent("message_stop", map[string]any{"type": "message_stop"})
}
