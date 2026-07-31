// Package mocks provides Go httptest-backed mock upstreams for OpenAI and
// Anthropic, fidelity-matched to each provider's real, documented request
// and response shapes. They exist so the QA suite can drive real proxy
// behavior (routing, streaming, credential injection, token extraction)
// without ever talking to a real provider or importing anything from the
// Rust workspace.
package mocks

import "net/http"

// RecordedRequest is one HTTP request a mock observed, captured in full —
// method, path, headers (including whatever the proxy itself injected, like
// credentials or x-request-id), and the parsed JSON body when present — so
// scenarios can assert on exactly what reached the "provider".
type RecordedRequest struct {
	Method  string
	Path    string
	Headers http.Header
	Body    map[string]any
}
