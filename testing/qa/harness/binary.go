// Package harness provides the black-box test scaffolding shared by every QA
// scenario: resolving the built llm-proxy binary, spawning and tearing it
// down, writing per-test config files, allocating free ports, and reading
// back the access log it wrote. It has zero dependency on the Rust
// workspace — it knows only the built binary, files it writes, and network
// I/O, which is the whole point of the QA suite (see SCENARIOS.md).
package harness

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// RepoRoot returns the absolute path to the llm-proxy repository root.
//
// Rust note (for the repo owner): there's no Rust equivalent of this trick,
// so a word on how it works — runtime.Caller(0) returns the absolute path of
// *this source file* as recorded at compile time, regardless of the working
// directory `go test` is invoked from. This file lives at
// testing/qa/harness/binary.go, so the repo root is three directories up.
func RepoRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("harness: could not determine this source file's location")
	}
	// file: <root>/testing/qa/harness/binary.go
	harnessDir := filepath.Dir(file)
	root := filepath.Dir(filepath.Dir(filepath.Dir(harnessDir)))
	return root, nil
}

// BinaryPath resolves the llm-proxy binary under test.
//
// It reads LLM_PROXY_BIN if set (and requires that path to exist); otherwise
// it defaults to target/debug/llm-proxy relative to the repo root. This
// suite tests the built artifact, never the source — there is precedent for
// that mattering (a stale binary once silently passed a test the code
// failed), so this never falls back to `cargo run` on a miss. It fails with
// a clear, actionable message instead.
func BinaryPath() (string, error) {
	if p := os.Getenv("LLM_PROXY_BIN"); p != "" {
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("LLM_PROXY_BIN=%s does not exist: %w", p, err)
		}
		return p, nil
	}

	root, err := RepoRoot()
	if err != nil {
		return "", err
	}
	p := filepath.Join(root, "target", "debug", "llm-proxy")
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf(
			"llm-proxy binary not found at %s, and LLM_PROXY_BIN is not set.\n"+
				"Build it with: cargo build --bin llm-proxy\n"+
				"or point LLM_PROXY_BIN at an existing build", p)
	}
	return p, nil
}
