package scenarios

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vigneshaigal/llm-proxy/testing/qa/harness"
)

// QA-2: a bad config fails at load, names the offending field, and exits
// nonzero (SCENARIOS.md — ground rule #1: silently ignoring a config field
// is a P0; strict mode's error quality is the whole product claim).
//
// This asserts on the FULL DOTTED FIELD PATH appearing in stderr, not merely
// that the process failed — "it failed" would pass even with a useless
// message like "invalid config".
func TestQA2_BadConfigFailsWithFieldPath(t *testing.T) {
	cfg := `
version: 0
listen: 127.0.0.1:18080
providers:
  openai:
    api_key: sk-test
routes:
  - model: "*"
    provider: openai
    this_field_does_not_exist: true
`
	configPath := harness.WriteConfig(t, "bad.yaml", cfg)

	result := harness.Run(t, []string{"--config", configPath, "--mode", "validate"}, 10*time.Second)

	if result.ExitCode == 0 {
		t.Fatalf("QA-2: expected nonzero exit for an invalid config, got 0\n--- output ---\n%s", result.Output)
	}

	// The offending field, as a full dotted path: `routes[0].this_field_does_not_exist`.
	const wantPath = "routes[0].this_field_does_not_exist"
	if !strings.Contains(result.Output, wantPath) {
		t.Fatalf(
			"QA-2: expected output to name the full dotted field path %q, got:\n%s",
			wantPath, result.Output,
		)
	}
}

// QA-2 (serve mode): the same bad config, run without --mode validate, must
// fail the same way and must not bind a listener — a strict-mode rejection
// has to happen before any socket work, in both entry points.
func TestQA2_BadConfigFailsInServeModeToo(t *testing.T) {
	port := harness.FreePort(t)
	cfg := `
version: 0
listen: 127.0.0.1:` + strconv.Itoa(port) + `
providers:
  openai:
    api_key: sk-test
routes:
  - model: "*"
    provider: openai
    this_field_does_not_exist: true
`
	configPath := harness.WriteConfig(t, "bad.yaml", cfg)

	result := harness.Run(t, []string{"--config", configPath}, 10*time.Second)

	if result.ExitCode == 0 {
		t.Fatalf("QA-2: expected nonzero exit for an invalid config in serve mode, got 0\n--- output ---\n%s", result.Output)
	}
	const wantPath = "routes[0].this_field_does_not_exist"
	if !strings.Contains(result.Output, wantPath) {
		t.Fatalf(
			"QA-2: expected output to name the full dotted field path %q, got:\n%s",
			wantPath, result.Output,
		)
	}
}
