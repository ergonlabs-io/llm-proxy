package harness

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// ReadAccessLogLines reads path and parses each non-empty line as one JSON
// object — the JSON access-log format emits one object per line. It fails
// the test (with the offending line attached) on the first line that isn't
// valid JSON.
func ReadAccessLogLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("harness: open access log %s: %v", path, err)
	}
	defer f.Close()

	var lines []map[string]any
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("harness: access log line is not valid JSON: %v\nline: %s", err, line)
		}
		lines = append(lines, obj)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("harness: scan access log %s: %v", path, err)
	}
	return lines
}

// WaitForAccessLogLines polls path until it contains at least n parsed
// lines, or fails the test once timeout elapses.
//
// The access log is flushed at stream end, not necessarily the instant an
// HTTP response finishes on the client side, so a test that reads
// immediately after its request returns can race the write. This absorbs
// that race so scenario tests don't need their own retry loops or sleeps.
func WaitForAccessLogLines(t *testing.T, path string, n int, timeout time.Duration) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lines []map[string]any
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			lines = ReadAccessLogLines(t, path)
			if len(lines) >= n {
				return lines
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("harness: access log %s did not reach %d line(s) within %s (got %d)", path, n, timeout, len(lines))
	return nil
}

// WaitForFile polls for path to exist, returning true once it does or false
// once timeout elapses without failing the test — for callers (like QA-1)
// that need to distinguish "not there yet" from "will never appear" without
// treating the latter as a hard test failure.
func WaitForFile(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	_, err := os.Stat(path)
	return err == nil
}
