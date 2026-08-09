package harness

import (
	"os"
	"path/filepath"
	"testing"
)

// WriteConfig writes contents (a rendered YAML config) into a fresh per-test
// temp directory and returns its path. t.TempDir() is already cleaned up
// automatically when the test ends, so there is nothing extra to register.
func WriteConfig(t *testing.T, filename, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("harness: write config %s: %v", path, err)
	}
	return path
}

// TempFilePath returns a path inside a fresh per-test temp dir without
// creating the file — for outputs the proxy itself is expected to create,
// like an access-log file.
func TempFilePath(t *testing.T, filename string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), filename)
}
