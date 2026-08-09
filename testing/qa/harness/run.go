package harness

import (
	"os/exec"
	"sync"
	"testing"
	"time"
)

// RunResult is the outcome of a one-shot llm-proxy invocation that is
// expected to exit on its own (config validation, `--mode translate`, etc.)
// rather than run as a long-lived server.
type RunResult struct {
	ExitCode int
	Output   string // combined stdout+stderr
}

// Run executes the llm-proxy binary with args, waits up to timeout for it to
// exit, and returns its exit code and combined stdout+stderr. It fails the
// test (with the captured output attached) if the process does not exit
// within timeout — for a case like QA-2, a config that should fail loudly at
// load time hanging instead is itself a bug worth surfacing loudly, not
// silently swallowing.
func Run(t *testing.T, args []string, timeout time.Duration) RunResult {
	t.Helper()
	bin, err := BinaryPath()
	if err != nil {
		t.Fatalf("harness: %v", err)
	}

	cmd := exec.Command(bin, args...)
	var combined outputBuffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined

	if err := cmd.Start(); err != nil {
		t.Fatalf("harness: start %s %v: %v", bin, args, err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case waitErr := <-done:
		exitCode := 0
		if waitErr != nil {
			if exitErr, ok := waitErr.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = -1
			}
		}
		return RunResult{ExitCode: exitCode, Output: combined.String()}
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf(
			"harness: %s %v did not exit within %s\n--- output ---\n%s",
			bin, args, timeout, combined.String(),
		)
		return RunResult{}
	}
}

// outputBuffer is a tiny concurrency-safe io.Writer sink. The os/exec
// package copies a child's stdout and stderr on two separate internal
// goroutines when both are plain io.Writers (not the same *os.File), so a
// plain bytes.Buffer — not safe for concurrent use — isn't enough here even
// though only one process is involved.
type outputBuffer struct {
	mu   sync.Mutex
	data []byte
}

func (b *outputBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *outputBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.data)
}
