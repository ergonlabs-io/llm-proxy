package harness

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// StartOpts configures how a Proxy is spawned. Exactly one of ConfigPath
// (the `llmproxy` dialect, passed as `--config`) or BootstrapPath (an Envoy
// bootstrap, passed as `-c`) must be set.
type StartOpts struct {
	ConfigPath    string
	BootstrapPath string

	// ExtraArgs are appended verbatim after the config flag and the default
	// --concurrency 1 (e.g. []string{"--mode", "validate"}).
	ExtraArgs []string

	// Concurrency overrides the default of 1 worker. Most scenarios want the
	// default: with more than one worker, `SO_REUSEPORT`-style listener
	// fan-out means several sockets share the configured port, which is
	// fine for traffic but makes "the proxy is ready" a less crisp question
	// than a single accept()-ing socket. Only override this if a scenario is
	// specifically about worker concurrency.
	Concurrency int
}

// Proxy is a running (or exited) llm-proxy process under test.
type Proxy struct {
	Cmd     *exec.Cmd
	LogPath string

	t       *testing.T
	done    chan struct{}
	exitErr error
}

// Start spawns the llm-proxy binary against the given config, capturing
// combined stdout+stderr to a log file inside the test's temp dir, and
// registers a t.Cleanup that terminates the process. It does not wait for
// readiness — call WaitReady with the listener address once the config
// declares one.
func Start(t *testing.T, opts StartOpts) *Proxy {
	t.Helper()
	bin, err := BinaryPath()
	if err != nil {
		t.Fatalf("harness: %v", err)
	}

	var args []string
	switch {
	case opts.ConfigPath != "":
		args = append(args, "--config", opts.ConfigPath)
	case opts.BootstrapPath != "":
		args = append(args, "-c", opts.BootstrapPath)
	default:
		t.Fatalf("harness: StartOpts needs ConfigPath or BootstrapPath")
	}

	concurrency := opts.Concurrency
	if concurrency == 0 {
		concurrency = 1
	}
	args = append(args, "--concurrency", fmt.Sprintf("%d", concurrency))
	args = append(args, opts.ExtraArgs...)

	logPath := TempFilePath(t, "proxy.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("harness: create log file %s: %v", logPath, err)
	}

	cmd := exec.Command(bin, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatalf("harness: start %s %v: %v", bin, args, err)
	}

	p := &Proxy{
		Cmd:     cmd,
		LogPath: logPath,
		t:       t,
		done:    make(chan struct{}),
	}

	go func() {
		p.exitErr = cmd.Wait()
		close(p.done)
	}()

	t.Cleanup(func() {
		if cmd.Process == nil {
			logFile.Close()
			return
		}
		select {
		case <-p.done:
			// Already exited.
		default:
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-p.done:
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
				<-p.done
			}
		}
		logFile.Close()
	})

	return p
}

// hasExited reports whether the process has already exited, without
// blocking — used so WaitReady can fail fast (with the log attached) instead
// of spinning out its whole timeout when the process has already died.
func (p *Proxy) hasExited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// WaitReady polls a real TCP connect against addr until it succeeds or
// timeout elapses.
//
// Deliberately NOT implemented as "wait for a log line" — a log line like
// "listener bound" can be observed before the socket is actually
// accept()-ing connections, which caused a real bug in this project. On
// failure, the proxy's captured combined stdout+stderr log is included in
// the failure message: a QA failure with no proxy log attached is nearly
// impossible to debug.
func (p *Proxy) WaitReady(addr string, timeout time.Duration) {
	p.t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		lastErr = err
		if p.hasExited() {
			p.t.Fatalf(
				"harness: proxy exited before becoming ready on %s: %v\n--- proxy log (%s) ---\n%s",
				addr, lastErr, p.LogPath, p.Log(),
			)
		}
		time.Sleep(20 * time.Millisecond)
	}
	p.t.Fatalf(
		"harness: proxy never became ready on %s within %s: %v\n--- proxy log (%s) ---\n%s",
		addr, timeout, lastErr, p.LogPath, p.Log(),
	)
}

// Wait blocks until the process exits (or timeout elapses, in which case it
// fails the test) and returns its exit code.
func (p *Proxy) Wait(timeout time.Duration) int {
	p.t.Helper()
	select {
	case <-p.done:
	case <-time.After(timeout):
		p.t.Fatalf(
			"harness: proxy did not exit within %s\n--- proxy log (%s) ---\n%s",
			timeout, p.LogPath, p.Log(),
		)
	}
	if p.exitErr == nil {
		return 0
	}
	if exitErr, ok := p.exitErr.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return -1
}

// Log returns the proxy's captured combined stdout+stderr so far.
func (p *Proxy) Log() string {
	b, err := os.ReadFile(p.LogPath)
	if err != nil {
		return fmt.Sprintf("(could not read log: %v)", err)
	}
	return string(b)
}
