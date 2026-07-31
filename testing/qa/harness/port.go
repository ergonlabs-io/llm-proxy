package harness

import (
	"net"
	"testing"
)

// FreePort asks the OS for an unused TCP port on 127.0.0.1 by binding to
// port 0, reading back the assigned port, and releasing the listener.
//
// There is an inherent, unavoidable TOCTOU race between releasing this
// listener and the proxy binding the same port later — any "hand back a
// free port number" strategy has it, since the alternative (holding the
// socket open and passing it to the child process) isn't how the llm-proxy
// binary takes a listen address. Acceptable for a test suite that isn't
// running a huge parallel fleet.
func FreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("harness: allocate free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
