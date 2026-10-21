package scenarios

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vigneshaigal/llm-proxy/testing/qa/harness"
)

// QA-21: a realtime (WebSocket) session under a tenant spend budget
// (ADR-0015), as a tenant and a billing consumer see it, through the real
// binary's listener and admin API only.
//
// A session is admitted at upgrade time and charged, once, the usage its
// `response.done` events reported, at the audio rates of the provider
// dialled; its ledger entry says what was bought. A session cut mid-response
// is recorded partial and charged once for what was reported. An upgrade
// without credentials never reaches the provider, the session over a
// concurrent-session limit is refused with 429, and drain closes an open
// session with code 1001.

const (
	qa21AdminToken = "qa21-admin-token"
	qa21Node       = "qa21-node"
	qa21Model      = "gpt-realtime-qa21"
	// The mock's usage per response: 10 input tokens (6 audio), 5 output
	// tokens (3 audio). At the example rates below that is
	// 4*1000 + 6*4000 + 2*2000 + 3*8000 = 56000 nanodollars, 56 micro-USD.
	qa21Done         = `{"type":"response.done","response":{"status":"completed","usage":{"total_tokens":15,"input_tokens":10,"output_tokens":5,"input_token_details":{"text_tokens":4,"audio_tokens":6},"output_token_details":{"text_tokens":2,"audio_tokens":3}}}}`
	qa21DoneMicroUSD = 56
)

// qa21Upstream is a minimal realtime provider. It answers each client text
// frame with `response.created` and `response.done`, except the text
// "cut", which gets only `response.created`; it answers a Close with a
// Close. It counts the upgrades it accepted.
type qa21Upstream struct {
	addr  string
	mu    sync.Mutex
	heads []string
}

func qa21StartUpstream(t *testing.T) *qa21Upstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	u := &qa21Upstream{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go u.serve(conn)
		}
	}()
	return u
}

func (u *qa21Upstream) serve(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	head, err := qa21ReadHead(r)
	if err != nil {
		return
	}
	u.mu.Lock()
	u.heads = append(u.heads, strings.ToLower(head))
	u.mu.Unlock()
	fmt.Fprint(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
	conn.Write(qa21Frame(0x1, []byte(`{"type":"session.created","session":{}}`), false))
	for {
		opcode, payload, err := qa21ReadFrame(r)
		if err != nil {
			return
		}
		switch opcode {
		case 0x1:
			out := qa21Frame(0x1, []byte(`{"type":"response.created"}`), false)
			if string(payload) != "cut" {
				out = append(out, qa21Frame(0x1, []byte(qa21Done), false)...)
			}
			conn.Write(out)
		case 0x8:
			conn.Write(qa21Frame(0x8, []byte{0x03, 0xe8}, false))
			return
		}
	}
}

func (u *qa21Upstream) dialled() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.heads)
}

func qa21ReadHead(r *bufio.Reader) (string, error) {
	var b strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return b.String(), err
		}
		b.WriteString(line)
		if line == "\r\n" {
			return b.String(), nil
		}
	}
}

// qa21Frame builds one final frame; a client frame is masked (RFC 6455
// section 5.3).
func qa21Frame(opcode byte, payload []byte, masked bool) []byte {
	out := []byte{0x80 | opcode}
	var maskBit byte
	if masked {
		maskBit = 0x80
	}
	switch {
	case len(payload) < 126:
		out = append(out, maskBit|byte(len(payload)))
	default:
		out = append(out, maskBit|126)
		out = binary.BigEndian.AppendUint16(out, uint16(len(payload)))
	}
	if !masked {
		return append(out, payload...)
	}
	mask := []byte{0x5a, 0x11, 0xc3, 0x07}
	out = append(out, mask...)
	for i, b := range payload {
		out = append(out, b^mask[i%4])
	}
	return out
}

func qa21ReadFrame(r io.Reader) (byte, []byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err
	}
	length := uint64(head[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	var mask []byte
	if head[1]&0x80 != 0 {
		mask = make([]byte, 4)
		if _, err := io.ReadFull(r, mask); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	for i := range payload {
		if mask != nil {
			payload[i] ^= mask[i%4]
		}
	}
	return head[0] & 0x0f, payload, nil
}

// qa21Session is a client session through the proxy.
type qa21Session struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

// qa21Open sends the upgrade and returns the session, or the refusal's
// status line.
func qa21Open(t *testing.T, listen, key string) (*qa21Session, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", listen, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	auth := ""
	if key != "" {
		auth = "Authorization: Bearer " + key + "\r\n"
	}
	fmt.Fprintf(conn, "GET /v1/realtime?model=%s HTTP/1.1\r\nHost: proxy.local\r\n%s"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
		"Sec-WebSocket-Version: 13\r\n\r\n", qa21Model, auth)
	r := bufio.NewReader(conn)
	head, err := qa21ReadHead(r)
	if err != nil {
		conn.Close()
		t.Fatalf("reading the upgrade response: %v (%q)", err, head)
	}
	status := strings.SplitN(head, "\r\n", 2)[0]
	if !strings.HasPrefix(status, "HTTP/1.1 101") {
		conn.Close()
		return nil, status
	}
	t.Cleanup(func() { conn.Close() })
	return &qa21Session{t: t, conn: conn, r: r}, status
}

func (s *qa21Session) event() string {
	s.t.Helper()
	opcode, payload, err := qa21ReadFrame(s.r)
	if err != nil || opcode != 0x1 {
		s.t.Fatalf("expected a text event, got opcode %d, err %v", opcode, err)
	}
	var event struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		s.t.Fatalf("event %q: %v", payload, err)
	}
	return event.Type
}

func (s *qa21Session) send(text string) {
	s.conn.Write(qa21Frame(0x1, []byte(text), true))
}

// respond asks for one response and reads it through to `response.done`.
func (s *qa21Session) respond() {
	s.t.Helper()
	s.send(`{"type":"response.create"}`)
	for _, want := range []string{"response.created", "response.done"} {
		if got := s.event(); got != want {
			s.t.Fatalf("event %q, want %q", got, want)
		}
	}
}

// close runs the client's side of the closing handshake to the end.
func (s *qa21Session) close(code uint16) {
	s.conn.Write(qa21Frame(0x8, binary.BigEndian.AppendUint16(nil, code), true))
	io.Copy(io.Discard, s.r)
	s.conn.Close()
}

type qa21Entry struct {
	ChargedMicroUSD uint64 `json:"charged_micro_usd"`
	ChargedScopes   []struct {
		Scope string `json:"scope"`
	} `json:"charged_scopes"`
	Record struct {
		Endpoint      string `json:"endpoint"`
		Status        uint16 `json:"status"`
		SelectedModel string `json:"selected_model"`
		Usage         struct {
			InputTokens       uint64  `json:"input_tokens"`
			OutputTokens      uint64  `json:"output_tokens"`
			InputAudioTokens  *uint64 `json:"input_audio_tokens"`
			OutputAudioTokens *uint64 `json:"output_audio_tokens"`
			Completeness      string  `json:"completeness"`
		} `json:"usage"`
	} `json:"record"`
}

type qa21Proxy struct {
	t      *testing.T
	proc   *harness.Proxy
	listen string
	admin  string
	client *http.Client
}

func qa21Start(t *testing.T, upstream string) *qa21Proxy {
	t.Helper()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "ledger.key")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		t.Fatal(err)
	}
	listen := fmt.Sprintf("127.0.0.1:%d", harness.FreePort(t))
	admin := fmt.Sprintf("127.0.0.1:%d", harness.FreePort(t))
	config := fmt.Sprintf(`version: 0
listen: %s
admin: %s
realtime: { enabled: true }
providers:
  openai:
    type: openai
    base_url: http://%s
    api_key: sk-qa21-provider-key
routes:
  - { model: "*", provider: openai }
auth:
  hmac_secret: "qa21-hmac-secret"
  enforce: { model_policy: false, object_ownership: false }
limits:
  - { key: global, concurrent_sessions: 1 }
pricing:
  price_list:
    version: qa21
    effective_from: "2026-01-01T00:00:00Z"
    entries:
      - provider_type: openai
        model: %s
        tier_mode: whole_request
        tiers:
          - input_nanodollars_per_token: 1000
            cached_input_nanodollars_per_token: 100
            cache_write_nanodollars_per_token: 1000
            output_nanodollars_per_token: 2000
            audio_input_nanodollars_per_token: 4000
            audio_output_nanodollars_per_token: 8000
ledger:
  directory: %s
  encryption_key_file: %s
  encryption_key_id: qa21-key
  max_disk_bytes: 67108864
  group_commit_interval: 10ms
  on_unavailable: reject
`, listen, admin, upstream, qa21Model, filepath.Join(dir, "ledger"), keyFile)
	path := harness.WriteConfig(t, "llmproxy.yaml", config)
	t.Setenv("LLMPROXY_ADMIN_TOKEN", qa21AdminToken)
	proc := harness.Start(t, harness.StartOpts{
		ConfigPath: path,
		ExtraArgs:  []string{"--service-node", qa21Node, "--drain-time-s", "30"},
	})
	proc.WaitReady(admin, 10*time.Second)
	proc.WaitReady(listen, 10*time.Second)
	return &qa21Proxy{t: t, proc: proc, listen: listen, admin: admin, client: &http.Client{Timeout: 30 * time.Second}}
}

func (p *qa21Proxy) adminCall(method, path, body string, want int) string {
	p.t.Helper()
	req, err := http.NewRequest(method, "http://"+p.admin+path, strings.NewReader(body))
	if err != nil {
		p.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+qa21AdminToken)
	resp, err := p.client.Do(req)
	if err != nil {
		p.t.Fatalf("%s %s: %v\n--- proxy log ---\n%s", method, path, err, p.proc.Log())
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		p.t.Fatalf("%s %s: status %d, want %d: %s", method, path, resp.StatusCode, want, b)
	}
	return string(b)
}

func (p *qa21Proxy) tenantKey() string {
	p.t.Helper()
	var minted struct {
		Key string `json:"key"`
	}
	resp := p.adminCall("POST", "/keys", `{"tenant":"t1","key_id":"qa21-key"}`, http.StatusCreated)
	if err := json.Unmarshal([]byte(resp), &minted); err != nil {
		p.t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", "http://"+p.admin+"/tenants", strings.NewReader(`{"tenant":"t1"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+qa21AdminToken)
	resp2, err := p.client.Do(req)
	if err != nil || resp2.StatusCode/100 != 2 {
		p.t.Fatalf("POST /tenants: %v %v", err, resp2)
	}
	resp2.Body.Close()
	return minted.Key
}

// entries polls the ledger until it holds want entries.
func (p *qa21Proxy) entries(want int) []qa21Entry {
	p.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var page struct {
			Entries []qa21Entry `json:"entries"`
		}
		resp := p.adminCall("GET", "/ledger/entries?after=0&limit=100", "", http.StatusOK)
		if err := json.Unmarshal([]byte(resp), &page); err != nil {
			p.t.Fatal(err)
		}
		if len(page.Entries) >= want {
			return page.Entries
		}
		if time.Now().After(deadline) {
			p.t.Fatalf("ledger holds %d entries, want %d: %s\n--- proxy log ---\n%s", len(page.Entries), want, resp, p.proc.Log())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestQA21_RealtimeSessionUnderABudgetIsChargedAndLedgered is the realtime-sessions
// acceptance through the real binary.
func TestQA21_RealtimeSessionUnderABudgetIsChargedAndLedgered(t *testing.T) {
	upstream := qa21StartUpstream(t)
	p := qa21Start(t, upstream.addr)
	key := p.tenantKey()
	p.adminCall("PUT", "/tenants/t1/budget", `{"budget":{"max_usd":"100","period":"daily"}}`, http.StatusNoContent)

	// The negative case first: no credentials, refused at upgrade time,
	// never dialled.
	if s, status := qa21Open(t, p.listen, ""); s != nil || !strings.HasPrefix(status, "HTTP/1.1 401") {
		t.Fatalf("an upgrade without credentials: %q", status)
	}
	if upstream.dialled() != 0 {
		t.Fatalf("a refused upgrade reached the provider")
	}

	// A session with two responses is charged both, once, at its close.
	s, status := qa21Open(t, p.listen, key)
	if s == nil {
		t.Fatalf("session refused: %q\n--- proxy log ---\n%s", status, p.proc.Log())
	}
	if got := s.event(); got != "session.created" {
		t.Fatalf("first event %q", got)
	}
	s.respond()
	s.respond()

	// The concurrent-session limit (1) refuses a second session while the
	// first is open, before it is dialled.
	if over, status := qa21Open(t, p.listen, key); over != nil || !strings.HasPrefix(status, "HTTP/1.1 429") {
		t.Fatalf("the session over the limit: %q", status)
	}
	if upstream.dialled() != 1 {
		t.Fatalf("the refused session reached the provider")
	}
	s.close(1000)

	entry := p.entries(1)[0]
	if entry.ChargedMicroUSD != 2*qa21DoneMicroUSD {
		t.Errorf("charged_micro_usd = %d, want %d", entry.ChargedMicroUSD, 2*qa21DoneMicroUSD)
	}
	tenantCharged := false
	for _, scope := range entry.ChargedScopes {
		tenantCharged = tenantCharged || scope.Scope == "tenant"
	}
	if !tenantCharged {
		t.Errorf("the tenant budget was not among the charged scopes: %+v", entry.ChargedScopes)
	}
	u := entry.Record.Usage
	if entry.Record.Endpoint != "realtime" || u.InputTokens != 20 || u.OutputTokens != 10 ||
		u.InputAudioTokens == nil || *u.InputAudioTokens != 12 ||
		u.OutputAudioTokens == nil || *u.OutputAudioTokens != 6 || u.Completeness != "complete" {
		t.Errorf("the entry does not say what was bought: %+v", entry.Record)
	}

	// A session cut mid-response is partial and charged once, for the one
	// response it reported. The limit's slot was freed by the close above.
	cut, status := qa21WaitOpen(t, p.listen, key)
	if cut == nil {
		t.Fatalf("session after the first closed: %q", status)
	}
	cut.event()
	cut.respond()
	cut.send("cut")
	if got := cut.event(); got != "response.created" {
		t.Fatalf("event %q", got)
	}
	cut.conn.(*net.TCPConn).SetLinger(0)
	cut.conn.Close()
	cutEntry := p.entries(2)[1]
	if cutEntry.ChargedMicroUSD != qa21DoneMicroUSD || cutEntry.Record.Usage.Completeness != "partial" {
		t.Errorf("a cut session: charged %d micro-USD, completeness %q; want %d, partial",
			cutEntry.ChargedMicroUSD, cutEntry.Record.Usage.Completeness, qa21DoneMicroUSD)
	}

	// Drain closes an open session with 1001.
	open, status := qa21WaitOpen(t, p.listen, key)
	if open == nil {
		t.Fatalf("session before drain: %q", status)
	}
	open.event()
	p.proc.Signal(syscall.SIGTERM)
	opcode, payload, err := qa21ReadFrame(open.r)
	if err != nil || opcode != 0x8 || len(payload) < 2 || binary.BigEndian.Uint16(payload) != 1001 {
		t.Fatalf("on drain: opcode %d, payload %v, err %v; want Close 1001", opcode, payload, err)
	}
	open.close(1001)
}

// qa21WaitOpen opens a session, retrying while a just-closed session's
// limit slot is still being released.
func qa21WaitOpen(t *testing.T, listen, key string) (*qa21Session, string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		s, status := qa21Open(t, listen, key)
		if s != nil || !strings.HasPrefix(status, "HTTP/1.1 429") || time.Now().After(deadline) {
			return s, status
		}
		time.Sleep(50 * time.Millisecond)
	}
}
