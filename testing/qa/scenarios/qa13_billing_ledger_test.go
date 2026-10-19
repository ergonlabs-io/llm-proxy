package scenarios

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/vigneshaigal/llm-proxy/testing/qa/harness"
	"github.com/vigneshaigal/llm-proxy/testing/qa/mocks"
)

// QA-13: the billing ledger (ADR-0009) as a consumer and an operator see it,
// through the real binary's listener and admin API only.
//
// crates/proxy/tests/ledger_e2e.rs already proves, against the binary: a
// SIGTERM restart opens a later epoch, startup refusals, the reload refusal,
// one read+ack page after which nothing is returned, and the reconciliation
// counters under load and under `admit` with every slot held (queue_full).
// These cases add what it never switches on: a SIGKILL under load, redelivery
// of unacknowledged entries, and the disk cap in both on_unavailable modes.

const (
	qa13Node       = "qa13-stable-node"
	qa13AdminToken = "qa13-admin-token"
	// The schema's floor for max_disk_bytes; small enough to reach quickly.
	qa13MinDiskBytes = 2 * 1024 * 1024
)

type qa13Entry struct {
	Cursor     uint64 `json:"cursor"`
	InstanceID string `json:"instance_id"`
	Epoch      uint64 `json:"epoch"`
	Seq        uint64 `json:"seq"`
	Record     struct {
		EventID string `json:"event_id"`
	} `json:"record"`
}

type qa13Page struct {
	Entries          []qa13Entry `json:"entries"`
	NextAfter        uint64      `json:"next_after"`
	CommittedThrough uint64      `json:"committed_through"`
	Epochs           []qa13Epoch `json:"epochs"`
}

type qa13Epoch struct {
	Epoch  uint64 `json:"epoch"`
	Closed bool   `json:"closed"`
}

// epochs returns the ledger's recent epochs as the read API reports them,
// oldest first; the last is the running one.
func (p *qa13Proxy) epochs() []qa13Epoch {
	p.t.Helper()
	var page qa13Page
	p.adminCall("GET", "/ledger/entries?after=0&limit=1", &page)
	return page.Epochs
}

type qa13Ack struct {
	AcknowledgedThrough uint64 `json:"acknowledged_through"`
	Admitting           bool   `json:"admitting"`
}

type qa13Proxy struct {
	t        *testing.T
	proc     *harness.Proxy
	listen   string
	admin    string
	client   *http.Client
	upstream *mocks.OpenAI
}

// qa13Setup writes a dialect config with a ledger in a fresh directory and
// returns a function that starts the proxy on it. Restarts reuse the same
// config, so the same ledger directory, key and node id.
func qa13Setup(t *testing.T, onUnavailable string, maxDiskBytes int) func() *qa13Proxy {
	t.Helper()
	upstream := mocks.NewOpenAI()
	t.Cleanup(upstream.Close)
	upstream.NonStreaming = &mocks.ChatCompletion{
		ID: "qa13", Content: "ok",
		Usage: mocks.Usage{PromptTokens: 6, CompletionTokens: 4, TotalTokens: 10},
	}

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
providers:
  openai:
    type: openai
    base_url: %s
    api_key: sk-qa13-provider-key
routes:
  - { model: "*", provider: openai }
ledger:
  directory: %s
  encryption_key_file: %s
  encryption_key_id: qa13-key
  max_disk_bytes: %d
  group_commit_interval: 10ms
  on_unavailable: %s
`, listen, admin, upstream.URL(), filepath.Join(dir, "ledger"), keyFile, maxDiskBytes, onUnavailable)
	path := harness.WriteConfig(t, "llmproxy.yaml", config)
	t.Setenv("LLMPROXY_ADMIN_TOKEN", qa13AdminToken)

	return func() *qa13Proxy {
		proc := harness.Start(t, harness.StartOpts{
			ConfigPath: path,
			ExtraArgs:  []string{"--service-node", qa13Node, "--drain-time-s", "1"},
		})
		proc.WaitReady(admin, 10*time.Second)
		proc.WaitReady(listen, 10*time.Second)
		return &qa13Proxy{
			t: t, proc: proc, listen: listen, admin: admin, upstream: upstream,
			client: &http.Client{Timeout: 10 * time.Second},
		}
	}
}

// chat sends one chat completion and returns the status and body. A
// transport error is status 0, so a caller racing a SIGKILL can tell it
// apart from an answer.
func (p *qa13Proxy) chat() (int, string) {
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	resp, err := p.client.Post("http://"+p.listen+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (p *qa13Proxy) adminCall(method, path string, out any) {
	p.t.Helper()
	if status, body := p.adminTry(method, path, out); status != http.StatusOK {
		p.t.Fatalf("%s %s: status %d: %s", method, path, status, body)
	}
}

// adminTry is adminCall for a caller that handles a non-200 answer itself;
// out is filled only on a 200.
func (p *qa13Proxy) adminTry(method, path string, out any) (int, string) {
	p.t.Helper()
	req, err := http.NewRequest(method, "http://"+p.admin+path, nil)
	if err != nil {
		p.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+qa13AdminToken)
	resp, err := p.client.Do(req)
	if err != nil {
		p.t.Fatalf("%s %s: %v\n--- proxy log ---\n%s", method, path, err, p.proc.Log())
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, string(b)
	}
	if err := json.Unmarshal(b, out); err != nil {
		p.t.Fatalf("%s %s: %v: %s", method, path, err, b)
	}
	return resp.StatusCode, string(b)
}

// readAll pages GET /ledger/entries from the start until a page comes back
// empty, without acknowledging anything.
func (p *qa13Proxy) readAll() ([]qa13Entry, uint64) {
	p.t.Helper()
	var all []qa13Entry
	after := uint64(0)
	for range 1000 {
		var page qa13Page
		p.adminCall("GET", fmt.Sprintf("/ledger/entries?after=%d&limit=1000", after), &page)
		if len(page.Entries) == 0 {
			return all, after
		}
		all = append(all, page.Entries...)
		after = page.NextAfter
	}
	p.t.Fatal("ledger never ran out of entries")
	return nil, 0
}

// drain is the consumer loop: read everything, acknowledge through the last
// cursor, and repeat until an acknowledgement says admission is open again.
// Every acknowledgement covers the whole range read, and at the cap it must
// still succeed: the spool keeps a reserve for acknowledgements. One
// acknowledgement can free less than the entries held at the cap need, so a
// consumer keeps acknowledging until `admitting` is true.
func (p *qa13Proxy) drain() []qa13Entry {
	p.t.Helper()
	var all []qa13Entry
	acked := uint64(0)
	for range 50 {
		entries, _ := p.readAll()
		var fresh []qa13Entry
		for _, e := range entries {
			if e.Cursor > acked {
				fresh = append(fresh, e)
			}
		}
		all = append(all, fresh...)
		// With nothing new to read, repeat the last acknowledgement: the
		// documented loop acknowledges until `admitting` is true, and a
		// repeat retries a reserve the previous one could not put back.
		through := acked
		if len(entries) > 0 {
			through = entries[len(entries)-1].Cursor
		}
		var ack qa13Ack
		status, body := p.adminTry("POST", fmt.Sprintf("/ledger/ack?through=%d", through), &ack)
		if status != http.StatusOK || ack.AcknowledgedThrough != through {
			p.t.Fatalf("full-range ack through=%d: status %d: %s\n--- proxy log ---\n%s", through, status, body, p.proc.Log())
		}
		acked = through
		if ack.Admitting {
			return all
		}
		// The writer writes the held entries after the ack; let them commit.
		time.Sleep(50 * time.Millisecond)
	}
	p.t.Fatalf("ledger never resumed admitting\n--- proxy log ---\n%s", p.proc.Log())
	return nil
}

// metric sums every series of name in /stats/prometheus whose line contains
// label (empty: every series). The scrape prefixes stat names with `envoy_`.
func (p *qa13Proxy) metric(name, label string) uint64 {
	p.t.Helper()
	resp, err := p.client.Get("http://" + p.admin + "/stats/prometheus")
	if err != nil {
		p.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var sum uint64
	found := false
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		series := fields[0]
		if series != "envoy_"+name && !strings.HasPrefix(series, "envoy_"+name+"{") {
			continue
		}
		if !strings.Contains(series, label) {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			p.t.Fatalf("series %s: %v", line, err)
		}
		sum += v
		found = true
	}
	if !found {
		p.t.Fatalf("no series envoy_%s%s in scrape:\n%s", name, label, b)
	}
	return sum
}

// waitMetric polls until metric(name, label) == want.
func (p *qa13Proxy) waitMetric(name, label string, want uint64) {
	p.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		got := p.metric(name, label)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			p.t.Fatalf("%s%s = %d, want %d\n--- proxy log ---\n%s", name, label, got, want, p.proc.Log())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestQA13_LedgerSurvivesSigkillAndRedeliversUntilAcked: what a consumer sees
// across a crash. Every entry read before a SIGKILL under load is still there
// after the restart (a read returns only committed entries, and committed
// means durable), it is returned again because it was never acknowledged
// (at-least-once), the killed epoch is a gapless prefix from seq 0, and the
// restart opens a later epoch. `seq` cannot show entries lost from the end
// of the killed epoch, so the restart reports that epoch as not closed, in
// the read API, a counter and the log. One acknowledgement then removes both
// epochs, and after a clean stop the next start reports nothing unclean.
func TestQA13_LedgerSurvivesSigkillAndRedeliversUntilAcked(t *testing.T) {
	start := qa13Setup(t, "reject", 64*1024*1024)
	p := start()

	var served atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// A failure here is the SIGKILL landing mid-request.
				if status, _ := p.chat(); status == http.StatusOK {
					served.Add(1)
				}
			}
		}()
	}
	for served.Load() < 50 {
		time.Sleep(10 * time.Millisecond)
	}

	// A consumer reads but has not acknowledged yet. A second read from the
	// start returns the same entries: reading does not consume.
	before, _ := p.readAll()
	again, _ := p.readAll()
	if len(before) == 0 || len(again) < len(before) {
		t.Fatalf("read %d entries, then %d", len(before), len(again))
	}
	for i := range before {
		if again[i].Record.EventID != before[i].Record.EventID {
			t.Fatalf("re-read entry %d is %+v, was %+v", i, again[i], before[i])
		}
	}
	epoch := before[0].Epoch

	// Kill with requests still in flight; nothing gets to commit on the way out.
	time.Sleep(100 * time.Millisecond)
	p.proc.Signal(syscall.SIGKILL)
	p.proc.Wait(10 * time.Second)
	close(stop)
	wg.Wait()
	servedBeforeKill := uint64(served.Load())

	p = start()
	if got := p.metric("llmproxy_ledger_unclean_epochs_total", ""); got != 1 {
		t.Fatalf("llmproxy_ledger_unclean_epochs_total = %d after SIGKILL, want 1", got)
	}
	if !strings.Contains(p.proc.Log(), "the previous epoch did not close") {
		t.Fatalf("no unclean-epoch error in the log:\n%s", p.proc.Log())
	}
	if e := p.epochs(); len(e) != 2 || e[0] != (qa13Epoch{Epoch: epoch, Closed: false}) || e[1].Closed {
		t.Fatalf("epochs after SIGKILL of %d: %+v", epoch, e)
	}
	after, _ := p.readAll()
	present := map[string]bool{}
	var killed []qa13Entry
	for _, e := range after {
		present[e.Record.EventID] = true
		if e.InstanceID != qa13Node {
			t.Fatalf("entry %+v: instance_id is not the node id %s", e, qa13Node)
		}
		if e.Epoch == epoch {
			killed = append(killed, e)
		}
	}
	for _, e := range before {
		if !present[e.Record.EventID] {
			t.Fatalf("entry %+v was read as committed before SIGKILL and is gone after restart", e)
		}
	}
	for i, e := range killed {
		if e.Seq != uint64(i) {
			t.Fatalf("killed epoch %d is not gapless from 0: position %d has seq %d", epoch, i, e.Seq)
		}
	}
	if uint64(len(killed)) > servedBeforeKill {
		t.Fatalf("killed epoch holds %d entries for %d served requests", len(killed), servedBeforeKill)
	}
	t.Logf("served %d before SIGKILL; %d committed in epoch %d; %d were read before the kill",
		servedBeforeKill, len(killed), epoch, len(before))

	if status, body := p.chat(); status != http.StatusOK {
		t.Fatalf("after restart: %d %s", status, body)
	}
	p.waitMetric("llmproxy_ledger_entries_committed_total", "", 1)
	all := p.drain()
	last := all[len(all)-1]
	if last.Epoch <= epoch || last.Seq != 0 {
		t.Fatalf("the restart's first entry is %+v; want seq 0 in an epoch after %d", last, epoch)
	}
	if rest, _ := p.readAll(); len(rest) != 0 {
		t.Fatalf("%d entries returned after acknowledging through the last cursor", len(rest))
	}

	// A clean stop closes its epoch, even with every entry acknowledged.
	p.proc.Signal(syscall.SIGTERM)
	p.proc.Wait(10 * time.Second)
	p = start()
	if got := p.metric("llmproxy_ledger_unclean_epochs_total", ""); got != 0 {
		t.Fatalf("llmproxy_ledger_unclean_epochs_total = %d after a clean stop, want 0", got)
	}
	e := p.epochs()
	if len(e) != 3 || e[0].Closed || e[1] != (qa13Epoch{Epoch: last.Epoch, Closed: true}) || e[2].Closed {
		t.Fatalf("epochs after a clean stop of %d: %+v", last.Epoch, e)
	}
}

// fillToCap sends requests from several goroutines until one is refused or
// the admit-mode counter rises, and returns how many were served and
// refused. Under `reject` every refusal must be the disk-cap 503.
func qa13FillToCap(t *testing.T, p *qa13Proxy, capped func() bool) (served, refused uint64) {
	t.Helper()
	var ok, no atomic.Uint64
	var bad atomic.Value
	var done atomic.Bool
	var wg sync.WaitGroup
	deadline := time.Now().Add(120 * time.Second)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !done.Load() && time.Now().Before(deadline) {
				switch status, body := p.chat(); status {
				case http.StatusOK:
					ok.Add(1)
				case http.StatusServiceUnavailable:
					no.Add(1)
					if body != "billing ledger unavailable: disk_full\n" {
						bad.Store(body)
					}
					done.Store(true)
				default:
					bad.Store(fmt.Sprintf("%d %s", status, body))
					done.Store(true)
				}
			}
		}()
	}
	for !done.Load() && time.Now().Before(deadline) {
		if capped() {
			done.Store(true)
		}
		time.Sleep(20 * time.Millisecond)
	}
	done.Store(true)
	wg.Wait()
	if b := bad.Load(); b != nil {
		t.Fatalf("unexpected answer while filling the ledger: %q", b)
	}
	if !capped() && no.Load() == 0 {
		t.Fatalf("never reached the disk cap after %d requests", ok.Load())
	}
	return ok.Load(), no.Load()
}

// TestQA13_RejectAtDiskCapRecoversAfterAck: with the default
// `on_unavailable: reject`, a ledger at max_disk_bytes turns requests into a
// local 503 naming disk_full, and none of them reaches the provider. The
// consumer acknowledging frees space, admission resumes without a restart,
// and every request that was served while the cap was being reached ends up
// committed: none of the entries held at the cap is lost.
func TestQA13_RejectAtDiskCapRecoversAfterAck(t *testing.T) {
	p := qa13Setup(t, "reject", qa13MinDiskBytes)()
	served, _ := qa13FillToCap(t, p, func() bool { return false })

	// The cap holds: a fresh request is refused too, before dialling.
	dialled := len(p.upstream.Requests())
	status, body := p.chat()
	if status != http.StatusServiceUnavailable || body != "billing ledger unavailable: disk_full\n" {
		t.Fatalf("at the cap: %d %q", status, body)
	}
	if got := len(p.upstream.Requests()); got != dialled {
		t.Fatalf("a refused request reached the provider (%d -> %d dials)", dialled, got)
	}
	if uint64(dialled) != served {
		t.Fatalf("provider saw %d requests, proxy served %d", dialled, served)
	}
	refused := p.metric("llmproxy_ledger_rejected_total", `reason="disk_full"`)
	if refused == 0 {
		t.Fatal("llmproxy_ledger_rejected_total{reason=\"disk_full\"} did not count the refusals")
	}

	entries := p.drain()
	if status, body := p.chat(); status != http.StatusOK {
		t.Fatalf("after acknowledging: %d %q\n--- proxy log ---\n%s", status, body, p.proc.Log())
	}
	p.waitMetric("llmproxy_ledger_entries_committed_total", "", served+1)
	if uint64(len(entries)) > served {
		t.Fatalf("consumer read %d entries for %d served requests", len(entries), served)
	}
	if lost := p.metric("llmproxy_ledger_entries_lost_total", ""); lost != 0 {
		t.Fatalf("%d entries lost at the disk cap", lost)
	}
	t.Logf("served %d, refused %d at the cap; consumer drained %d", served, refused, len(entries))
}

// TestQA13_AdmitAtDiskCapServesUnledgered: the fail-open mode at the disk
// cap. Every request is served and dialled; the ones with no ledger capacity
// are counted under reason disk_full and warned about. After the consumer
// acknowledges, committed plus unledgered accounts for every request.
func TestQA13_AdmitAtDiskCapServesUnledgered(t *testing.T) {
	p := qa13Setup(t, "admit", qa13MinDiskBytes)()
	capped := func() bool {
		return p.metric("llmproxy_ledger_unledgered_total", `reason="disk_full"`) >= 20
	}
	served, refused := qa13FillToCap(t, p, capped)
	if refused != 0 {
		t.Fatalf("admit mode refused %d requests", refused)
	}
	if got := len(p.upstream.Requests()); uint64(got) != served {
		t.Fatalf("provider saw %d requests, proxy served %d", got, served)
	}
	if !strings.Contains(p.proc.Log(), "request served without a ledger entry (on_unavailable: admit)") {
		t.Fatalf("no unledgered warning in the log:\n%s", p.proc.Log())
	}

	p.drain()
	unledgered := p.metric("llmproxy_ledger_unledgered_total", `reason="disk_full"`)
	p.waitMetric("llmproxy_ledger_entries_committed_total", "", served-unledgered)
	if lost := p.metric("llmproxy_ledger_entries_lost_total", ""); lost != 0 {
		t.Fatalf("%d entries lost at the disk cap", lost)
	}
	t.Logf("served %d; %d unledgered at the cap", served, unledgered)
}
