package processor

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"k-guard/internal/alert"
	"k-guard/internal/config"
	kebpf "k-guard/internal/ebpf"
	"k-guard/internal/metrics"
	"k-guard/internal/safety"
)

// MockSink catches emitted alerts for inspection
type MockSink struct {
	mu     sync.Mutex
	alerts []alert.Alert
}

func (m *MockSink) Name() string { return "mock" }
func (m *MockSink) Send(a alert.Alert) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alerts = append(m.alerts, a)
}

func (m *MockSink) Alerts() []alert.Alert {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := make([]alert.Alert, len(m.alerts))
	copy(res, m.alerts)
	return res
}

func copyInt8(dst []int8, src string) {
	for i := 0; i < len(src) && i < len(dst); i++ {
		dst[i] = int8(src[i])
	}
}

func setupTestEngine(t *testing.T) (*Engine, *MockSink, *config.Manager) {
	t.Helper()

	cfgFile, err := os.CreateTemp("", "processor-cfg-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp config: %v", err)
	}

	t.Cleanup(func() {
		os.Remove(cfgFile.Name())
	})

	cfgData := `{
  "version": "1",
  "enforcement_enabled": false,
  "dedup_window_seconds": 5,
  "rules": [
    {
      "name": "detect-nc",
      "match": "basename",
      "pattern": "nc",
      "severity": "high",
      "action": "ALERT"
    },
    {
      "name": "kill-malware",
      "match": "exact_path",
      "pattern": "/tmp/malware",
      "severity": "critical",
      "action": "KILL"
    }
  ],
  "allowlist": [
    "/usr/bin/trusted"
  ]
}`

	if _, err := cfgFile.WriteString(cfgData); err != nil {
		t.Fatalf("failed to write mock config: %v", err)
	}
	cfgFile.Close()

	cfgMgr, err := config.NewManager(cfgFile.Name())
	if err != nil {
		t.Fatalf("failed to create config manager: %v", err)
	}

	guard := safety.NewGuard()
	disp := alert.NewDispatcher()
	mockSink := &MockSink{}
	disp.Register(mockSink)

	m := metrics.NewRegistry()
	eng := NewEngine(cfgMgr, guard, disp, m, nil, nil)

	return eng, mockSink, cfgMgr
}

func TestLRUCache(t *testing.T) {
	cache := newLRUCache[string, int](2)

	cache.Add("a", 1)
	cache.Add("b", 2)

	if v, ok := cache.Get("a"); !ok || v != 1 {
		t.Errorf("expected key 'a' to be 1, got %d (ok=%v)", v, ok)
	}

	cache.Add("c", 3)

	if _, ok := cache.Get("b"); ok {
		t.Errorf("expected key 'b' to be evicted")
	}
	if v, ok := cache.Get("c"); !ok || v != 3 {
		t.Errorf("expected key 'c' to be 3, got %d", v)
	}
}

func TestCorrelator(t *testing.T) {
	c := NewCorrelator(5 * time.Second)

	c.RecordExec(10, 1, "systemd", "/sbin/init")
	c.RecordExec(100, 10, "bash", "/bin/bash")
	c.RecordExec(200, 100, "malware", "/tmp/malware")

	tree := c.BuildTree(200)
	if len(tree) != 3 {
		t.Fatalf("expected 3 nodes in lineage tree, got %d", len(tree))
	}

	if tree[0].Pid != 200 || tree[1].Pid != 100 || tree[2].Pid != 10 {
		t.Errorf("unexpected tree structure: %+v", tree)
	}

	formatted := c.FormatTree(200)
	if formatted == "" {
		t.Errorf("expected non-empty formatted tree string")
	}
}

func TestDeduper(t *testing.T) {
	d := NewDeduper(50 * time.Millisecond)

	if !d.Allow("event1") {
		t.Errorf("first event should be allowed")
	}
	if d.Allow("event1") {
		t.Errorf("immediate duplicate should be suppressed")
	}

	time.Sleep(60 * time.Millisecond)

	if !d.Allow("event1") {
		t.Errorf("event should be allowed after dedup window expires")
	}
}

func TestEngine_AnalyzeExec(t *testing.T) {
	eng, sink, _ := setupTestEngine(t)

	// Allowlisted execution should generate no alerts
	eng.AnalyzeExec("trusted", "/usr/bin/trusted", 500, 1, 0, 0, 1, "", false, false, "", false, false)
	if len(sink.Alerts()) != 0 {
		t.Fatalf("expected 0 alerts for allowlisted executable, got %d", len(sink.Alerts()))
	}

	// Rule Match Alert action
	eng.AnalyzeExec("nc", "/usr/bin/nc", 501, 1, 1000, 1000, 1, "-e /bin/sh", false, false, "", false, false)
	alerts := waitForAlerts(sink, 1)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for nc execution, got %d", len(alerts))
	}
	if alerts[0].RuleName != "detect-nc" || alerts[0].Severity != string(config.SeverityHigh) {
		t.Errorf("unexpected alert details: %+v", alerts[0])
	}

	// Fileless Execution
	eng.AnalyzeExec("memfd_proc", "memfd:malware (deleted)", 502, 1, 0, 0, 1, "", false, false, "", false, true)
	alerts = waitForAlerts(sink, 2)
	if len(alerts) != 2 {
		t.Fatalf("expected 2 alerts total, got %d", len(alerts))
	}
	if alerts[1].EventType != "FILELESS_EXEC" {
		t.Errorf("expected FILELESS_EXEC event type, got %s", alerts[1].EventType)
	}
}

func TestRouter_ProcessRawRecord(t *testing.T) {
	eng, sink, cfgMgr := setupTestEngine(t)
	m := metrics.NewRegistry()
	router := NewRouter(eng, m, cfgMgr)

	hdr := kebpf.BPFEventHdr{
		EventType: uint32(kebpf.EventExec),
		Pid:       1234,
		Ppid:      1,
		Uid:       1000,
		Gid:       1000,
		CgroupId:  1,
	}
	copyInt8(hdr.Comm[:], "nc")

	execEvt := kebpf.BPFExecEvent{
		Hdr: hdr,
	}
	copyInt8(execEvt.Filename[:], "/usr/bin/nc")

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, execEvt); err != nil {
		t.Fatalf("failed to pack binary event: %v", err)
	}

	router.ProcessRawRecord(buf.Bytes())

	alerts := waitForAlerts(sink, 1)
	if len(alerts) != 1 {
		t.Fatalf("expected router to process and dispatch 1 alert, got %d", len(alerts))
	}
	if alerts[0].Comm != "nc" || alerts[0].Filename != "/usr/bin/nc" {
		t.Errorf("unexpected alert routed content: %+v", alerts[0])
	}
}

func TestInt8ToStringAndParseArgs(t *testing.T) {
	int8s := []int8{'h', 'e', 'l', 'l', 'o', 0, 'w', 'o', 'r', 'l', 'd'}
	str := int8ToString(int8s)
	if str != "hello" {
		t.Errorf("expected 'hello', got %q", str)
	}

	argBytes := []int8{'a', 'r', 'g', '1', 0, 'a', 'r', 'g', '2', 0, 0}
	parsed := parseArgs(argBytes)
	if parsed != "arg1 arg2" {
		t.Errorf("expected 'arg1 arg2', got %q", parsed)
	}
}

func TestIsLoopback(t *testing.T) {
	if !isLoopback(net.ParseIP("127.0.0.1")) {
		t.Errorf("expected 127.0.0.1 to be loopback")
	}
	if isLoopback(net.ParseIP("8.8.8.8")) {
		t.Errorf("expected 8.8.8.8 not to be loopback")
	}
}

func waitForAlerts(sink *MockSink, count int) []alert.Alert {
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		alerts := sink.Alerts()
		if len(alerts) >= count {
			return alerts
		}
		time.Sleep(2 * time.Millisecond)
	}
	return sink.Alerts()
}
