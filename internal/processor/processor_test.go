package processor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
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
      "expression": "process.basename == 'nc'",
      "severity": "high",
      "action": "ALERT"
    },
    {
      "name": "kill-malware",
      "expression": "process.path == '/tmp/malware'",
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

func TestIsSuspiciousPath(t *testing.T) {
	paths := []string{"/tmp", "/var/tmp", "/dev/shm"}
	if !isSuspiciousPath("/tmp/evil.sh", paths) {
		t.Errorf("expected /tmp/evil.sh to be marked suspicious")
	}
	if isSuspiciousPath("/usr/bin/ls", paths) {
		t.Errorf("expected /usr/bin/ls to NOT be marked suspicious")
	}
}

func TestExecHash_GetSelf(t *testing.T) {
	h := &execHash{pid: uint32(os.Getpid())}
	hexVal, err := h.get()
	if err != nil {
		t.Fatalf("expected hash for current process, got err: %v", err)
	}
	if len(hexVal) != 64 {
		t.Errorf("expected 64-char sha256 hex string, got %s", hexVal)
	}

	// Verify caching path
	cachedHex, err := h.get()
	if err != nil || cachedHex != hexVal {
		t.Errorf("expected cached hash match")
	}
}

func TestEngine_GenericAnalyzers(t *testing.T) {
	eng, sink, _ := setupTestEngine(t)

	eng.AnalyzeConnect(1001, 1, 1000, 1000, "curl", 1, "1.1.1.1", 443, true, "/tmp/bad")
	eng.AnalyzeGeneric("MEMFD_CREATE", config.SeverityHigh, 1002, 1, 1000, 1000, "malware", 1, "/tmp/m", "memfd created", false, "", false)
	eng.AnalyzeWriteBlocked("bash", "/etc/shadow", 1003, 1, 0, 0, 1, false, "", false)
	eng.AnalyzePtraceBlocked("gdb", "target", 1004, 0x1, 1005, 1, 0, 0, 1, false, "")
	eng.AnalyzeKmodBlocked("insmod", 1006, 1, 0, 0, 1, true, "/tmp/rootkit")
	eng.AnalyzeIoUring(1007, 1, 1000, 1000, "exploit", "", 1, 1, false, "")
	eng.AnalyzeLpeBlocked("exploit", 1008, 1, 1000, 1000, 1, 1000, 0, true, "/tmp/lpe")
	eng.AnalyzePmu(1009, 1, 1000, 1000, "spectre", 1, 5000, false, "")

	alerts := waitForAlerts(sink, 8)
	if len(alerts) < 8 {
		t.Fatalf("expected at least 8 alerts from generic analyzers, got %d", len(alerts))
	}
}

func TestRouter_AllEvents(t *testing.T) {
	eng, sink, cfgMgr := setupTestEngine(t)
	m := metrics.NewRegistry()
	router := NewRouter(eng, m, cfgMgr)

	makeHdr := func(et kebpf.EventType) kebpf.BPFEventHdr {
		h := kebpf.BPFEventHdr{
			EventType:          uint32(et),
			Pid:                2000,
			Ppid:               1,
			Uid:                1000,
			Gid:                1000,
			CgroupId:           1,
			AncestorSuspicious: 1,
		}
		copyInt8(h.Comm[:], "test")
		copyInt8(h.AncestorFilename[:], "/tmp/ancestor")
		return h
	}

	connEvt := kebpf.BPFConnectEvent{
		Hdr:    makeHdr(kebpf.EventConnect),
		Family: 2,
		Dport:  80,
		Daddr:  0x08080808,
	}
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, connEvt)
	router.ProcessRawRecord(buf.Bytes())

	unixEvt := kebpf.BPFConnectEvent{
		Hdr:    makeHdr(kebpf.EventConnect),
		Family: 1,
	}
	copyInt8(unixEvt.UnixPath[:], "/var/run/test.sock")
	buf.Reset()
	binary.Write(buf, binary.LittleEndian, unixEvt)
	router.ProcessRawRecord(buf.Bytes())

	openEvt := kebpf.BPFOpenEvent{
		Hdr: makeHdr(kebpf.EventOpenSensitive),
	}
	copyInt8(openEvt.Filename[:], "/etc/passwd")
	buf.Reset()
	binary.Write(buf, binary.LittleEndian, openEvt)
	router.ProcessRawRecord(buf.Bytes())

	ptraceEvt := makeHdr(kebpf.EventPtrace)
	buf.Reset()
	binary.Write(buf, binary.LittleEndian, ptraceEvt)
	router.ProcessRawRecord(buf.Bytes())

	ptraceBlockedEvt := kebpf.BPFPtraceEvent{
		Hdr:       makeHdr(kebpf.EventPtraceBlocked),
		TargetPid: 3000,
		Mode:      1,
	}
	copyInt8(ptraceBlockedEvt.TargetComm[:], "target")
	buf.Reset()
	binary.Write(buf, binary.LittleEndian, ptraceBlockedEvt)
	router.ProcessRawRecord(buf.Bytes())

	kmodEvt := kebpf.BPFKmodEvent{
		Hdr: makeHdr(kebpf.EventKmodBlocked),
	}
	buf.Reset()
	binary.Write(buf, binary.LittleEndian, kmodEvt)
	router.ProcessRawRecord(buf.Bytes())

	lpeEvt := kebpf.BPFLpeEvent{
		Hdr:    makeHdr(kebpf.EventLpeBlocked),
		OldUid: 1000,
		NewUid: 0,
	}
	buf.Reset()
	binary.Write(buf, binary.LittleEndian, lpeEvt)
	router.ProcessRawRecord(buf.Bytes())

	pmuEvt := kebpf.BPFPmuEvent{
		Hdr:          makeHdr(kebpf.EventBranchMispredict),
		MispredCount: 999,
	}
	buf.Reset()
	binary.Write(buf, binary.LittleEndian, pmuEvt)
	router.ProcessRawRecord(buf.Bytes())

	alerts := waitForAlerts(sink, 8)
	if len(alerts) < 8 {
		t.Fatalf("expected at least 8 alerts from router events, got %d", len(alerts))
	}
}

func TestResolveAbsolutePath(t *testing.T) {
	if resolved := resolveAbsolutePath(uint32(os.Getpid()), "relative/path"); resolved == "" {
		t.Errorf("expected non-empty resolved path")
	}
}

func TestEngine_AnalyzeExec_BlockedAndTruncated(t *testing.T) {
	eng, sink, _ := setupTestEngine(t)

	// Blocked pre-flight exec with path truncation
	eng.AnalyzeExec("badapp", "/tmp/badapp", 601, 1, 0, 0, 1, "-v", true, true, "/tmp/ancestor", true, false)

	alerts := waitForAlerts(sink, 1)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for blocked exec, got %d", len(alerts))
	}
	if !alerts[0].Blocked || alerts[0].EventType != "EXEC_BLOCKED" || !alerts[0].PathTruncated {
		t.Errorf("unexpected alert details for blocked exec: %+v", alerts[0])
	}
}

func TestEngine_AnalyzeExec_SeverityEscalationAndKillAction(t *testing.T) {
	eng, sink, _ := setupTestEngine(t)

	// Trigger rule 'kill-malware' which action is KILL
	eng.AnalyzeExec("malware", "/tmp/malware", 602, 1, 0, 0, 1, "", false, false, "", true, false)

	alerts := waitForAlerts(sink, 1)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for kill action, got %d", len(alerts))
	}
	if alerts[0].Action != string(config.ActionKill) || !alerts[0].PathTruncated {
		t.Errorf("unexpected alert details: %+v", alerts[0])
	}
}

func TestEngine_ApplyConfig_NilManager(t *testing.T) {
	eng, _, _ := setupTestEngine(t)
	// Passing a config with ebpfMgr == nil should return cleanly without panicking
	eng.applyConfig(&config.Config{
		DedupWindowSeconds: 10,
		ProtectedPIDs:      []int{1},
		ProtectedComms:     []string{"systemd"},
	})
}

func TestRouter_OpenEventsAndEdgeCases(t *testing.T) {
	eng, sink, cfgMgr := setupTestEngine(t)
	m := metrics.NewRegistry()
	router := NewRouter(eng, m, cfgMgr)

	makeHdr := func(et kebpf.EventType) kebpf.BPFEventHdr {
		h := kebpf.BPFEventHdr{
			EventType:          uint32(et),
			Pid:                3000,
			Ppid:               1,
			Uid:                1000,
			Gid:                1000,
			CgroupId:           1,
			AncestorSuspicious: 0,
		}
		copyInt8(h.Comm[:], "tester")
		return h
	}

	memfdEvt := kebpf.BPFOpenEvent{Hdr: makeHdr(kebpf.EventMemfd)}
	copyInt8(memfdEvt.Filename[:], "memfd:test")
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, memfdEvt)
	router.ProcessRawRecord(buf.Bytes())

	writeEvt := kebpf.BPFOpenEvent{Hdr: makeHdr(kebpf.EventSensitiveWrite)}
	copyInt8(writeEvt.Filename[:], "/etc/shadow")
	buf.Reset()
	binary.Write(buf, binary.LittleEndian, writeEvt)
	router.ProcessRawRecord(buf.Bytes())

	setuidHdr := makeHdr(kebpf.EventSetuid)
	setuidHdr.Ret = 0
	buf.Reset()
	binary.Write(buf, binary.LittleEndian, setuidHdr)
	router.ProcessRawRecord(buf.Bytes())

	modHdr := makeHdr(kebpf.EventModuleLoad)
	buf.Reset()
	binary.Write(buf, binary.LittleEndian, modHdr)
	router.ProcessRawRecord(buf.Bytes())

	wbEvt := kebpf.BPFOpenEvent{Hdr: makeHdr(kebpf.EventWriteBlocked)}
	copyInt8(wbEvt.Filename[:], "/etc/passwd")
	buf.Reset()
	binary.Write(buf, binary.LittleEndian, wbEvt)
	router.ProcessRawRecord(buf.Bytes())

	alerts := waitForAlerts(sink, 5)
	if len(alerts) < 5 {
		t.Fatalf("expected at least 5 alerts from additional router events, got %d", len(alerts))
	}
}

func TestRouter_MalformedRecord(t *testing.T) {
	eng, _, cfgMgr := setupTestEngine(t)
	m := metrics.NewRegistry()
	router := NewRouter(eng, m, cfgMgr)

	// Short byte array to trigger binary read error
	router.ProcessRawRecord([]byte{0x01, 0x02})
}

func TestMatchesSHA256(t *testing.T) {
	h := &execHash{pid: uint32(os.Getpid())}
	actualHash, err := h.get()
	if err != nil {
		t.Fatalf("failed to get hash: %v", err)
	}

	match, err := matchesSHA256(h, actualHash)
	if err != nil || !match {
		t.Errorf("expected hash match to return true")
	}

	mismatch, err := matchesSHA256(h, "0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil || mismatch {
		t.Errorf("expected hash mismatch to return false")
	}
}

func TestDeduper_Cleanup(t *testing.T) {
	d := NewDeduper(10 * time.Millisecond)

	// Populate entries
	for i := 0; i < 2050; i++ {
		d.Allow("key-" + string(rune(i)))
	}

	time.Sleep(15 * time.Millisecond)

	// Trigger map cleanup loop
	d.Allow("trigger-cleanup")
}

func TestIsIgnoredComm(t *testing.T) {
	comms := []string{"systemd", "dockerd"}
	if !isIgnoredComm(comms, "dockerd") {
		t.Errorf("expected dockerd to be ignored")
	}
	if isIgnoredComm(comms, "bash") {
		t.Errorf("expected bash not to be ignored")
	}
}

func TestRouter_IPv6Connect(t *testing.T) {
	eng, sink, cfgMgr := setupTestEngine(t)
	m := metrics.NewRegistry()
	router := NewRouter(eng, m, cfgMgr)

	makeHdr := func(et kebpf.EventType) kebpf.BPFEventHdr {
		return kebpf.BPFEventHdr{
			EventType: uint32(et),
			Pid:       4000,
			Ppid:      1,
			Uid:       1000,
			Gid:       1000,
			CgroupId:  1,
		}
	}

	// AF_INET6 Event (Family = 10)
	v6Evt := kebpf.BPFConnectEvent{
		Hdr:    makeHdr(kebpf.EventConnect),
		Family: 10,
		Dport:  443,
	}
	// 2001:db8::1
	v6Evt.Daddr6[0] = 0x20
	v6Evt.Daddr6[1] = 0x01
	v6Evt.Daddr6[2] = 0x0d
	v6Evt.Daddr6[3] = 0xb8
	v6Evt.Daddr6[15] = 0x01

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, v6Evt)
	router.ProcessRawRecord(buf.Bytes())

	alerts := waitForAlerts(sink, 1)
	if len(alerts) < 1 {
		t.Fatalf("expected 1 alert for IPv6 connect, got %d", len(alerts))
	}
	if alerts[0].DestIP != "[2001:db8::1]" {
		t.Errorf("expected parsed IPv6 string, got %s", alerts[0].DestIP)
	}
}

func TestRouter_UnknownAddressFamily(t *testing.T) {
	eng, sink, cfgMgr := setupTestEngine(t)
	m := metrics.NewRegistry()
	router := NewRouter(eng, m, cfgMgr)

	unknownEvt := kebpf.BPFConnectEvent{
		Hdr: kebpf.BPFEventHdr{
			EventType: uint32(kebpf.EventConnect),
			Pid:       4001,
		},
		Family: 99, // Unknown family
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, unknownEvt)
	router.ProcessRawRecord(buf.Bytes())

	alerts := waitForAlerts(sink, 1)
	if len(alerts) < 1 {
		t.Fatalf("expected 1 alert for unknown family connect, got %d", len(alerts))
	}
}

func TestExecHash_NonExistentPID(t *testing.T) {
	// PID 999999999 should fail symlink/stat lookup cleanly
	h := &execHash{pid: 999999999}
	_, err := h.get()
	if err == nil {
		t.Errorf("expected error fetching hash for invalid PID")
	}

	// Verify error state caching
	_, cachedErr := h.get()
	if cachedErr == nil {
		t.Errorf("expected cached error on subsequent calls")
	}
}

func TestCorrelator_EmptyTree(t *testing.T) {
	c := NewCorrelator(5 * time.Second)
	// Query PID that was never recorded
	tree := c.BuildTree(9999)
	if len(tree) != 0 {
		t.Errorf("expected empty tree for unrecorded PID")
	}

	formatted := c.FormatTree(9999)
	if formatted != "" {
		t.Errorf("expected empty string for unrecorded tree")
	}
}

func TestFormatTree_FallbackToComm(t *testing.T) {
	c := NewCorrelator(5 * time.Second)
	// Node without Filename forces the name = n.Comm fallback branch
	c.cache.Add(10, ProcessNode{Pid: 10, Ppid: 1, Comm: "fallback-comm", Filename: ""})

	formatted := c.FormatTree(10)
	if !strings.Contains(formatted, "fallback-comm") {
		t.Errorf("expected tree output to contain fallback comm name, got: %s", formatted)
	}
}

func TestRouter_PtraceBlocked_EmptyTargetComm(t *testing.T) {
	eng, sink, cfgMgr := setupTestEngine(t)
	m := metrics.NewRegistry()
	router := NewRouter(eng, m, cfgMgr)

	hdr := kebpf.BPFEventHdr{
		EventType: uint32(kebpf.EventPtraceBlocked),
		Pid:       5000,
	}
	// Omit TargetComm to trigger the targetComm == "" -> "UNKNOWN" branch
	evt := kebpf.BPFPtraceEvent{Hdr: hdr, TargetPid: 5001, Mode: 2}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, evt)
	router.ProcessRawRecord(buf.Bytes())

	alerts := waitForAlerts(sink, 1)
	if len(alerts) < 1 || !strings.Contains(alerts[0].Detail, "UNKNOWN") {
		t.Errorf("expected UNKNOWN fallback target comm in detail")
	}
}

func TestGlobalHashCache_Eviction(t *testing.T) {
	// Fill globalHashCache past its 1000 capacity to hit LRU eviction logic
	for i := 0; i < 1005; i++ {
		globalHashCache.Add(fmt.Sprintf("/fake/path/%d", i), cachedHash{hex: "abc"})
	}
}

func TestDeduper_ZeroWindow(t *testing.T) {
	d := NewDeduper(0)
	// Window <= 0 forces direct return true branch
	if !d.Allow("any_key") || !d.Allow("any_key") {
		t.Errorf("deduper with 0 window should always allow")
	}
}

func TestResolveAbsolutePath_EmptyAndAbs(t *testing.T) {
	if res := resolveAbsolutePath(1, ""); res != "" {
		t.Errorf("expected empty string")
	}
	if res := resolveAbsolutePath(1, "/usr/bin/ls"); res != "/usr/bin/ls" {
		t.Errorf("expected absolute path return")
	}
}
