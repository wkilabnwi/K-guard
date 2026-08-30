package alert

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// MockSink captures received alerts for verification
type MockSink struct {
	name   string
	mu     sync.Mutex
	alerts []Alert
	block  chan struct{}
}

func NewMockSink(name string) *MockSink {
	return &MockSink{
		name:  name,
		block: make(chan struct{}),
	}
}

func (m *MockSink) Name() string { return m.name }

func (m *MockSink) Send(a Alert) {
	m.mu.Lock()
	m.alerts = append(m.alerts, a)
	m.mu.Unlock()
}

func (m *MockSink) Alerts() []Alert {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := make([]Alert, len(m.alerts))
	copy(res, m.alerts)
	return res
}

// BlockingSink simulates a stuck/slow receiver
type BlockingSink struct {
	name  string
	block chan struct{}
}

func (b *BlockingSink) Name() string { return b.name }
func (b *BlockingSink) Send(a Alert) {
	<-b.block // Block indefinitely until unblocked
}

// PanickingSink simulates a buggy sink
type PanickingSink struct{}

func (p PanickingSink) Name() string { return "panicking" }
func (p PanickingSink) Send(a Alert) {
	panic("sink explosion")
}

func TestDispatcher_FanOutAndDelivery(t *testing.T) {
	d := NewDispatcher()
	s1 := NewMockSink("mock1")
	s2 := NewMockSink("mock2")

	d.Register(s1)
	d.Register(s2)

	testAlert := Alert{
		RuleName:  "TestRule",
		Severity:  "high",
		Action:    "ALERT",
		EventType: "EXEC",
		Pid:       1234,
		Comm:      "malicious_proc",
	}

	d.Dispatch(testAlert)
	d.Close()

	if len(s1.Alerts()) != 1 || s1.Alerts()[0].RuleName != "TestRule" {
		t.Errorf("sink1 failed to receive alert correctly")
	}
	if len(s2.Alerts()) != 1 || s2.Alerts()[0].RuleName != "TestRule" {
		t.Errorf("sink2 failed to receive alert correctly")
	}
}

func TestDispatcher_DropWhenQueueFull(t *testing.T) {
	d := NewDispatcher()
	blocker := &BlockingSink{name: "slow_sink", block: make(chan struct{})}

	var dropCount int32
	d.OnDrop(func(sink string) {
		if sink == "slow_sink" {
			atomic.AddInt32(&dropCount, 1)
		}
	})

	d.Register(blocker)

	// Fill queue (queueDepth = 256) + 1 extra to trigger drop
	for i := 0; i < queueDepth+10; i++ {
		d.Dispatch(Alert{Pid: uint32(i)})
	}

	if atomic.LoadInt32(&dropCount) == 0 {
		t.Errorf("expected alerts to be dropped when sink queue is full, got 0 drops")
	}

	close(blocker.block) // Cleanup blocking channel
	d.Close()
}

func TestDispatcher_PanicRecovery(t *testing.T) {
	d := NewDispatcher()
	panicker := PanickingSink{}
	mock := NewMockSink("mock")

	d.Register(panicker)
	d.Register(mock)

	// Dispatch should not panic the caller process
	d.Dispatch(Alert{RuleName: "PanicTest"})

	d.Close()

	// Verify the valid sink still processed its alert despite the panic in sister worker
	if len(mock.Alerts()) != 1 {
		t.Errorf("expected normal sink to complete processing despite sister panic")
	}
}

func TestStore_Operations(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewStore(tmpDir)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	alerts := []Alert{
		{RuleName: "Rule1", Severity: "HIGH", Pid: 100},
		{RuleName: "Rule2", Severity: "MEDIUM", Pid: 200},
		{RuleName: "Rule3", Severity: "HIGH", Pid: 300},
	}

	for _, a := range alerts {
		store.Send(a)
	}

	// Test Recent lookup
	recent, err := store.Recent(2)
	if err != nil {
		t.Fatalf("Recent failed: %v", err)
	}
	if len(recent) != 2 {
		t.Fatalf("expected 2 recent alerts, got %d", len(recent))
	}
	if recent[0].Pid != 200 || recent[1].Pid != 300 {
		t.Errorf("unexpected recent order or items: %+v", recent)
	}

	// Test Severity Counts
	counts, err := store.CountBySeverity()
	if err != nil {
		t.Fatalf("CountBySeverity failed: %v", err)
	}
	if counts["HIGH"] != 2 || counts["MEDIUM"] != 1 {
		t.Errorf("unexpected severity counts: %+v", counts)
	}

	_ = store.Close()
}

func TestWebhookSink_Send(t *testing.T) {
	var receivedAlert Alert
	var receivedPayload webhookPayload

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST method, got %s", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Errorf("failed to decode webhook body: %v", err)
		}
		receivedAlert = receivedPayload.Alert
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink := NewWebhookSink(server.URL)
	testAlert := Alert{
		EventType: "EXEC",
		Severity:  "CRITICAL",
		Action:    "KILL",
		Comm:      "nc",
		Pid:       4321,
		Filename:  "/usr/bin/nc",
	}

	sink.Send(testAlert)

	if receivedAlert.Pid != 4321 || receivedAlert.Comm != "nc" {
		t.Errorf("webhook received incorrect alert payload: %+v", receivedAlert)
	}
}
