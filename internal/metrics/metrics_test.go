package metrics

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestMetrics_ConcurrentIncrements(t *testing.T) {
	reg := NewRegistry()
	var wg sync.WaitGroup

	numGoroutines := 100
	incrementsPerGoroutine := 1000

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < incrementsPerGoroutine; j++ {
				reg.IncEvent("EXEC")
				reg.IncRuleHit("detect_nc", "HIGH", "KILL")
				reg.IncKill()
				reg.IncKillError()
				reg.IncBlock()
				reg.IncRingbufDrop()
				reg.IncSinkError("syslog")
				reg.IncSinkDrop("webhook")
				reg.IncHashCheckError()
			}
		}()
	}

	wg.Wait()

	expectedCount := int64(numGoroutines * incrementsPerGoroutine)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	reg.Handler().ServeHTTP(w, req)

	body := w.Body.String()

	expectedStrings := []string{
		fmt.Sprintf(`kguard_events_total{event_type="EXEC"} %d`, expectedCount),
		fmt.Sprintf(`kguard_rule_hits_total{rule="detect_nc",severity="HIGH",action="KILL"} %d`, expectedCount),
		fmt.Sprintf(`kguard_kills_total %d`, expectedCount),
		fmt.Sprintf(`kguard_kill_errors_total %d`, expectedCount),
		fmt.Sprintf(`kguard_blocks_total %d`, expectedCount),
		fmt.Sprintf(`kguard_ringbuf_drops_total %d`, expectedCount),
		fmt.Sprintf(`kguard_sink_errors_total{sink="syslog"} %d`, expectedCount),
		fmt.Sprintf(`kguard_hash_check_errors_total %d`, expectedCount),
	}

	for _, exp := range expectedStrings {
		if !strings.Contains(body, exp) {
			t.Errorf("expected metrics body to contain %q, but got:\n%s", exp, body)
		}
	}
}

func TestMetrics_ExpositionFormattingAndSorting(t *testing.T) {
	reg := NewRegistry()

	// Increment unordered to test sorting
	reg.IncEvent("PTRACE")
	reg.IncEvent("EXEC")

	reg.IncRuleHit("rule_b", "HIGH", "ALERT")
	reg.IncRuleHit("rule_a", "LOW", "LOG")
	reg.IncRuleHit("rule_a", "HIGH", "KILL")

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	reg.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status code 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "text/plain; version=0.0.4" {
		t.Errorf("expected Content-Type 'text/plain; version=0.0.4', got %q", contentType)
	}

	body := w.Body.String()

	// Test lexicographical sorting of metric labels
	execIdx := strings.Index(body, `kguard_events_total{event_type="EXEC"}`)
	ptraceIdx := strings.Index(body, `kguard_events_total{event_type="PTRACE"}`)

	if execIdx == -1 || ptraceIdx == -1 || execIdx > ptraceIdx {
		t.Errorf("expected 'EXEC' to be sorted before 'PTRACE' in metrics output")
	}

	// Test multi-label sorting for rule hits (rule -> severity -> action)
	ruleAHighIdx := strings.Index(body, `kguard_rule_hits_total{rule="rule_a",severity="HIGH",action="KILL"}`)
	ruleALowIdx := strings.Index(body, `kguard_rule_hits_total{rule="rule_a",severity="LOW",action="LOG"}`)
	ruleBHighIdx := strings.Index(body, `kguard_rule_hits_total{rule="rule_b",severity="HIGH",action="ALERT"}`)

	if ruleAHighIdx == -1 || ruleALowIdx == -1 || ruleBHighIdx == -1 {
		t.Fatalf("missing rule hit metrics in exposition output")
	}

	if !(ruleAHighIdx < ruleALowIdx && ruleALowIdx < ruleBHighIdx) {
		t.Errorf("rule hits out of order: expected rule_a/HIGH < rule_a/LOW < rule_b/HIGH")
	}
}
