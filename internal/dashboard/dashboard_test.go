package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"k-guard/internal/alert"
)

type mockStatusProvider struct {
	sensors []string
	lsm     bool
}

func (m *mockStatusProvider) ActiveSensors() []string { return m.sensors }
func (m *mockStatusProvider) LSMEnabled() bool        { return m.lsm }

func TestServer_Endpoints(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := alert.NewStore(tmpDir)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	testAlert := alert.Alert{
		Timestamp: time.Now(),
		RuleName:  "TestExecRule",
		Severity:  "critical",
		Action:    "KILL",
		Blocked:   true,
		EventType: "EXEC",
		Pid:       1234,
		Comm:      "bad_proc",
		Filename:  "/tmp/bad_proc",
	}
	store.Send(testAlert)

	status := &mockStatusProvider{
		sensors: []string{"tracepoint/sys_enter_execve", "lsm/bprm_check_security"},
		lsm:     true,
	}

	authToken := "test-dashboard-token"
	srv := NewServer("127.0.0.1:0", store, status, authToken)

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleIndex)
	mux.HandleFunc("/api/alerts", srv.handleAlertsJSON)

	t.Run("HTML Index rendering", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}

		body := rec.Body.String()
		if !strings.Contains(body, "K-Guard Dashboard") {
			t.Errorf("expected body to contain title")
		}
		if !strings.Contains(body, "ACTIVE") {
			t.Errorf("expected body to show ACTIVE LSM enforcement")
		}
		if !strings.Contains(body, "TestExecRule") {
			t.Errorf("expected body to render alert rule name")
		}
	})

	t.Run("JSON API alerts response", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/alerts", nil)
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}

		var alerts []alert.Alert
		if err := json.NewDecoder(rec.Body).Decode(&alerts); err != nil {
			t.Fatalf("failed to parse JSON response: %v", err)
		}

		if len(alerts) != 1 {
			t.Fatalf("expected 1 alert, got %d", len(alerts))
		}

		if alerts[0].RuleName != "TestExecRule" || alerts[0].Pid != 1234 {
			t.Errorf("unexpected alert content in JSON: %+v", alerts[0])
		}
	})
}
