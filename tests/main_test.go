package tests

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestMain_ValidationAndFlags tests main execution failure on invalid config.
func TestMain_ValidationAndFlags(t *testing.T) {
	tmpDir := t.TempDir()
	invalidConfig := filepath.Join(tmpDir, "invalid.json")
	if err := os.WriteFile(invalidConfig, []byte("{ invalid json }"), 0600); err != nil {
		t.Fatalf("failed to create dummy config: %v", err)
	}

	// Build or run the main binary against invalid config
	cmd := exec.Command("go", "run", "../main.go", "-config", invalidConfig)
	output, err := cmd.CombinedOutput()

	if err == nil {
		t.Fatalf("expected main to fail on invalid config, but succeeded. Output:\n%s", string(output))
	}
}

// TestMain_Lifecycle tests daemon booting, HTTP endpoints, and graceful teardown.
func TestMain_Lifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping main lifecycle test: eBPF initialization requires root privileges")
	}

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "rules.json")
	storePath := filepath.Join(tmpDir, "alerts.jsonl")

	configData := fmt.Sprintf(`{
		"rules": [],
		"proc_path": "/proc",
		"cgroup_path": "/sys/fs/cgroup",
		"sinks": {
			"stdout": true,
			"store_path": "%s",
			"metrics_listen_addr": "127.0.0.1:19090",
			"dashboard_listen_addr": "127.0.0.1:18080",
			"metrics_auth_token": "test-token",
			"dashboard_auth_token": "test-token"
		}
	}`, storePath)

	if err := os.WriteFile(cfgPath, []byte(configData), 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cmd := exec.Command("go", "run", "../main.go", "-config", cfgPath)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start main binary: %v", err)
	}

	time.Sleep(2 * time.Second)

	// Verify unauthenticated metrics endpoint returns 401
	req, _ := http.NewRequest("GET", "http://127.0.0.1:19090/metrics", nil)
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected HTTP 401, got %d", resp.StatusCode)
		}
	}

	// Send SIGINT for graceful shutdown
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Errorf("failed to send SIGINT: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-ctx.Done():
		cmd.Process.Kill()
		t.Fatalf("process timed out during shutdown")
	case err := <-done:
		if err != nil && err.Error() != "exit status 0" {
			t.Logf("process exited: %v", err)
		}
	}
}
