package ebpf

import (
	"os"
	"testing"
)

// TestEventType_String tests purely Go-side string representations of eBPF event types.
func TestEventType_String(t *testing.T) {
	tests := []struct {
		evt      EventType
		expected string
	}{
		{EventExec, "EXEC"},
		{EventExecBlocked, "EXEC_BLOCKED"},
		{EventConnect, "CONNECT"},
		{EventOpenSensitive, "OPEN_SENSITIVE"},
		{EventPtrace, "PTRACE"},
		{EventSetuid, "SETUID"},
		{EventModuleLoad, "MODULE_LOAD"},
		{EventMemfd, "MEMFD_CREATE"},
		{EventSensitiveWrite, "SENSITIVE_WRITE"},
		{EventWriteBlocked, "WRITE_BLOCKED"},
		{EventPtraceBlocked, "PTRACE_BLOCKED"},
		{EventKmodBlocked, "KMOD_BLOCKED"},
		{EventIoUring, "IOURING"},
		{EventType(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		if got := tt.evt.String(); got != tt.expected {
			t.Errorf("EventType(%d).String() = %q; want %q", tt.evt, got, tt.expected)
		}
	}
}

// TestPathToKey verifies path byte padding conversion.
func TestPathToKey(t *testing.T) {
	p := "/usr/bin/nc"
	key := pathToKey(p)

	if string(key[:len(p)]) != p {
		t.Errorf("expected key prefix %q, got %q", p, string(key[:len(p)]))
	}

	for i := len(p); i < len(key); i++ {
		if key[i] != 0 {
			t.Errorf("expected null padding at index %d, got %d", i, key[i])
			break
		}
	}
}

// TestLoadBPF_Spec verifies that embedded BPF object specs can be loaded without kernel attachment.
func TestLoadBPF_Spec(t *testing.T) {
	spec, err := LoadBPF()
	if err != nil {
		t.Fatalf("failed to load embedded BPF spec: %v", err)
	}

	expectedPrograms := []string{
		"tp_execve",
		"tp_connect",
		"lsm_bprm_check",
		"lsm_file_open",
	}

	for _, progName := range expectedPrograms {
		if _, ok := spec.Programs[progName]; !ok {
			t.Errorf("expected program spec %q missing in loaded BPF collection", progName)
		}
	}
}

// TestNewManager_KernelIntegration tests actual kernel loading and map interactions.
// Requires root privileges and a Linux kernel.
func TestNewManager_KernelIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping integration test: requires root privileges to load eBPF programs")
	}

	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("failed to initialize eBPF Manager: %v", err)
	}
	defer mgr.Close()

	// Test enforcement toggle
	if err := mgr.SetEnforcement(true); err != nil {
		t.Errorf("failed to set enforcement: %v", err)
	}

	// Test map path sync
	blockedPaths := []string{"/usr/bin/malware", "/tmp/bad_exec"}
	if err := mgr.SyncBlockedPaths(blockedPaths); err != nil {
		t.Errorf("failed to sync blocked paths: %v", err)
	}

	// Test active sensors retrieval
	sensors := mgr.ActiveSensors()
	if len(sensors) == 0 {
		t.Errorf("expected at least 1 active sensor, got 0")
	}
}
