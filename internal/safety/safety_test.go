package safety_test

import (
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"k-guard/internal/safety"
)

func TestGuard_IsProtected_ImplicitProtections(t *testing.T) {
	g := safety.NewGuard()
	myPID := uint32(os.Getpid())

	t.Run("protects PID 1", func(t *testing.T) {
		if !g.IsProtected(1, "init") {
			t.Errorf("expected PID 1 to be implicitly protected")
		}
	})

	t.Run("protects self PID", func(t *testing.T) {
		if !g.IsProtected(myPID, "k-guard") {
			t.Errorf("expected self PID (%d) to be implicitly protected", myPID)
		}
	})
}

func TestGuard_IsProtected_ExplicitPIDs(t *testing.T) {
	g := safety.NewGuard()
	g.SetProtected([]int{100, 200, 300}, nil)

	tests := []struct {
		name     string
		pid      uint32
		comm     string
		expected bool
	}{
		{"protected PID 100", 100, "custom-service", true},
		{"protected PID 200", 200, "db-agent", true},
		{"unprotected PID 999", 999, "malware", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := g.IsProtected(tt.pid, tt.comm)
			if got != tt.expected {
				t.Errorf("IsProtected(%d, %q) = %v, want %v", tt.pid, tt.comm, got, tt.expected)
			}
		})
	}
}

func TestGuard_SafeKill_ProtectionRejection(t *testing.T) {
	g := safety.NewGuard()
	myPID := uint32(os.Getpid())
	g.SetProtected([]int{555}, nil)

	t.Run("refuses to kill PID 1", func(t *testing.T) {
		err := g.SafeKill(1, "systemd")
		if err == nil {
			t.Fatalf("expected error when attempting to kill PID 1, got nil")
		}
	})

	t.Run("refuses to kill self PID", func(t *testing.T) {
		err := g.SafeKill(myPID, "k-guard")
		if err == nil {
			t.Fatalf("expected error when attempting to kill self PID (%d), got nil", myPID)
		}
	})

	t.Run("refuses to kill explicitly protected PID", func(t *testing.T) {
		err := g.SafeKill(555, "protected-daemon")
		if err == nil {
			t.Fatalf("expected error when attempting to kill PID 555, got nil")
		}
	})
}

func TestGuard_SafeKill_AlreadyExitedPID(t *testing.T) {
	g := safety.NewGuard()

	// Use a dummy PID high enough that it doesn't exist on the system
	nonExistentPID := uint32(4194303)

	err := g.SafeKill(nonExistentPID, "ghost-process")
	if err == nil {
		t.Fatalf("expected error for non-existent PID, got nil")
	}

	// Should report PID exited / ESRCH race, not panic
	t.Logf("Correctly caught non-existent PID error: %v", err)
}

func TestGuard_SafeKill_RealProcessExecutionAndKill(t *testing.T) {
	g := safety.NewGuard()

	// Spawn a short-lived subprocess (sleep) to test actual termination
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start test process: %v", err)
	}
	targetPID := uint32(cmd.Process.Pid)

	// Ensure process gets cleaned up if test fails
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// Perform SafeKill on the real running process
	if err := g.SafeKill(targetPID, "sleep"); err != nil {
		t.Fatalf("SafeKill failed on valid process PID %d: %v", targetPID, err)
	}

	// Wait for the process state to confirm it was terminated
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-done:
		// Process exited via SIGKILL as expected
	case <-time.After(2 * time.Second):
		t.Fatalf("process %d was not killed within expected timeframe", targetPID)
	}
}

func TestGuard_ConcurrentAccess(t *testing.T) {
	g := safety.NewGuard()
	var wg sync.WaitGroup

	// Stress test concurrent reads (IsProtected) and writes (SetProtected)
	for i := 0; i < 50; i++ {
		wg.Add(2)

		// Reader goroutine
		go func(pid uint32) {
			defer wg.Done()
			_ = g.IsProtected(pid, "test-comm")
		}(uint32(100 + i))

		// Writer goroutine (simulates hot-reloads)
		go func(pid int) {
			defer wg.Done()
			g.SetProtected([]int{pid, pid + 1}, nil)
		}(100 + i)
	}

	wg.Wait()
}
