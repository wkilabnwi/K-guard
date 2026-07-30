// Package safety guards against K-Guard harming our own system
// it protects us from : killing PID 1 (which panics/reboots most systems), killing
// itself, or killing an already-exited PID and logging a confusing error.
package safety

import (
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// Guard tracks which PIDs/processes must never be killed, on top of
// the two that are always implicitly protected: PID 1 and K-Guard's own
// PID (os.Getpid()).
type Guard struct {
	mu             sync.RWMutex
	protectedPIDs  map[int]bool
	protectedComms map[string]bool
	selfPID        int
}

func NewGuard() *Guard {
	return &Guard{
		protectedPIDs:  map[int]bool{},
		protectedComms: map[string]bool{},
		selfPID:        os.Getpid(),
	}
}

// SetProtected replaces the configured protected PID/comm list on every hot-reload for example
func (g *Guard) SetProtected(pids []int, comms []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.protectedPIDs = make(map[int]bool, len(pids))
	for _, p := range pids {
		g.protectedPIDs[p] = true
	}
	g.protectedComms = make(map[string]bool, len(comms))
	for _, c := range comms {
		g.protectedComms[c] = true
	}
}

// IsProtected reports whether the given pid/comm must never be killed
func (g *Guard) IsProtected(pid uint32, comm string) bool {
	if pid == 1 {
		return true // protecting us from killing pid 1
	}
	if int(pid) == g.selfPID {
		return true // never kill ourselves
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.protectedPIDs[int(pid)] {
		return true
	}
	if g.protectedComms[comm] {
		return true
	}
	return false
}

// SafeKill sends SIGKILL to kill the process, refusing (with a descriptive error)
// if the pid is protected or has already exited
// Callers should treat "already exited" as informational, not a failure
// it just means the process died on its own between the
// event firing and the kill attempt (a real race that especially matters
// in detect-only mode, since there's an inherent window between the exec
// tracepoint firing and userspace processing the event)
func (g *Guard) SafeKill(pid uint32, comm string) error {
	if g.IsProtected(pid, comm) {
		return fmt.Errorf("refusing to kill protected pid %d (%s)", pid, comm)
	}

	// The usage of PidfdOpen instead of directly killing the program
	// is due to : in some rare cases a binary excutes and finishes fast
	// so to defend against the Kernel giving it's pid to another process and us ending
	// up killing a process that wasn't meant to be killed
	// but PidfdOpen returns a file descriptor so if even if it isn't valid
	// we won't end up killing anything that might be useful

	fd, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		if err == unix.ESRCH {
			return fmt.Errorf("pid %d already exited before kill attempt (race between detection and response)", pid)
		}
		return fmt.Errorf("pidfd_open for pid %d failed: %w", pid, err)
	}
	defer unix.Close(fd)

	if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil {
		if err == unix.ESRCH {
			return fmt.Errorf("pid %d exited between pidfd_open and kill (race between detection and response)", pid)
		}
		return fmt.Errorf("SIGKILL via pidfd to pid %d failed: %w", pid, err)
	}
	return nil
}
