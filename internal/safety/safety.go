// Package safety guards against K-Guard harming our own system
// it protects us from : killing PID 1 (which panics/reboots most systems), killing
// itself, or killing an already-exited PID and logging a confusing error.
package safety

import (
	"fmt"
	"k-guard/internal/trust"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// Guard tracks which PIDs/processes must never be killed, on top of
// the two that are always implicitly protected: PID 1 and K-Guard's own
// PID (os.Getpid()).
type Guard struct {
	mu            sync.RWMutex
	protectedPIDs map[int]bool
	protected     *trust.Set
	selfPID       int
}

func NewGuard() *Guard {
	return &Guard{
		protectedPIDs: map[int]bool{},
		protected:     trust.NewSet(),
		selfPID:       os.Getpid(),
	}
}

// SetProtected replaces the configured protected PID/comm list on every hot-reload for example
func (g *Guard) SetProtected(pids []int, paths []string) {
	g.mu.Lock()
	g.protectedPIDs = make(map[int]bool, len(pids))
	for _, p := range pids {
		g.protectedPIDs[p] = true
	}
	g.mu.Unlock()

	g.protected.Sync(paths, "protected_comms")
}

func exeIdentity(pid uint32) (trust.FileID, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return trust.FileID{}, err
	}
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return trust.FileID{}, err
	}
	return trust.FileID{Dev: uint64(st.Dev), Ino: st.Ino}, nil
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
	byPID := g.protectedPIDs[int(pid)]
	g.mu.RUnlock()
	if byPID {
		return true
	}

	id, err := exeIdentity(pid)
	if err != nil {
		return false
	}
	return g.protected.Contains(id)
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
