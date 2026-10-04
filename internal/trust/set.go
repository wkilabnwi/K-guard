package trust

import (
	"fmt"
	"k-guard/internal/types"
	"log/slog"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

type FileID = types.FileID

type pinnedFile struct {
	f  *os.File
	id FileID
}

// Set is a hot-reloadable collection of pinned binaries
type Set struct {
	mu     sync.RWMutex
	pinned map[string]*pinnedFile
	ids    map[FileID]int
}

func NewSet() *Set {
	return &Set{
		pinned: make(map[string]*pinnedFile),
		ids:    make(map[FileID]int),
	}
}

func IDFromStat(st *syscall.Stat_t) FileID {
	major := unix.Major(uint64(st.Dev))
	minor := unix.Minor(uint64(st.Dev))
	return FileID{
		Dev: (uint64(major) << 20) | (uint64(minor) & 0xfffff),
		Ino: st.Ino,
	}
}

func statFD(f *os.File) (FileID, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return FileID{}, err
	}
	return IDFromStat(&st), nil
}

func (s *Set) Sync(paths []string, label string) []FileID {
	s.mu.Lock()
	defer s.mu.Unlock()

	want := make(map[string]bool, len(paths))
	s.ids = make(map[FileID]int)

	for _, p := range paths {
		if p == "" {
			continue
		}
		want[p] = true

		if pf, ok := s.pinned[p]; ok {
			currentID, err := statPath(p)
			if err == nil && currentID == pf.id {
				s.ids[pf.id]++
				continue
			}
			slog.Warn("detected inode change on protected binary, re-verifying",
				"component", "trust",
				"label", label,
				"path", p,
				"old_ino", pf.id.Ino,
				"new_ino", currentID.Ino,
			)
			_ = pf.f.Close()
			delete(s.pinned, p)
		}

		f, err := OpenFileSafely(p)
		if err != nil {
			slog.Warn("cannot open path for pinning", "component", "trust", "label", label, "path", p, "error", err)
			continue
		}

		if err := verifyBinaryIntegrity(f); err != nil {
			_ = f.Close()
			slog.Error("SECURITY WARNING: refusing to trust binary", "component", "trust", "label", label, "path", p, "error", err)
			continue
		}

		id, err := statFD(f)
		if err != nil {
			_ = f.Close()
			slog.Warn("fstat failed", "component", "trust", "label", label, "path", p, "error", err)
			continue
		}

		s.pinned[p] = &pinnedFile{f: f, id: id}
		s.ids[id]++
	}

	for p, pf := range s.pinned {
		if !want[p] {
			_ = pf.f.Close()
			delete(s.pinned, p)
		}
	}

	ids := make([]FileID, 0, len(s.ids))
	for id := range s.ids {
		ids = append(ids, id)
	}
	return ids
}

func verifyBinaryIntegrity(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("not a regular file")
	}
	if fi.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("refusing to trust writable binary (mode %04o)", fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if os.Geteuid() == 0 && st.Uid != 0 {
			return fmt.Errorf("refusing to trust binary owned by non-root uid %d", st.Uid)
		}
	}
	return nil
}

func statPath(path string) (FileID, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return FileID{}, err
	}
	return IDFromStat(&st), nil
}

func OpenFileSafely(path string) (*os.File, error) {
	// O_PATH gets a handle strictly for stat/inode checks without reading contents
	fd, err := unix.Open(path, unix.O_PATH|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// Contains reports whether id matches one of the pinned ids
func (s *Set) Contains(id FileID) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.ids[id]
	return exists
}

func (s *Set) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, pf := range s.pinned {
		if err := pf.f.Close(); err != nil {
			slog.Error("error closing pinned file", "component", "trust", "error", err)
		}
	}
}
