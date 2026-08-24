package trust

import (
	"log"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

type FileID struct {
	Dev uint64
	Ino uint64
}

type pinnedFile struct {
	f  *os.File
	id FileID
}

// Set is a hot-reloadable collection of pinned binaries
type Set struct {
	mu     sync.RWMutex
	pinned map[string]*pinnedFile
}

func NewSet() *Set {
	return &Set{pinned: make(map[string]*pinnedFile)}
}

func statFD(f *os.File) (FileID, error) {

	var st syscall.Stat_t

	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return FileID{}, err
	}

	major := unix.Major(uint64(st.Dev))
	minor := unix.Minor(uint64(st.Dev))
	kernelDev := (uint64(major) << 20) | (uint64(minor) & 0xfffff)
	return FileID{Dev: kernelDev, Ino: st.Ino}, nil
}

func (s *Set) Sync(paths []string, label string) []FileID {
	s.mu.Lock()
	defer s.mu.Unlock()

	want := make(map[string]bool, len(paths))
	for _, p := range paths {
		if p == "" {
			continue
		}
		want[p] = true
		if _, ok := s.pinned[p]; ok {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			log.Printf("[trust] %s: cannot open %q, skipping: %v", label, p, err)
			continue
		}
		id, err := statFD(f)
		if err != nil {
			f.Close()
			log.Printf("[trust] %s: fstat %q failed, skipping: %v", label, p, err)
			continue
		}
		s.pinned[p] = &pinnedFile{f: f, id: id}
	}

	for p, pf := range s.pinned {
		if !want[p] {
			pf.f.Close()
			delete(s.pinned, p)
		}
	}

	ids := make([]FileID, 0, len(s.pinned))
	for _, pf := range s.pinned {
		ids = append(ids, pf.id)
	}
	return ids
}

// Contains reports whether id matches one of the pinned ids
func (s *Set) Contains(id FileID) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, pf := range s.pinned {
		if pf.id == id {
			return true
		}
	}
	return false
}

func (s *Set) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, pf := range s.pinned {
		pf.f.Close()
	}
}
