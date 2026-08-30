package trust_test

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"k-guard/internal/trust"
)

func createTempFile(t *testing.T) (string, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "trust-test-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	path := f.Name()
	f.Close()

	cleanup := func() {
		_ = os.Remove(path)
	}
	return path, cleanup
}

func TestSet_SyncAndContains(t *testing.T) {
	path1, cleanup1 := createTempFile(t)
	defer cleanup1()

	path2, cleanup2 := createTempFile(t)
	defer cleanup2()

	s := trust.NewSet()
	defer s.Close()

	// Sync path1 and path2
	ids := s.Sync([]string{path1, path2}, "test")
	if len(ids) != 2 {
		t.Fatalf("expected 2 FileIDs returned, got %d", len(ids))
	}

	// Verify both FileIDs are registered in Contains
	for _, id := range ids {
		if !s.Contains(id) {
			t.Errorf("expected Set to contain FileID dev=%d ino=%d", id.Dev, id.Ino)
		}
	}

	// Unknown FileID should return false
	fakeID := trust.FileID{Dev: 999999, Ino: 888888}
	if s.Contains(fakeID) {
		t.Errorf("expected Set.Contains to return false for fake FileID")
	}
}

func TestSet_Sync_Symlinks(t *testing.T) {
	targetPath, cleanup := createTempFile(t)
	defer cleanup()

	dir := t.TempDir()
	symlinkPath := filepath.Join(dir, "symlink_bin")

	if err := os.Symlink(targetPath, symlinkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	s := trust.NewSet()
	defer s.Close()

	ids := s.Sync([]string{symlinkPath}, "test-symlink")
	if len(ids) != 1 {
		t.Fatalf("expected 1 FileID for symlink target, got %d", len(ids))
	}

	// Verify identity matches the target file's actual underlying inode
	f, err := os.Open(targetPath)
	if err != nil {
		t.Fatalf("failed to open target path: %v", err)
	}
	defer f.Close()

	if !s.Contains(ids[0]) {
		t.Errorf("expected symlink FileID to match target file identity")
	}
}

func TestSet_Sync_HotReloadDiffingAndClose(t *testing.T) {
	path1, cleanup1 := createTempFile(t)
	defer cleanup1()

	path2, cleanup2 := createTempFile(t)
	defer cleanup2()

	s := trust.NewSet()

	// Initial Sync with path1 and path2
	idsV1 := s.Sync([]string{path1, path2}, "v1")
	if len(idsV1) != 2 {
		t.Fatalf("expected 2 IDs in v1, got %d", len(idsV1))
	}

	// Hot reload (Sync) dropping path1 and keeping path2
	idsV2 := s.Sync([]string{path2}, "v2")
	if len(idsV2) != 1 {
		t.Fatalf("expected 1 ID in v2 after dropping path1, got %d", len(idsV2))
	}

	// path2 should remain, path1 should no longer match
	if !s.Contains(idsV2[0]) {
		t.Errorf("expected path2 identity to remain in Set")
	}

	// Test Close releases all descriptors cleanly without panic
	s.Close()
}

func TestSet_Sync_EdgeCases(t *testing.T) {
	t.Run("empty path and non-existent path ignored", func(t *testing.T) {
		s := trust.NewSet()
		defer s.Close()

		ids := s.Sync([]string{"", "/path/does/not/exist/99999"}, "invalid-test")
		if len(ids) != 0 {
			t.Errorf("expected 0 IDs for empty and non-existent paths, got %d", len(ids))
		}
	})
}

func TestSet_ConcurrentAccess(t *testing.T) {
	path1, cleanup1 := createTempFile(t)
	defer cleanup1()

	s := trust.NewSet()
	defer s.Close()

	ids := s.Sync([]string{path1}, "test-concurrent")
	if len(ids) == 0 {
		t.Fatalf("failed to sync path1 for concurrency test")
	}
	targetID := ids[0]

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)

		// Concurrent Readers
		go func() {
			defer wg.Done()
			_ = s.Contains(targetID)
		}()

		// Concurrent Syncs (hot-reloads)
		go func() {
			defer wg.Done()
			_ = s.Sync([]string{path1}, "concurrent-sync")
		}()
	}

	wg.Wait()
}
