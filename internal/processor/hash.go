package processor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

type cachedHash struct {
	hex   string
	inode uint64
	mtime int64
	size  int64
}

type HashCache struct {
	mu    sync.RWMutex
	items map[string]cachedHash
}

var globalHashCache = &HashCache{
	items: make(map[string]cachedHash),
}

type execHash struct {
	pid      uint32
	hex      string
	err      error
	computed bool
}

// Helper functions to get the inode field
// ok = false means we couldn't verify
func statIdentity(fi os.FileInfo) (inode uint64, mtime int64, size int64, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, false
	}
	return st.Ino, fi.ModTime().UnixNano(), fi.Size(), true
}

// get returns the SHA256 hex digest of the executable for the given PID by streaming
// the contents of its /proc/[pid]/exe symlink. It caches the result after the first
// computation
// If the process terminates before the binary can be read, it returns
// an error detailing the failure.
func (h *execHash) get() (string, error) {
	if h.computed {
		return h.hex, h.err
	}
	h.computed = true

	procPath := "/proc/" + strconv.Itoa(int(h.pid)) + "/exe"

	resolvedPath, err := filepath.EvalSymlinks(procPath)
	if err != nil {
		h.err = fmt.Errorf("resolving symlink %s: %w", procPath, err)
		return "", h.err
	}

	fi, err := os.Stat(procPath)
	if err != nil {
		h.err = fmt.Errorf("stat %s: %w", procPath, err)
		return "", h.err
	}
	inode, mtime, size, ok := statIdentity(fi)

	globalHashCache.mu.RLock()
	cached, exists := globalHashCache.items[resolvedPath]
	globalHashCache.mu.RUnlock()

	if exists && ok && cached.inode == inode && cached.mtime == mtime && cached.size == size {
		h.hex = cached.hex
		return h.hex, nil
	}

	// Cache miss, or stat id changed since we cached it, or we
	// couldn't verify identity at all so we re-hash from disk rather than
	// trust an entry that's possibly stale
	f, err := os.Open(procPath)
	if err != nil {
		h.err = fmt.Errorf("opening %s: %w", procPath, err)
		return "", h.err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		h.err = fmt.Errorf("hashing %s: %w", procPath, err)
		return "", h.err
	}

	computedHex := hex.EncodeToString(hasher.Sum(nil))

	globalHashCache.mu.Lock()
	if len(globalHashCache.items) > 1000 {
		globalHashCache.items = make(map[string]cachedHash)
	}
	globalHashCache.items[resolvedPath] = cachedHash{hex: computedHex, inode: inode, mtime: mtime, size: size}
	globalHashCache.mu.Unlock()

	h.hex = computedHex
	return h.hex, nil
}

// matchesSHA256 returns if the hash we want to block matches the one of the binary is trying to run
func matchesSHA256(h *execHash, wantHex string) (bool, error) {
	got, err := h.get()
	if err != nil {
		return false, err
	}
	return got == strings.ToLower(wantHex), nil
}
