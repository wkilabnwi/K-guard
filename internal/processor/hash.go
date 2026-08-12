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
)

type HashCache struct {
	mu    sync.RWMutex
	items map[string]string
}

var globalHashCache = &HashCache{
	items: make(map[string]string),
}

type execHash struct {
	pid      uint32
	hex      string
	err      error
	computed bool
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

	// Resolve symlink to get actual canonical disk path
	resolvedPath, err := filepath.EvalSymlinks(procPath)
	if err != nil {
		h.err = fmt.Errorf("resolving symlink %s: %w", procPath, err)
		return "", h.err
	}

	// Check in-memory cache first
	globalHashCache.mu.RLock()
	cachedHash, exists := globalHashCache.items[resolvedPath]
	globalHashCache.mu.RUnlock()

	if exists {
		h.hex = cachedHash
		return h.hex, nil
	}

	// Cache miss: stream binary and hash from disk
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

	// Store result in cache for future PIDs
	globalHashCache.mu.Lock()
	if len(globalHashCache.items) > 1000 {
		globalHashCache.items = make(map[string]string)
	}
	globalHashCache.items[resolvedPath] = computedHex
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
