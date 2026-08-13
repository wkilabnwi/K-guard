package processor

import (
	"container/list"
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

type cacheItem[K comparable, V any] struct {
	key   K
	value V
}

type lruCache[K comparable, V any] struct {
	mu        sync.Mutex
	capacity  int
	items     map[K]*list.Element
	evictList *list.List
}

func newLRUCache[K comparable, V any](capacity int) *lruCache[K, V] {
	return &lruCache[K, V]{
		capacity:  capacity,
		items:     make(map[K]*list.Element),
		evictList: list.New(),
	}
}

func (c *lruCache[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.evictList.MoveToFront(elem)
		return elem.Value.(*cacheItem[K, V]).value, true
	}
	var zero V
	return zero, false
}

func (c *lruCache[K, V]) Add(key K, val V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Existing item update
	if elem, ok := c.items[key]; ok {
		c.evictList.MoveToFront(elem)
		elem.Value.(*cacheItem[K, V]).value = val
		return
	}

	// Add new item
	elem := c.evictList.PushFront(&cacheItem[K, V]{key: key, value: val})
	c.items[key] = elem

	// Evict oldest if full
	if c.evictList.Len() > c.capacity {
		oldest := c.evictList.Back()
		if oldest != nil {
			c.evictList.Remove(oldest)
			kv := oldest.Value.(*cacheItem[K, V])
			delete(c.items, kv.key)
		}
	}
}

type cachedHash struct {
	hex   string
	inode uint64
	mtime int64
	size  int64
}

var globalHashCache = newLRUCache[string, cachedHash](1000)

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

	// Check cache
	if cached, exists := globalHashCache.Get(resolvedPath); exists && ok && cached.inode == inode && cached.mtime == mtime && cached.size == size {
		h.hex = cached.hex
		return h.hex, nil
	}

	// Cache miss or stat changed: compute hash from disk
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

	globalHashCache.Add(resolvedPath, cachedHash{
		hex:   computedHex,
		inode: inode,
		mtime: mtime,
		size:  size,
	})

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
