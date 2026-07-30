package processor

import (
	"sync"
	"time"
)

// Deduper suppresses repeat alerts for the same event within a specified
// window, for example the same rule firing for the same PID every time it
// touches a file in a tight loop. A window of 0 disables suppression
// entirely
type Deduper struct {
	mu     sync.Mutex
	window time.Duration
	last   map[string]time.Time
}

func NewDeduper(window time.Duration) *Deduper {
	return &Deduper{window: window, last: map[string]time.Time{}}
}

func (d *Deduper) SetWindow(window time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.window = window
}

// Allow reports whether an alert with this key should be emitted or not
// It also periodically removes expired entries (every 2048 calls) so the map
// doesn't grow unbounded
func (d *Deduper) Allow(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.window <= 0 {
		return true
	}

	now := time.Now()
	if last, ok := d.last[key]; ok && now.Sub(last) < d.window {
		return false
	}
	d.last[key] = now

	if len(d.last) > 2048 {
		for k, t := range d.last {
			if now.Sub(t) > d.window {
				delete(d.last, k)
			}
		}
	}
	return true
}
