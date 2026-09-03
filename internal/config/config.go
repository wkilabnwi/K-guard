// Package config loads and hot-reloads K-Guard's rule/policy configuration
// from a JSON file
//
// JSON was chosen over because i feel much more comfortable handling it
// changing to YAML isn't that hard you only need to change a couple things
package config

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func checkConfigPermissionsFD(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("fstat %s: %w", f.Name(), err)
	}

	mode := fi.Mode()
	if mode&0022 != 0 {
		return fmt.Errorf("refusing to load %s: writable by group and/or other (mode %04o), "+
			"run e.g. chmod 600 %s", f.Name(), mode.Perm(), f.Name())
	}

	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if uid := os.Getuid(); uid != 0 && int(st.Uid) != uid {
			return fmt.Errorf("refusing to load %s: owned by uid %d, not the uid K-Guard is running as (%d)", f.Name(), st.Uid, uid)
		}
	}

	return nil
}

// Load reads, parses, defaults, and validates a config file in one shot
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config %s: %w", path, err)
	}
	defer f.Close()

	if err := checkConfigPermissionsFD(f); err != nil {
		return nil, err
	}

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return &c, nil
}

type Manager struct {
	path    string
	current atomic.Pointer[Config]

	mu          sync.Mutex
	lastMod     time.Time
	subscribers []func(*Config)
}

func NewManager(path string) (*Manager, error) {
	c, err := Load(path)
	if err != nil {
		return nil, err
	}
	m := &Manager{path: path}
	m.current.Store(c)
	if fi, err := os.Stat(path); err == nil {
		m.lastMod = fi.ModTime()
	}
	return m, nil
}

// Current returns the currently active config
func (m *Manager) Current() *Config {
	return m.current.Load()
}

// OnChange registers a callback invoked with the new config every time a
// reload succeeds (from ReloadNow or the polling loop)
func (m *Manager) OnChange(fn func(*Config)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subscribers = append(m.subscribers, fn)
}

// ReloadNow rereads the config file immediately, On failure, the previously loaded config is
// left untouched and the error is returned for the caller to log.
func (m *Manager) ReloadNow() error {
	old := m.current.Load()

	c, err := Load(m.path)
	if err != nil {
		return err
	}
	m.current.Store(c)
	m.mu.Lock()
	if fi, statErr := os.Stat(m.path); statErr == nil {
		m.lastMod = fi.ModTime()
	}
	m.mu.Unlock()

	if old != nil {
		if changes := diffConfig(old, c); len(changes) > 0 {
			log.Printf("[config] reload applied %d change(s):", len(changes))
			for _, ch := range changes {
				log.Printf("[config] : %s", ch)
			}
		} else {
			log.Printf("[config] reload: file changed but no effective policy differences detected")
		}
	}

	m.notify(c)
	return nil
}

func (m *Manager) notify(c *Config) {
	m.mu.Lock()
	subs := make([]func(*Config), len(m.subscribers))
	copy(subs, m.subscribers)
	m.mu.Unlock()
	for _, fn := range subs {
		fn(c)
	}
}

// WatchPoll starts a background goroutine that checks the config file's
// mtime every interval and calls ReloadNow if it changed, stops when
// 'stop' is closed.
func (m *Manager) WatchPoll(interval time.Duration, stop <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				fi, err := os.Stat(m.path)
				if err != nil {
					log.Printf("[config] stat %s: %v", m.path, err)
					continue
				}

				m.mu.Lock()
				changed := fi.ModTime().After(m.lastMod)
				m.mu.Unlock()

				if changed {
					log.Printf("[config] change detected in %s, reloading", m.path)
					if err := m.ReloadNow(); err != nil {
						log.Printf("[config] reload FAILED, keeping previous config: %v", err)
					} else {
						log.Printf("[config] reload succeeded")
					}
				}
			}
		}
	}()
}
