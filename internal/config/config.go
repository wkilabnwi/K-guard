// Package config loads and hot-reloads K-Guard's rule/policy configuration
// from a yaml file
//
// JSON was chosen over because i feel much more comfortable handling it
// changing to YAML isn't that hard you only need to change a couple things
// (no more JSON now lmao)
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	pb "k-guard/internal/pb"

	"cel.dev/cel-go/cel"
	"go.yaml.in/yaml/v3"
)

var (
	exactPathRe  = regexp.MustCompile(`^\s*process\.path\s*==\s*(?:'([^'\\]+)'|"([^"\\]+)")\s*$`)
	prefixPathRe = regexp.MustCompile(`^\s*process\.path\.startsWith\(\s*(?:'([^'\\]+)'|"([^"\\]+)")\s*\)\s*$`)
)

func firstGroup(m []string) string {
	for _, g := range m[1:] {
		if g != "" {
			return g
		}
	}
	return ""
}

var (
	celEnv  *cel.Env
	celErr  error
	celOnce sync.Once
)

// GetCELEnvironment returns the singleton CEL environment instance
func GetCELEnvironment() (*cel.Env, error) {
	celOnce.Do(func() {
		celEnv, celErr = cel.NewEnv(
			cel.Types(&pb.EventContext{}, &pb.ProcessContext{}),
			cel.Variable("event", cel.ObjectType("kguard.EventContext")),
			cel.Variable("process", cel.ObjectType("kguard.ProcessContext")),
		)
	})
	return celEnv, celErr
}

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

	if !fi.Mode().IsRegular() {
		return fmt.Errorf("refusing to load %s: not a regular file", f.Name())
	}

	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if uid := os.Getuid(); uid != 0 && int(st.Uid) != uid {
			return fmt.Errorf("refusing to load %s: owned by uid %d, not running uid (%d)", f.Name(), st.Uid, uid)
		}
	}
	return nil
}

const maxConfigBytes = 1 << 20

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	if err := checkConfigPermissionsFD(f); err != nil {
		return nil, err
	}

	b, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	if len(b) > maxConfigBytes {
		return nil, fmt.Errorf("config %s exceeds %d bytes", path, maxConfigBytes)
	}

	c, err := parseConfig(b, strings.ToLower(filepath.Ext(path)))
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return c, nil
}

func parseConfig(b []byte, ext string) (*Config, error) {
	env, err := GetCELEnvironment()
	if err != nil {
		return nil, fmt.Errorf("building CEL env: %w", err)
	}

	var c Config
	switch ext {
	case ".json":
		err = decodeJSON(b, &c)
	case ".yaml", ".yml":
		err = decodeYAML(b, &c)
	default:
		if yerr := decodeYAML(b, &c); yerr != nil {
			c = Config{}
			if jerr := decodeJSON(b, &c); jerr != nil {
				return nil, fmt.Errorf("not valid YAML (%v) or JSON (%v)", yerr, jerr)
			}
		}
	}
	if err != nil {
		return nil, err
	}

	c.applyDefaults()
	if err := c.Validate(env); err != nil {
		return nil, fmt.Errorf("invalid: %w", err)
	}
	return &c, nil
}

func decodeJSON(b []byte, c *Config) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(c)
}

func decodeYAML(b []byte, c *Config) error {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	return dec.Decode(c)
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
			slog.Info("config reload applied policy changes", "component", "config", "count", len(changes))
			for _, ch := range changes {
				slog.Info("policy diff", "component", "config", "change", ch)
			}
		} else {
			slog.Info("config file changed but no effective policy differences detected", "component", "config")
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
	for i, fn := range subs {
		func(index int, subscriber func(*Config)) {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("CRITICAL: config subscriber panicked during reload notification",
						"component", "config",
						"subscriber_index", index,
						"panic", r,
					)
				}
			}()
			subscriber(c)
		}(i, fn)
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
					slog.Warn("config stat failed", "component", "config", "path", m.path, "error", err)
					continue
				}

				m.mu.Lock()
				changed := fi.ModTime().After(m.lastMod)
				m.mu.Unlock()

				if changed {
					slog.Info("config file change detected, reloading", "component", "config", "path", m.path)
					if err := m.ReloadNow(); err != nil {
						slog.Error("config reload FAILED, keeping previous configuration", "component", "config", "error", err)
					} else {
						slog.Info("config reload succeeded", "component", "config")
					}
				}
			}
		}
	}()
}
