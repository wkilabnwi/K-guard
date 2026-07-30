package alert

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Store is append-only, daily-rotated JSON-Lines event history
// one alert per line, one file per calendar day (alerts-YYYY-MM-DD.jsonl in dir
type Store struct {
	mu      sync.Mutex
	dir     string
	prefix  string
	curDate string
	f       *os.File
}

func (*Store) Name() string { return "store" }

// NewStore ensures dir exists and opens (or creates) today's file
func NewStore(dir string) (*Store, error) {
	s := &Store{dir: dir, prefix: "alerts"}
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, err
	}
	if err := s.rotateIfNeeded(); err != nil {
		return nil, err
	}
	return s, nil
}

// pathFor returns the on-disk path for a given date's file
func (s *Store) pathFor(date string) string {
	return filepath.Join(s.dir, fmt.Sprintf("%s-%s.jsonl", s.prefix, date))
}

// rotateIfNeeded closes the current file and opens a new one if the
// calendar date has changed since the last write, caller must hold s.mu
func (s *Store) rotateIfNeeded() error {
	today := time.Now().Format("2006-01-02")
	if today == s.curDate && s.f != nil {
		return nil
	}
	if s.f != nil {
		s.f.Close()
	}
	f, err := os.OpenFile(s.pathFor(today), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	s.f, s.curDate = f, today
	return nil
}

func (s *Store) Send(a Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.rotateIfNeeded(); err != nil {
		return
	}
	line, err := json.Marshal(a)
	if err != nil {
		return
	}
	line = append(line, '\n')
	_, _ = s.f.Write(line)
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// Recent returns up to 'limit' most recent alerts (newest last), reading
// backwards from the newest daily file until enough alerts are collected
func (s *Store) Recent(limit int) ([]Alert, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), s.prefix+"-") && strings.HasSuffix(e.Name(), ".jsonl") {
			files = append(files, filepath.Join(s.dir, e.Name()))
		}
	}
	sort.Strings(files) // filenames are date-prefixed

	var all []Alert
	for i := len(files) - 1; i >= 0 && len(all) < limit; i-- {
		alerts, err := readAlertsFile(files[i])
		if err != nil {
			continue // skip unreadable/corrupt day rather than failing the whole read
		}
		all = append(alerts, all...) // older file's alerts go first
	}
	if len(all) > limit {
		all = all[len(all)-limit:]
	}
	return all, nil
}

// CountBySeverity returns a tally of alerts per severity across the whole
// stored history
func (s *Store) CountBySeverity() (map[string]int, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), s.prefix+"-") || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		alerts, err := readAlertsFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			continue
		}
		for _, a := range alerts {
			counts[a.Severity]++
		}
	}
	return counts, nil
}

// readAlertsFile reads and parses every alert in a single daily file,
// shared by Recent and CountBySeverity
func readAlertsFile(path string) ([]Alert, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var all []Alert
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var a Alert
		if err := json.Unmarshal(sc.Bytes(), &a); err != nil {
			continue
		}
		all = append(all, a)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return all, nil
}
