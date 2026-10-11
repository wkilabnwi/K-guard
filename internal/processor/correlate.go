package processor

import (
	"fmt"
	"k-guard/internal/trust"
	"net"
	"strings"
	"time"
)

type fileWriteRecord struct {
	writtenAt  time.Time
	writerPID  uint32
	writerComm string
}

type ProcessNode struct {
	Pid      uint32
	Ppid     uint32
	Comm     string
	Filename string
	At       time.Time
}

type ipRecord struct {
	domain string
	at     time.Time
}

type ipKey struct {
	cgroupID uint64
	ip       string
}

// Correlator keeps a short lived memory per Pid of recent exec context so
// that other sensorscan ask "did this PID recently
// exec from a suspicious location?" and escalate accordingly
// a lot of programs run execve(), the same thing is true for connect()
// but running them in a very short window is much more suspicious
type Correlator struct {
	window           time.Duration
	cache            *lruCache[uint32, ProcessNode]
	ipScoped         *lruCache[ipKey, ipRecord]
	ipFallback       *lruCache[string, ipRecord]
	recentPathWrites *lruCache[string, fileWriteRecord]
	recentIDWrites   *lruCache[trust.FileID, fileWriteRecord]
}

func NewCorrelator(window time.Duration) *Correlator {
	return &Correlator{window: window,
		cache:            newLRUCache[uint32, ProcessNode](1000),
		ipScoped:         newLRUCache[ipKey, ipRecord](5000),
		ipFallback:       newLRUCache[string, ipRecord](5000),
		recentPathWrites: newLRUCache[string, fileWriteRecord](2000),
		recentIDWrites:   newLRUCache[trust.FileID, fileWriteRecord](2000),
	}
}

// RecordExec should be called for every observed exec (whether or not it
// matched a rule) so later events from the same Pid can reference it
func (c *Correlator) RecordExec(pid, ppid uint32, comm, filename string) {
	c.cache.Add(pid, ProcessNode{
		Pid:      pid,
		Ppid:     ppid,
		Comm:     comm,
		Filename: filename,
		At:       time.Now(),
	})
}

func (c *Correlator) BuildTree(startPid uint32) []ProcessNode {
	var tree []ProcessNode
	visited := make(map[uint32]bool)
	curr := startPid

	for curr > 1 {
		// for safety cause we never know what might happen inside a kernel
		if visited[curr] {
			break
		}
		visited[curr] = true

		node, ok := c.cache.Get(curr)
		if !ok {
			break
		}

		tree = append(tree, node)
		curr = node.Ppid
	}

	return tree
}

func (c *Correlator) FormatTree(startPid uint32) string {
	nodes := c.BuildTree(startPid)
	if len(nodes) == 0 {
		return ""
	}

	// I used Strings builder here because normal strings are immutable
	// could've done it with normal concat but why not optomize ?
	var sb strings.Builder

	// Walk backwards (root ancestor down to target process)
	for i := len(nodes) - 1; i >= 0; i-- {
		n := nodes[i]
		prefix := "|--"
		if i == 0 {
			prefix = "'--"
		}

		name := n.Filename
		if name == "" {
			name = n.Comm
		}

		fmt.Fprintf(&sb, "\n       %s [PID %d] %s", prefix, n.Pid, name)
	}

	return sb.String()
}

func (c *Correlator) RecordIPDomain(cgroupID uint64, ip, domain string) {
	if ip == "" || domain == "" {
		return
	}
	ip = normalizeIP(ip)
	rec := ipRecord{domain: domain, at: time.Now()}
	c.ipScoped.Add(ipKey{cgroupID, ip}, rec)
	c.ipFallback.Add(ip, rec)
}

func (c *Correlator) GetDomainByIP(cgroupID uint64, ip string) (string, bool) {
	ip = normalizeIP(ip)
	if rec, ok := c.ipScoped.Get(ipKey{cgroupID, ip}); ok && time.Since(rec.at) <= 5*time.Minute {
		return rec.domain, true
	}
	if rec, ok := c.ipFallback.Get(ip); ok && time.Since(rec.at) <= 5*time.Minute {
		return rec.domain, false
	}
	return "", false
}

func normalizeIP(ip string) string {
	ip = strings.TrimSuffix(strings.TrimPrefix(ip, "["), "]")
	if parsed := net.ParseIP(ip); parsed != nil {
		return parsed.String()
	}
	return ip
}

// RecordFileWrite stores write event context by both path and FileID (if available)
func (c *Correlator) RecordFileWrite(path string, id trust.FileID, pid uint32, comm string) {
	rec := fileWriteRecord{
		writtenAt:  time.Now(),
		writerPID:  pid,
		writerComm: comm,
	}

	if path != "" {
		c.recentPathWrites.Add(path, rec)
	}
	if id.Dev != 0 || id.Ino != 0 {
		c.recentIDWrites.Add(id, rec)
	}
}

// GetRecentWrite queries recent write history by FileID first, then falls back to Path
func (c *Correlator) GetRecentWrite(path string, id trust.FileID, within time.Duration) (fileWriteRecord, bool) {
	if id.Dev != 0 || id.Ino != 0 {
		if rec, ok := c.recentIDWrites.Get(id); ok && time.Since(rec.writtenAt) <= within {
			return rec, true
		}
	}

	if path != "" {
		if rec, ok := c.recentPathWrites.Get(path); ok && time.Since(rec.writtenAt) <= within {
			return rec, true
		}
	}

	return fileWriteRecord{}, false
}
