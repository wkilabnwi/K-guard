package processor

import (
	"fmt"
	"strings"
	"time"
)

type ProcessNode struct {
	Pid      uint32
	Ppid     uint32
	Comm     string
	Filename string
	At       time.Time
}

// Correlator keeps a short lived memory per Pid of recent exec context so
// that other sensorscan ask "did this PID recently
// exec from a suspicious location?" and escalate accordingly
// a lot of programs run execve(), the same thing is true for connect()
// but running them in a very short window is much more suspicious
type Correlator struct {
	window time.Duration
	cache  *lruCache[uint32, ProcessNode]
}

func NewCorrelator(window time.Duration) *Correlator {
	return &Correlator{window: window,
		cache: newLRUCache[uint32, ProcessNode](1000)}
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

		sb.WriteString(fmt.Sprintf("\n       %s [PID %d] %s", prefix, n.Pid, name))
	}

	return sb.String()
}
