package processor

import (
	"sync"
	"time"
)

// Correlator keeps a short lived memory per Pid of recent exec context so
// that other sensors (for now it's just connect()) can ask "did this PID recently
// exec from a suspicious location?" and escalate accordingly.
// a lot of programs run execve(), the same thing is true for connect()
// but running them in a very short window is much more suspicious
type Correlator struct {
	mu     sync.Mutex
	window time.Duration
	execs  map[uint32]execContext
}

type execContext struct {
	filename   string
	suspicious bool
	at         time.Time
}

func NewCorrelator(window time.Duration) *Correlator {
	return &Correlator{window: window, execs: map[uint32]execContext{}}
}

// RecordExec should be called for every observed exec (whether or not it
// matched a rule) so later events from the same Pid can reference it
// a sweep to delete old information happens when the map exceeds 4096 entries
func (c *Correlator) RecordExec(pid uint32, filename string, suspiciousPath bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.execs[pid] = execContext{filename: filename, suspicious: suspiciousPath, at: time.Now()}

	if len(c.execs) > 4096 {
		now := time.Now()
		for k, v := range c.execs {
			if now.Sub(v.at) > c.window {
				delete(c.execs, k)
			}
		}
	}
}

// CorrelateConnect reports whether Pid recently exec'd from a suspicious path
// returning that exec's filename for inclusion in the resulting alert's detail.
func (c *Correlator) CorrelateConnect(pid uint32) (suspicious bool, execFilename string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx, ok := c.execs[pid]
	if !ok || time.Since(ctx.at) > c.window {
		return false, ""
	}
	return ctx.suspicious, ctx.filename
}
