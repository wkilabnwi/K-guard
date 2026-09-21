package audit

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type Decision string

const (
	DecisionBlock Decision = "BLOCK"
	DecisionKill  Decision = "KILL"
	DecisionAlert Decision = "ALERT"
)

type Record struct {
	Timestamp time.Time
	Decision  Decision
	EventType string
	RuleName  string
	PID       uint32
	PPID      uint32
	UID       uint32
	Comm      string
	CgroupID  uint64
	Target    string
	Reason    string
}

type Logger struct {
	ch   chan Record
	file *os.File
	done chan struct{}
}

func NewLogger(path string) (*Logger, error) {
	if path == "" {
		path = "/var/log/kguard/audit.log"
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}

	l := &Logger{
		ch:   make(chan Record, 10000), // Non-blocking queue for up to 10k in-flight events
		file: f,
		done: make(chan struct{}),
	}

	go l.worker()
	return l, nil
}

// Log pushes the record to the channel
func (l *Logger) Log(rec Record) {
	if l == nil {
		return
	}
	rec.Timestamp = time.Now().UTC()
	select {
	case l.ch <- rec:
	default:
		// Drop under extreme, improbable queue overflow to protect engine latency
	}
}

// Background worker: zero-allocation JSON formatting + 64KB batched disk writes
func (l *Logger) worker() {
	defer close(l.done)
	w := bufio.NewWriterSize(l.file, 64*1024)
	defer w.Flush()

	// Pre-allocated scratch buffer reused across all events
	buf := make([]byte, 0, 512)

	for rec := range l.ch {
		buf = buf[:0] // Reset buffer header without re-allocating memory

		buf = append(buf, `{"timestamp":"`...)
		buf = append(buf, rec.Timestamp.Format(time.RFC3339Nano)...)
		buf = append(buf, `","decision":"`...)
		buf = append(buf, rec.Decision...)
		buf = append(buf, `","event_type":"`...)
		buf = append(buf, rec.EventType...)
		buf = append(buf, '"')

		if rec.RuleName != "" {
			buf = append(buf, `,"rule_name":`...)
			buf = strconv.AppendQuote(buf, rec.RuleName)
		}

		buf = append(buf, `,"pid":`...)
		buf = strconv.AppendUint(buf, uint64(rec.PID), 10)
		buf = append(buf, `,"ppid":`...)
		buf = strconv.AppendUint(buf, uint64(rec.PPID), 10)
		buf = append(buf, `,"uid":`...)
		buf = strconv.AppendUint(buf, uint64(rec.UID), 10)
		buf = append(buf, `,"comm":`...)
		buf = strconv.AppendQuote(buf, rec.Comm)
		buf = append(buf, `,"cgroup_id":`...)
		buf = strconv.AppendUint(buf, rec.CgroupID, 10)

		if rec.Target != "" {
			buf = append(buf, `,"target":`...)
			buf = strconv.AppendQuote(buf, rec.Target)
		}

		buf = append(buf, `,"reason":`...)
		buf = strconv.AppendQuote(buf, rec.Reason)
		buf = append(buf, "}\n"...)

		w.Write(buf)
	}
}

func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	close(l.ch)
	<-l.done
	return l.file.Close()
}
