// Package alert defines the Alert record K-Guard emits for anything
// noteworthy so the same alert can fan out to stdout, syslog, a
// webhook, and a JSON-lines store simultaneously.
package alert

import (
	"io"
	"k-guard/internal/config"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// Alert is a single normalized security event, independent of which
// eBPF hook produced it.
type Alert struct {
	Timestamp time.Time `json:"timestamp"`

	RuleName string            `json:"rule_name,omitempty"` // empty for raw sensor events not tied to a named rule
	Mitre    *config.MitreMeta `json:"mitre,omitempty"`
	Mode     string            `json:"mode,omitempty"`
	Severity string            `json:"severity"`
	Action   string            `json:"action"`
	Blocked  bool              `json:"blocked"` // true if the LSM hook actually prevented the exec

	EventType string `json:"event_type"`

	Pid      uint32 `json:"pid"`
	Ppid     uint32 `json:"ppid,omitempty"`
	Uid      uint32 `json:"uid"`
	Gid      uint32 `json:"gid,omitempty"`
	Comm     string `json:"comm"`
	CgroupID uint64 `json:"cgroup_id,omitempty"`

	Filename string `json:"filename,omitempty"`
	Args     string `json:"args,omitempty"`

	DestIP   string `json:"dest_ip,omitempty"`
	DestPort uint16 `json:"dest_port,omitempty"`

	// Lineage fields
	AncestorSuspicious bool   `json:"ancestor_suspicious,omitempty"`
	AncestorFilename   string `json:"ancestor_filename,omitempty"`
	LineageTree        string `json:"lineage_tree,omitempty"`

	// Free form extra detail
	Detail        string `json:"detail,omitempty"`
	PathTruncated bool   `json:"path_truncated,omitempty"`
	IsFileless    bool   `json:"is_fileless,omitempty"`

	// ResponseErr records why an intended KILL action didn't happen, kept on the alert itself so it
	// shows up in the store/dashboard rather than only in logs.
	ResponseErr string `json:"response_error,omitempty"`

	// k8s specific fields
	ContainerID string `json:"container_id,omitempty"`
	PodName     string `json:"pod_name,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	PodUID      string `json:"pod_uid,omitempty"`
	Runtime     string `json:"runtime,omitempty"`
}

// Sink is anything that can receive alerts. DElivery became async because
// one hung sink would otherwise hang up everything with it
type Sink interface {
	Name() string
	Send(a Alert)
}

// sinkWorker owns one sink's queue and delivery goroutine, so a slow or
// stuck sink only ever affects itself, never the ring buffer reader loop
// upstream, and never other sinks
type sinkWorker struct {
	sink  Sink
	queue chan Alert
	drops func()
}

// queueDepth bounds how many alerts a sink is allowed to lag behind by
// before Dispatch starts dropping for it
const queueDepth = 256

func newSinkWorker(s Sink, onDrop func()) *sinkWorker {
	w := &sinkWorker{sink: s, queue: make(chan Alert, queueDepth), drops: onDrop}
	return w
}

func (w *sinkWorker) run() {
	for a := range w.queue {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[alert] sink %s panicked: %v", w.sink.Name(), r)
				}
			}()
			w.sink.Send(a)
		}()
	}
}

// enqueue is non-blocking so if the sink is backed up, the alert is dropped
// for that sink only, rather than blocking Dispatch
func (w *sinkWorker) enqueue(a Alert) {
	select {
	case w.queue <- a:
	default:
		if w.drops != nil {
			w.drops()
		}
		log.Printf("[alert] sink %s queue full, dropping alert (pid=%d rule=%s)", w.sink.Name(), a.Pid, a.RuleName)
	}
}

type Dispatcher struct {
	mu      sync.RWMutex
	workers []*sinkWorker
	closed  bool
	wg      sync.WaitGroup

	// onDrop is read from sink queues while OnDrop may be called concurrently,
	// so it lives in an atomic rather than behind mu (Dispatch holds mu.RLock
	// while enqueueing, and re-locking in the callback could deadlock).
	onDrop atomic.Pointer[func(sink string)]
}

func NewDispatcher() *Dispatcher {
	return &Dispatcher{}
}

// OnDrop registers a callback invoked (sink name) whenever an alert is
// dropped due to that sink's queue being full
func (d *Dispatcher) OnDrop(fn func(sink string)) {
	d.onDrop.Store(&fn)
}

func (d *Dispatcher) Register(s Sink) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}

	name := s.Name()
	w := newSinkWorker(s, func() {
		if fn := d.onDrop.Load(); fn != nil && *fn != nil {
			(*fn)(name)
		}
	})
	d.workers = append(d.workers, w)

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		w.run()
	}()
}

// Dispatch enqueues the alert to every sink and returns immediately
func (d *Dispatcher) Dispatch(a Alert) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return
	}
	for _, w := range d.workers {
		w.enqueue(a)
	}
}

// Close drains and stops all sink workers
func (d *Dispatcher) Close() {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	workers := make([]*sinkWorker, len(d.workers))
	copy(workers, d.workers)
	for _, w := range workers {
		close(w.queue)
	}
	d.mu.Unlock()

	d.wg.Wait()

	for _, w := range workers {
		if c, ok := w.sink.(io.Closer); ok {
			if err := c.Close(); err != nil {
				log.Printf("[alert] sink %s close error: %v", w.sink.Name(), err)
			}
		}
	}
}
