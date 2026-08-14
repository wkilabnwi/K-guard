// Package alert defines the Alert record K-Guard emits for anything
// noteworthy so the same alert can fan out to stdout, syslog, a
// webhook, and a JSON-lines store simultaneously.
package alert

import (
	"log"
	"sync"
	"time"
)

// Alert is a single normalized security event, independent of which
// eBPF hook produced it.
type Alert struct {
	Timestamp time.Time `json:"timestamp"`

	RuleName string `json:"rule_name,omitempty"` // empty for raw sensor events not tied to a named rule
	Severity string `json:"severity"`
	Action   string `json:"action"`
	Blocked  bool   `json:"blocked"` // true if the LSM hook actually prevented the exec

	EventType string `json:"event_type"`

	Pid      uint32 `json:"pid"`
	Ppid     uint32 `json:"ppid,omitempty"`
	Uid      uint32 `json:"uid"`
	Gid      uint32 `json:"gid,omitempty"`
	Comm     string `json:"comm"`
	CgroupID uint64 `json:"cgroup_id,omitempty"`

	Filename string `json:"filename,omitempty"`
	Argv0    string `json:"argv0,omitempty"`

	DestIP   string `json:"dest_ip,omitempty"`
	DestPort uint16 `json:"dest_port,omitempty"`

	// Lineage fields
	AncestorSuspicious bool   `json:"ancestor_suspicious,omitempty"`
	AncestorFilename   string `json:"ancestor_filename,omitempty"`

	// Free form extra detail
	Detail        string `json:"detail,omitempty"`
	PathTruncated bool   `json:"path_truncated,omitempty"`

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
	onDrop  func(sink string)
	wg      sync.WaitGroup
}

func NewDispatcher() *Dispatcher {
	return &Dispatcher{}
}

// OnDrop registers a callback invoked (sink name) whenever an alert is
// dropped due to that sink's queue being full
func (d *Dispatcher) OnDrop(fn func(sink string)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.onDrop = fn
}

func (d *Dispatcher) Register(s Sink) {
	d.mu.Lock()
	defer d.mu.Unlock()
	name := s.Name()
	w := newSinkWorker(s, func() {
		if d.onDrop != nil {
			d.onDrop(name)
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
	workers := make([]*sinkWorker, len(d.workers))
	copy(workers, d.workers)
	d.mu.RUnlock()

	for _, w := range workers {
		w.enqueue(a)
	}
}

// Close drains and stops all sink workers
func (d *Dispatcher) Close() {
	d.mu.Lock()
	for _, w := range d.workers {
		close(w.queue)
	}
	d.mu.Unlock()
	d.wg.Wait()
}
