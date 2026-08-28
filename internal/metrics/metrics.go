package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
)

type RuleHitKey struct {
	Rule     string
	Severity string
	Action   string
}

// Registry holds every counter K-Guard tracks. All operations are
// atomic on the hot path except for the label maps, which
// take a mutex only on first-seen-label creation.
type Registry struct {
	eventsTotal          map[string]*int64
	eventsMu             sync.Mutex
	ruleHitsTotal        map[RuleHitKey]*int64
	ruleHitsMu           sync.Mutex
	killsTotal           int64
	killErrorsTotal      int64
	blocksTotal          int64
	ringbufDropsTotal    int64
	sinkErrorsTotal      map[string]*int64
	sinkErrorsMu         sync.Mutex
	hashCheckErrorsTotal int64
	sinkDropsTotal       map[string]*int64
	sinkDropsMu          sync.Mutex
}

func NewRegistry() *Registry {
	return &Registry{
		eventsTotal:     map[string]*int64{},
		ruleHitsTotal:   map[RuleHitKey]*int64{},
		sinkErrorsTotal: map[string]*int64{},
		sinkDropsTotal:  map[string]*int64{},
	}
}

func bump(m map[string]*int64, mu *sync.Mutex, key string) {
	mu.Lock()
	p, ok := m[key]
	if !ok {
		var v int64
		p = &v
		m[key] = p
	}
	mu.Unlock()
	atomic.AddInt64(p, 1)
}

func (r *Registry) IncHashCheckError()        { atomic.AddInt64(&r.hashCheckErrorsTotal, 1) }
func (r *Registry) IncEvent(eventType string) { bump(r.eventsTotal, &r.eventsMu, eventType) }
func (r *Registry) IncRuleHit(ruleName, severity, action string) {
	key := RuleHitKey{
		Rule:     ruleName,
		Severity: severity,
		Action:   action,
	}
	r.ruleHitsMu.Lock()
	p, ok := r.ruleHitsTotal[key]
	if !ok {
		var v int64
		p = &v
		r.ruleHitsTotal[key] = p
	}
	r.ruleHitsMu.Unlock()
	atomic.AddInt64(p, 1)
}
func (r *Registry) IncKill()                 { atomic.AddInt64(&r.killsTotal, 1) }
func (r *Registry) IncKillError()            { atomic.AddInt64(&r.killErrorsTotal, 1) }
func (r *Registry) IncBlock()                { atomic.AddInt64(&r.blocksTotal, 1) }
func (r *Registry) IncRingbufDrop()          { atomic.AddInt64(&r.ringbufDropsTotal, 1) }
func (r *Registry) IncSinkError(sink string) { bump(r.sinkErrorsTotal, &r.sinkErrorsMu, sink) }
func (r *Registry) IncSinkDrop(sink string)  { bump(r.sinkDropsTotal, &r.sinkDropsMu, sink) }

// Handler returns an http.Handler serving Prometheus text exposition
// format at whatever path it's mounted on
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")

		fmt.Fprintln(w, "# HELP kguard_events_total Total kernel events observed, by event_type.")
		fmt.Fprintln(w, "# TYPE kguard_events_total counter")
		writeLabeled(w, "kguard_events_total", "event_type", r.eventsTotal, &r.eventsMu)

		fmt.Fprintln(w, "# HELP kguard_rule_hits_total Total rule matches, by rule name, severity, and action.")
		fmt.Fprintln(w, "# TYPE kguard_rule_hits_total counter")
		r.writeRuleHits(w)

		fmt.Fprintln(w, "# HELP kguard_kills_total Total SIGKILLs issued in response to a KILL-action rule.")
		fmt.Fprintln(w, "# TYPE kguard_kills_total counter")
		fmt.Fprintf(w, "kguard_kills_total %d\n", atomic.LoadInt64(&r.killsTotal))

		fmt.Fprintln(w, "# HELP kguard_kill_errors_total Total failed kill attempts (protected pid, already exited, permission denied).")
		fmt.Fprintln(w, "# TYPE kguard_kill_errors_total counter")
		fmt.Fprintf(w, "kguard_kill_errors_total %d\n", atomic.LoadInt64(&r.killErrorsTotal))

		fmt.Fprintln(w, "# HELP kguard_blocks_total Total execs actually prevented pre-flight by the LSM hook.")
		fmt.Fprintln(w, "# TYPE kguard_blocks_total counter")
		fmt.Fprintf(w, "kguard_blocks_total %d\n", atomic.LoadInt64(&r.blocksTotal))

		fmt.Fprintln(w, "# HELP kguard_ringbuf_drops_total Total ring buffer read errors (possible event loss).")
		fmt.Fprintln(w, "# TYPE kguard_ringbuf_drops_total counter")
		fmt.Fprintf(w, "kguard_ringbuf_drops_total %d\n", atomic.LoadInt64(&r.ringbufDropsTotal))

		fmt.Fprintln(w, "# HELP kguard_sink_errors_total Total alert delivery failures, by sink.")
		fmt.Fprintln(w, "# TYPE kguard_sink_errors_total counter")
		writeLabeled(w, "kguard_sink_errors_total", "sink", r.sinkErrorsTotal, &r.sinkErrorsMu)

		fmt.Fprintln(w, "# HELP kguard_hash_check_errors_total Total SHA256 rule checks that could not be completed (e.g. process exited before the binary could be read).")
		fmt.Fprintln(w, "# TYPE kguard_hash_check_errors_total counter")
		fmt.Fprintf(w, "kguard_hash_check_errors_total %d\n", atomic.LoadInt64(&r.hashCheckErrorsTotal))
	})
}

func writeLabeled(w http.ResponseWriter, metric, label string, m map[string]*int64, mu *sync.Mutex) {
	mu.Lock()
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	vals := make([]int64, len(keys))
	for i, k := range keys {
		vals[i] = atomic.LoadInt64(m[k])
	}
	mu.Unlock()

	for i, k := range keys {
		fmt.Fprintf(w, "%s{%s=%q} %d\n", metric, label, k, vals[i])
	}
}

func (r *Registry) writeRuleHits(w http.ResponseWriter) {
	r.ruleHitsMu.Lock()
	type item struct {
		key RuleHitKey
		val int64
	}
	items := make([]item, 0, len(r.ruleHitsTotal))
	for k, v := range r.ruleHitsTotal {
		items = append(items, item{key: k, val: atomic.LoadInt64(v)})
	}
	r.ruleHitsMu.Unlock()

	sort.Slice(items, func(i, j int) bool {
		if items[i].key.Rule != items[j].key.Rule {
			return items[i].key.Rule < items[j].key.Rule
		}
		if items[i].key.Severity != items[j].key.Severity {
			return items[i].key.Severity < items[j].key.Severity
		}
		return items[i].key.Action < items[j].key.Action
	})

	for _, it := range items {
		fmt.Fprintf(w, "kguard_rule_hits_total{rule=%q,severity=%q,action=%q} %d\n",
			it.key.Rule, it.key.Severity, it.key.Action, it.val)
	}
}
