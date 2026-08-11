package processor

import (
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"k-guard/internal/alert"
	"k-guard/internal/config"
	"k-guard/internal/ebpf"
	"k-guard/internal/metrics"
	"k-guard/internal/safety"
)

type Engine struct {
	cfg        *config.Manager
	guard      *safety.Guard
	dispatcher *alert.Dispatcher
	metrics    *metrics.Registry
	ebpfMgr    *ebpf.Manager

	dedup      *Deduper
	correlator *Correlator
}

func NewEngine(cfg *config.Manager, guard *safety.Guard, dispatcher *alert.Dispatcher, m *metrics.Registry, mgr *ebpf.Manager) *Engine {
	e := &Engine{
		cfg:        cfg,
		guard:      guard,
		dispatcher: dispatcher,
		metrics:    m,
		ebpfMgr:    mgr,
		dedup:      NewDeduper(time.Duration(cfg.Current().DedupWindowSeconds) * time.Second),
		correlator: NewCorrelator(10 * time.Second),
	}

	// Apply the initial config, then keep re-applying on every hot reload
	e.applyConfig(cfg.Current())
	cfg.OnChange(e.applyConfig)

	return e
}

func (e *Engine) applyConfig(c *config.Config) {
	e.dedup.SetWindow(time.Duration(c.DedupWindowSeconds) * time.Second)
	e.guard.SetProtected(c.ProtectedPIDs, c.ProtectedComms)

	if e.ebpfMgr == nil {
		return
	}
	if err := e.ebpfMgr.SyncBlockedPaths(c.BlockedPatterns()); err != nil {
		log.Printf("[engine] failed to sync LSM block-list: %v", err)
	}
	if err := e.ebpfMgr.SyncSuspiciousPaths(c.SuspiciousPaths); err != nil {
		log.Printf("[engine] failed to sync Suspicious Paths: %v", err)
	}
	if err := e.ebpfMgr.SyncSensitiveWritePaths(c.SensitiveWritePaths); err != nil {
		log.Printf("[engine] failed to sync Suspicious write Paths: %v", err)
	}
	wantEnforcement := c.EnforcementEnabled && e.ebpfMgr.LSMEnabled
	if c.EnforcementEnabled && !e.ebpfMgr.LSMEnabled {
		log.Printf("[engine] config requests enforcement_enabled=true, but the LSM hook is not active on this kernel/build, staying in detect-only mode. See bpf/include/README.md.")
	}
	if err := e.ebpfMgr.SetEnforcement(wantEnforcement); err != nil {
		log.Printf("[engine] failed to set enforcement kill-switch: %v", err)
	}
}

// Hardcoded for now, will add logic for config loading tomorrow, i'm feeling so tired lmao
func isSuspiciousPath(target string, filenames []string) bool {
	for _, v := range filenames {
		if strings.HasPrefix(target, v) {
			return true
		}
	}
	return false
}

// matchesRule sees if the filename matches the Pattern that was set for it in the config file
func matchesRule(r config.Rule, sus []string, filename string, h *execHash) (bool, error) {
	if r.SuspiciousPathOnly && !isSuspiciousPath(filename, sus) {
		return false, nil
	}
	switch r.Match {
	case config.MatchExactPath:
		return filename == r.Pattern, nil
	case config.MatchBasename:
		return filepath.Base(filename) == r.Pattern, nil
	case config.MatchPrefix:
		return strings.HasPrefix(filename, r.Pattern), nil
	case config.MatchSubstring:
		return strings.Contains(filename, r.Pattern), nil
	case config.MatchSHA256:
		return matchesSHA256(h, r.Pattern)
	default:
		return false, nil
	}
}

// isAllowlisted checks if the our filename matches either a trusted entry
// in config or it's basename
func isAllowlisted(cfg *config.Config, filename string) bool {
	base := filepath.Base(filename)
	for _, a := range cfg.Allowlist {
		if a == filename || a == base {
			return true
		}
	}
	return false
}

// AnalyzeExec is the exec-path rule engine, "blocked" indicates this exec was already
// prevented pre-flight by the LSM hook (EVT_EXEC_BLOCKED), in that case no
// KILL is attempted (there is no process to kill; it never ran), but a
// BLOCK-severity alert is still produced.
func (e *Engine) AnalyzeExec(comm, filename string, pid, ppid, uid, gid uint32, cgroupID uint64, argv0 string, blocked bool, ancestorSuspicious bool, ancestorFilename string) {
	cfg := e.cfg.Current()
	h := &execHash{pid: pid}

	suspicious := isSuspiciousPath(filename, cfg.SuspiciousPaths)
	e.correlator.RecordExec(pid, filename, suspicious)

	if isAllowlisted(cfg, filename) {
		return // explicitly trusted
	}

	if blocked {
		e.metrics.IncBlock()
		e.dispatcher.Dispatch(alert.Alert{
			Timestamp: time.Now(), Severity: string(config.SeverityCritical), Action: string(config.ActionBlock),
			Blocked: true, EventType: "EXEC_BLOCKED", Pid: pid, Ppid: ppid, Uid: uid, Gid: gid, Comm: comm,
			CgroupID: cgroupID, Filename: filename, Argv0: argv0,
			AncestorSuspicious: ancestorSuspicious, AncestorFilename: ancestorFilename,
		})
		return
	}

	for _, r := range cfg.Rules {
		matched, err := matchesRule(r, cfg.SuspiciousPaths, filename, h)
		if err != nil {
			// For now only the Hash check might return an error so we only account for that specific case
			e.metrics.IncHashCheckError()
			log.Printf("[engine] rule %q: could not verify SHA256 for pid %d comm %q (%s): %v",
				r.Name, pid, comm, filename, err)
			continue
		}
		if !matched {
			continue
		}

		if !e.dedup.Allow(r.Name + "|" + strconv.Itoa(int(pid))) {
			// if the same (Rule,pid) were already alerted within the dedup window, we pass on alerting for this one
			continue
		}
		e.metrics.IncRuleHit(r.Name)

		a := alert.Alert{
			Timestamp: time.Now(), RuleName: r.Name, Severity: string(r.Severity), Action: string(r.Action),
			EventType: "EXEC", Pid: pid, Ppid: ppid, Uid: uid, Gid: gid, Comm: comm, CgroupID: cgroupID,
			Filename: filename, Argv0: argv0, AncestorSuspicious: ancestorSuspicious, AncestorFilename: ancestorFilename,
		}

		switch r.Action {
		case config.ActionKill, config.ActionBlock:
			// A BLOCK-action rule reaching here (post-exec, in the
			// tracepoint sensor path) means the LSM hook either isn't
			// active or hadn't synced this pattern yet, prevention
			// already failed, so KILL is the best remaining response.
			if err := e.guard.SafeKill(pid, comm); err != nil {
				a.ResponseErr = err.Error()
				e.metrics.IncKillError()
			} else {
				e.metrics.IncKill()
			}
		}

		e.dispatcher.Dispatch(a)
	}
}

// AnalyzeConnect handles CONNECT sensor events, escalating to CRITICAL
// when kernel lineage marks the process as originating from a suspicious binary.
func (e *Engine) AnalyzeConnect(pid, ppid, uid, gid uint32, comm string, cgroupID uint64, destIP string, destPort uint16, ancestorSuspicious bool, ancestorFilename string) {
	if !e.dedup.Allow("connect|" + strconv.Itoa(int(pid)) + "|" + destIP) {
		return
	}

	sev := config.SeverityLow
	detail := ""

	// Check kernel-emitted lineage
	if ancestorSuspicious {
		sev = config.SeverityCritical
		if comm == filepath.Base(ancestorFilename) {
			detail = "forked process with suspicious ancestor: " + ancestorFilename

		} else {
			detail = "suspicious ancestor: " + ancestorFilename
		}
	}

	e.dispatcher.Dispatch(alert.Alert{
		Timestamp: time.Now(), Severity: string(sev), Action: string(config.ActionAlert),
		EventType: "CONNECT", Pid: pid, Ppid: ppid, Uid: uid, Gid: gid, Comm: comm, CgroupID: cgroupID,
		DestIP: destIP, DestPort: destPort, Detail: detail, AncestorSuspicious: ancestorSuspicious, AncestorFilename: ancestorFilename,
	})
}

// AnalyzeGeneric handles every other sensor type with a shared, simple severity
// default. each is still its own distinct EventType in the alert so sinks
// and the dashboard can filter them independently.
func (e *Engine) AnalyzeGeneric(eventType string, defaultSeverity config.Severity, pid, ppid, uid, gid uint32, comm string, cgroupID uint64, filename, detail string, ancestorSuspicious bool, ancestorFilename string) {
	if !e.dedup.Allow(eventType + "|" + strconv.Itoa(int(pid))) {
		return
	}

	sev := defaultSeverity
	if ancestorSuspicious {
		sev = config.SeverityCritical
		if detail != "" {
			detail += " | "
		}
		if filename != "" && filename == ancestorFilename {
			detail += "forked process with suspicious ancestor: " + ancestorFilename

		} else {
			detail += "suspicious ancestor: " + ancestorFilename
		}
	}

	e.dispatcher.Dispatch(alert.Alert{
		Timestamp: time.Now(), Severity: string(sev), Action: string(config.ActionAlert),
		EventType: eventType, Pid: pid, Ppid: ppid, Uid: uid, Gid: gid, Comm: comm, CgroupID: cgroupID,
		Filename: filename, Detail: detail, AncestorSuspicious: ancestorSuspicious, AncestorFilename: ancestorFilename,
	})
}
