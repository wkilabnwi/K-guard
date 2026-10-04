package processor

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"k-guard/internal/alert"
	"k-guard/internal/audit"
	"k-guard/internal/config"
	"k-guard/internal/ebpf"
	k8s "k-guard/internal/k8s"
	"k-guard/internal/metrics"
	"k-guard/internal/pb"
	"k-guard/internal/safety"
)

type Engine struct {
	cfg         *config.Manager
	guard       *safety.Guard
	dispatcher  *alert.Dispatcher
	metrics     *metrics.Registry
	ebpfMgr     *ebpf.Manager
	auditLogger *audit.Logger

	dedup       *Deduper
	correlator  *Correlator
	k8sresolver *k8s.Resolver
}

func NewEngine(cfg *config.Manager, guard *safety.Guard, dispatcher *alert.Dispatcher, m *metrics.Registry, mgr *ebpf.Manager, k8sResolver *k8s.Resolver, auditLogger *audit.Logger) *Engine {
	e := &Engine{
		cfg:         cfg,
		guard:       guard,
		dispatcher:  dispatcher,
		metrics:     m,
		ebpfMgr:     mgr,
		auditLogger: auditLogger,
		dedup:       NewDeduper(time.Duration(cfg.Current().DedupWindowSeconds) * time.Second),
		correlator:  NewCorrelator(10 * time.Second),
		k8sresolver: k8sResolver,
	}

	// Apply the initial config, then keep re-applying on every hot reload
	e.applyConfig(cfg.Current())
	cfg.OnChange(e.applyConfig)

	cfg.OnChange(k8sResolver.UpdateConfig)
	return e
}

func (e *Engine) applyConfig(c *config.Config) {
	e.dedup.SetWindow(time.Duration(c.DedupWindowSeconds) * time.Second)
	e.guard.SetProtected(c.ProtectedPIDs, c.ProtectedComms)

	if e.ebpfMgr == nil {
		return
	}

	if err := e.ebpfMgr.SyncPrefixBlocks(c.BlockedPrefix()); err != nil {
		slog.Error("failed to sync LPM prefix block-list", "component", "engine", "error", err)
	}
	if err := e.ebpfMgr.SyncBlockedPaths(c.BlockedPatterns()); err != nil {
		slog.Error("failed to sync LSM block-list", "component", "engine", "error", err)
	}
	if err := e.ebpfMgr.SyncSuspiciousPaths(c.SuspiciousPaths); err != nil {
		slog.Error("failed to sync Suspicious Paths", "component", "engine", "error", err)
	}
	if err := e.ebpfMgr.SyncSensitiveWritePaths(c.SensitiveWritePaths); err != nil {
		slog.Error("failed to sync Sensitive write Paths", "component", "engine", "error", err)
	}
	if err := e.ebpfMgr.SyncBlockedWritePaths(c.BlockedWritePaths); err != nil {
		slog.Error("failed to sync Blocked write Paths", "component", "engine", "error", err)
	}
	if err := e.ebpfMgr.SyncAllowedPtraceAttached(c.AllowedPtraceAttached); err != nil {
		slog.Error("failed to sync Allowed Ptrace Attaches", "component", "engine", "error", err)
	}

	wantPtraceEnforcement := c.PtraceEnforcementEnabled
	if err := e.ebpfMgr.SetPtraceEnforcement(wantPtraceEnforcement); err != nil {
		slog.Error("failed to set Ptrace enforcement kill-switch", "component", "engine", "error", err)
	}

	wantKmodEnforcement := c.KmodEnforcementEnabled
	if err := e.ebpfMgr.SetKmodEnforcement(wantKmodEnforcement); err != nil {
		slog.Error("failed to set kmod enforcement kill-switch", "component", "engine", "error", err)
	}

	wantEnforcement := c.EnforcementEnabled && e.ebpfMgr.LSMEnabled
	if c.EnforcementEnabled && !e.ebpfMgr.LSMEnabled {
		slog.Warn("enforcement_enabled=true requested, but LSM hook is inactive on this kernel; staying in detect-only mode", "component", "engine")
	}
	if err := e.ebpfMgr.SetEnforcement(wantEnforcement); err != nil {
		slog.Error("failed to set enforcement kill-switch", "component", "engine", "error", err)
	}
}

func isSuspiciousPath(target string, filenames []string) bool {
	for _, v := range filenames {
		if strings.HasPrefix(target, v) {
			return true
		}
	}
	return false
}

// evaluateCEL executes the pre-compiled AST for a rule against event context
func evaluateCEL(r config.Rule, pbEvt *pb.EventContext) bool {
	if r.Program == nil {
		return false
	}

	out, _, err := r.Program.Eval(map[string]any{
		"event":   pbEvt,
		"process": pbEvt.GetProcess(),
	})
	if err != nil {
		slog.Error("CEL evaluation error in rule", "component", "engine", "rule", r.Name, "error", err)
		return false
	}

	matched, ok := out.Value().(bool)
	return ok && matched
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

// AnalyzeExec is the exec-path rule engine entry point
func (e *Engine) AnalyzeExec(meta ProcessMeta, blocked bool) {
	cfg := e.cfg.Current()
	e.correlator.RecordExec(meta.PID, meta.PPID, meta.Comm, meta.Filename)

	if isAllowlisted(cfg, meta.Filename) {
		return
	}

	if meta.IsFileless {
		e.handleFilelessExec(meta)
		return
	}

	if blocked {
		e.handleExecBlocked(cfg, meta)
		return
	}

	var shaVal string
	if cfg.RequiresSHA256() {
		h := &execHash{pid: meta.PID}
		var err error
		shaVal, err = h.get()
		if err != nil {
			e.metrics.IncHashCheckError()
		}
	}

	pbCtx := &pb.EventContext{
		Type:               "EXEC",
		AncestorSuspicious: meta.AncestorSuspicious,
		AncestorFilename:   meta.AncestorFilename,
		IsSuspiciousPath:   isSuspiciousPath(meta.Filename, cfg.SuspiciousPaths),
		Process: &pb.ProcessContext{
			Path:       meta.Filename,
			Basename:   filepath.Base(meta.Filename),
			Sha256:     shaVal,
			Pid:        int64(meta.PID),
			Ppid:       int64(meta.PPID),
			Uid:        int64(meta.UID),
			Gid:        int64(meta.GID),
			Comm:       meta.Comm,
			Args:       strings.Fields(meta.Args),
			IsFileless: meta.IsFileless,
		},
	}

	for _, r := range cfg.Rules {
		if !evaluateCEL(r, pbCtx) {
			continue
		}

		e.metrics.IncRuleHit(r.Name, string(r.Severity), string(r.Action))

		if !e.dedup.Allow(r.Name + "|" + strconv.Itoa(int(meta.PID))) {
			continue
		}

		if terminated := e.processExecRuleMatch(r, meta); terminated {
			return
		}
	}
}

// Helper: Handle fileless execution events
func (e *Engine) handleFilelessExec(meta ProcessMeta) {
	filelessDetail := "Fileless execution detected"
	sev := config.SeverityCritical

	e.metrics.IncRuleHit("FilelessExecution", string(sev), string(config.ActionKill))

	a := meta.ToAlert("FILELESS_EXEC", sev, config.ActionKill, filelessDetail)
	e.emit(a)
}

// Helper: Handle pre-flight LSM blocked execution events
func (e *Engine) handleExecBlocked(cfg *config.Config, meta ProcessMeta) {
	e.metrics.IncBlock()
	detail := ""
	if meta.PathTruncated {
		detail = "path truncated during read, match against blocked_paths may be unreliable"
	}

	var ruleName string
	var mitre *config.MitreMeta
	var ruleMode = config.RuleModeEnforce

	celCtx := &pb.EventContext{
		Type:               "EXEC_BLOCKED",
		AncestorSuspicious: meta.AncestorSuspicious,
		AncestorFilename:   meta.AncestorFilename,
		IsSuspiciousPath:   isSuspiciousPath(meta.Filename, cfg.SuspiciousPaths),
		Process: &pb.ProcessContext{
			Path:       meta.Filename,
			Basename:   filepath.Base(meta.Filename),
			Pid:        int64(meta.PID),
			Ppid:       int64(meta.PPID),
			Uid:        int64(meta.UID),
			Gid:        int64(meta.GID),
			Comm:       meta.Comm,
			Args:       strings.Fields(meta.Args),
			IsFileless: meta.IsFileless,
		},
	}

	for _, r := range cfg.Rules {
		if r.Action == config.ActionBlock {
			if r.ExactBlockPath == meta.Filename || (r.ExactBlockPrefix != "" && strings.HasPrefix(meta.Filename, r.ExactBlockPrefix)) || evaluateCEL(r, celCtx) {
				ruleName = r.Name
				mitre = r.Mitre
				ruleMode = r.Mode
				break
			}
		}
	}

	isActuallyBlocked := (ruleMode == config.RuleModeEnforce)
	reason := "LSM pre-exec hook blocked binary execution"
	if !isActuallyBlocked {
		reason = "LSM pre-exec hook matched rule in audit mode (execution allowed)"
		if detail != "" {
			detail += " | "
		}
		detail += "[SHADOW/AUDIT] Pre-exec LSM block dry-run matched (execution allowed)"
	}

	a := meta.ToAlert("EXEC_BLOCKED", config.SeverityCritical, config.ActionAlert, detail)
	a.RuleName = ruleName
	a.Mitre = mitre
	a.Mode = string(ruleMode)
	a.Blocked = isActuallyBlocked

	rec := meta.ToAuditRecord(audit.DecisionBlock, "EXEC_BLOCKED", ruleName, mitre, meta.Filename, reason)
	e.emitAuditAndAlert(a, rec)
}

// Helper: Handle matched post-exec rules
func (e *Engine) processExecRuleMatch(r config.Rule, meta ProcessMeta) bool {
	sev := r.Severity
	detail := ""
	if meta.PathTruncated && sev.Rank() < config.SeverityMedium.Rank() {
		sev = config.SeverityMedium
	}
	e.metrics.IncRuleHit(r.Name, string(sev), string(r.Action))
	if meta.PathTruncated {
		detail = "path truncated during read, match against configured path lists may be unreliable"
	}

	a := meta.ToAlert("EXEC", sev, r.Action, detail)
	a.RuleName = r.Name
	a.Mitre = r.Mitre
	a.Mode = string(r.Mode)

	if r.Mode == config.RuleModeAudit {
		shadowDetail := fmt.Sprintf("[SHADOW MODE] Rule matched dry-run audit mode; %s action suppressed", r.Action)
		if detail != "" {
			a.Detail = detail + " | " + shadowDetail
		} else {
			a.Detail = shadowDetail
		}
		e.emit(a)
		return false
	}

	switch r.Action {
	case config.ActionKill, config.ActionBlock:
		if err := e.guard.SafeKill(meta.PID, meta.Comm); err != nil {
			a.ResponseErr = err.Error()
			e.metrics.IncKillError()
		} else {
			e.metrics.IncKill()
			rec := meta.ToAuditRecord(audit.DecisionKill, "EXEC", r.Name, r.Mitre, meta.Filename, "Process killed post-exec via rule action")
			e.emitAudit(rec)
		}
		e.emit(a)
		return true
	}

	e.emit(a)
	return false
}

func (e *Engine) RecordDNSAnswer(cgroupID uint64, ip, domain string) {
	e.correlator.RecordIPDomain(cgroupID, ip, domain)
}

// AnalyzeNetworkEgress handles CONNECT and SENDTO egress sensor events, escalating
// to CRITICAL when kernel lineage marks the process as originating from a suspicious binary.
func (e *Engine) AnalyzeNetworkEgress(meta ProcessMeta, eventType, destIP string, destPort uint16) {
	if !e.dedup.Allow(eventType + "|" + strconv.Itoa(int(meta.PID)) + "|" + destIP) {
		return
	}

	sev := config.SeverityLow
	detail := ""

	if e.correlator != nil {
		if domain, exact := e.correlator.GetDomainByIP(meta.CgroupID, destIP); domain != "" {
			if exact {
				detail = fmt.Sprintf("Resolved domain: %s", domain)
			} else {
				detail = fmt.Sprintf("Resolved domain: %s (cross-process match)", domain)
			}
		}
	}

	if meta.AncestorSuspicious {
		sev = config.SeverityCritical
	}

	a := meta.ToAlert(eventType, sev, config.ActionAlert, detail)
	a.DestIP = destIP
	a.DestPort = destPort

	e.emit(a)
}

// AnalyzeGeneric handles every other sensor type with a shared, simple severity
// default. each is still its own distinct EventType in the alert so sinks
// and the dashboard can filter them independently.
func (e *Engine) AnalyzeGeneric(meta ProcessMeta, eventType string, defaultSeverity config.Severity, detail string) {
	if !e.dedup.Allow(eventType + "|" + strconv.Itoa(int(meta.PID)) + "|" + meta.Filename) {
		return
	}

	sev := defaultSeverity
	if meta.AncestorSuspicious {
		sev = config.SeverityCritical
	}

	if meta.PathTruncated && sev.Rank() < config.SeverityMedium.Rank() {
		sev = config.SeverityMedium
		if detail != "" {
			detail += " | "
		}
		detail += "path truncated during read, manual check the full path"
	}

	a := meta.ToAlert(eventType, sev, config.ActionAlert, detail)
	e.emit(a)
}

func (e *Engine) AnalyzeWriteBlocked(meta ProcessMeta) {
	e.metrics.IncBlock()

	detail := "write intent blocked pre-flight by blocked_write_paths policy"
	if meta.PathTruncated {
		detail += " | path truncated during read"
	}

	a := meta.ToAlert("WRITE_BLOCKED", config.SeverityCritical, config.ActionAlert, detail)
	a.Blocked = true

	rec := meta.ToAuditRecord(audit.DecisionBlock, "WRITE_BLOCKED", "", nil, meta.Filename, "Write intent blocked pre-flight by blocked_write_paths policy")
	e.emitAuditAndAlert(a, rec)
}

func (e *Engine) AnalyzePtraceBlocked(meta ProcessMeta, targetComm string, targetPid, mode uint32) {
	e.metrics.IncBlock()

	reason := fmt.Sprintf("Blocked ptrace request mode=0x%x targeting PID %d", mode, targetPid)
	detail := fmt.Sprintf("BLOCKED ptrace request mode=0x%x targeting pid=%d (comm='%s')", mode, targetPid, targetComm)

	a := meta.ToAlert("PTRACE_BLOCKED", config.SeverityCritical, config.ActionAlert, detail)
	a.Filename = targetComm
	a.Blocked = true

	rec := meta.ToAuditRecord(audit.DecisionBlock, "PTRACE_BLOCKED", "", nil, targetComm, reason)
	e.emitAuditAndAlert(a, rec)
}

func (e *Engine) AnalyzeKmodBlocked(meta ProcessMeta) {
	e.metrics.IncBlock()

	detail := fmt.Sprintf("Kernel module load or read blocked by LSM policy (comm='%s')", meta.Comm)
	if meta.AncestorSuspicious {
		detail += fmt.Sprintf(" [triggered via suspicious ancestor: %s]", meta.AncestorFilename)
	}

	a := meta.ToAlert("KMOD_BLOCKED", config.SeverityCritical, config.ActionAlert, detail)
	a.Blocked = true

	rec := meta.ToAuditRecord(audit.DecisionBlock, "KMOD_BLOCKED", "", nil, "", "Kernel module load or read blocked by LSM policy")
	e.emitAuditAndAlert(a, rec)
}

func (e *Engine) AnalyzeIoUring(meta ProcessMeta, opcode uint8) {
	if !e.dedup.Allow("iouring|" + strconv.Itoa(int(meta.PID)) + "|" + strconv.Itoa(int(opcode))) {
		return
	}

	detail := fmt.Sprintf("io_uring evasion attempt detected (opcode=%d)", opcode)
	sev := config.SeverityMedium
	if meta.AncestorSuspicious {
		sev = config.SeverityCritical
	}

	a := meta.ToAlert("IO_URING", sev, config.ActionAlert, detail)
	e.emit(a)
}

func (e *Engine) AnalyzeLpeBlocked(meta ProcessMeta, oldUID, newUID uint32) {
	e.metrics.IncBlock()

	reason := fmt.Sprintf("Unauthorized Local Privilege Escalation blocked by LSM policy (comm='%s', uid %d -> %d)", meta.Comm, oldUID, newUID)
	detail := reason
	if meta.AncestorSuspicious {
		detail += fmt.Sprintf(" [triggered via suspicious ancestor: %s]", meta.AncestorFilename)
	}

	a := meta.ToAlert("LPE_BLOCKED", config.SeverityCritical, config.ActionAlert, detail)
	a.Blocked = true

	rec := meta.ToAuditRecord(audit.DecisionBlock, "LPE_BLOCKED", "", nil, "", reason)
	e.emitAuditAndAlert(a, rec)
}

func (e *Engine) AnalyzePmu(meta ProcessMeta, mispredCount uint64) {
	if !e.dedup.Allow("pmu_mispredict|" + strconv.Itoa(int(meta.PID))) {
		return
	}

	detail := fmt.Sprintf("PMU branch misprediction spike: count=%d", mispredCount)
	sev := config.SeverityMedium
	if meta.AncestorSuspicious {
		sev = config.SeverityCritical
	}

	a := meta.ToAlert("BRANCH_MISPREDICT", sev, config.ActionAlert, detail)
	e.emit(a)
}

func (e *Engine) AnalyzeNsChange(meta ProcessMeta, op uint32, flags uint64, nstype uint32) {
	if !e.dedup.Allow("ns_change|" + strconv.Itoa(int(meta.PID)) + "|" + strconv.Itoa(int(op))) {
		return
	}

	opName := "unshare"
	if op == 2 {
		opName = "setns"
	}

	detail := fmt.Sprintf("Namespace manipulation attempt via %s() (flags/fd=0x%x, nstype=0x%x)", opName, flags, nstype)
	sev := config.SeverityHigh
	if meta.AncestorSuspicious {
		sev = config.SeverityCritical
	}

	a := meta.ToAlert("NS_CHANGE", sev, config.ActionAlert, detail)
	e.emit(a)
}

func (e *Engine) AnalyzeReverseShell(meta ProcessMeta) {
	cfg := e.cfg.Current()
	enforced := cfg.EnforcementEnabled && e.ebpfMgr != nil && e.ebpfMgr.LSMEnabled

	detail := "Reverse-shell vector detected: network socket redirected to standard I/O (fd 0/1/2) prior to shell execution"

	act := config.ActionKill
	if enforced {
		act = config.ActionBlock
	}

	a := meta.ToAlert("REVERSE_SHELL", config.SeverityCritical, act, detail)
	a.Blocked = enforced

	if enforced {
		e.metrics.IncBlock()
		a.Detail += " [LSM Pre-flight Blocked]"
		rec := meta.ToAuditRecord(audit.DecisionBlock, "REVERSE_SHELL", "", nil, meta.Filename, detail+" (LSM Pre-flight Blocked)")
		e.emitAuditAndAlert(a, rec)
	} else {
		rec := meta.ToAuditRecord(audit.DecisionKill, "REVERSE_SHELL", "", nil, meta.Filename, detail+" (Post-exec SIGKILL)")
		e.emitAudit(rec)

		if err := e.guard.SafeKill(meta.PID, meta.Comm); err != nil {
			a.ResponseErr = err.Error()
			e.metrics.IncKillError()
		} else {
			e.metrics.IncKill()
		}
		e.emit(a)
	}
}

// enrichAlert applies contextual metadata (timestamps, k8s Pod/Container info) to an alert
// at the next refactor this function will do the work of enriching all alerts not only the k8s context
func (e *Engine) enrichAlert(a alert.Alert) alert.Alert {
	if a.Timestamp.IsZero() {
		a.Timestamp = time.Now()
	}

	cfg := e.cfg.Current()

	if a.AncestorSuspicious && !isSuspiciousPath(a.Filename, cfg.SuspiciousPaths) && e.correlator != nil {
		a.LineageTree = e.correlator.FormatTree(a.Pid)
	}

	if e.k8sresolver != nil {
		if ctx, ok := e.k8sresolver.Resolve(a.CgroupID, a.Pid); ok {
			a.ContainerID = ctx.ContainerID
			a.PodName = ctx.PodName
			a.Namespace = ctx.Namespace
			a.PodUID = ctx.PodUID
			a.Runtime = ctx.Runtime
		}
	}

	return a
}

func (e *Engine) emit(a alert.Alert) {
	e.dispatcher.Dispatch(e.enrichAlert(a))
}

func (e *Engine) emitAudit(rec audit.Record) {
	if e.auditLogger != nil {
		e.auditLogger.Log(rec)
	}
}

func (e *Engine) emitAuditAndAlert(a alert.Alert, rec audit.Record) {
	e.emitAudit(rec)
	e.emit(a)
}
