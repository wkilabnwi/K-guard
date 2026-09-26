package processor

import (
	"fmt"
	"log"
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
		log.Printf("[engine] failed to sync LPM prefix block-list: %v", err)
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
	if err := e.ebpfMgr.SyncBlockedWritePaths(c.BlockedWritePaths); err != nil {
		log.Printf("[engine] failed to sync Blocked write Paths: %v", err)
	}
	if err := e.ebpfMgr.SyncAllowedPtraceAttached(c.AllowedPtraceAttached); err != nil {
		log.Printf("[engine] faile to sync Allowed Ptrace Attaches: %v", err)
	}

	wantPtraceEnforcement := c.PtraceEnforcementEnabled
	if err := e.ebpfMgr.SetPtraceEnforcement(wantPtraceEnforcement); err != nil {
		log.Printf("[engine] failed to set Ptrace enforcement kill-switch: %v", err)
	}

	wantKmodEnforcement := c.KmodEnforcementEnabled
	if err := e.ebpfMgr.SetKmodEnforcement(wantKmodEnforcement); err != nil {
		log.Printf("[engine] failed to set kmod enforcement kill-switch: %v", err)
	}

	wantEnforcement := c.EnforcementEnabled && e.ebpfMgr.LSMEnabled
	if c.EnforcementEnabled && !e.ebpfMgr.LSMEnabled {
		log.Printf("[engine] config requests enforcement_enabled=true, but the LSM hook is not active on this kernel/build, staying in detect-only mode. See bpf/include/README.md.")
	}
	if err := e.ebpfMgr.SetEnforcement(wantEnforcement); err != nil {
		log.Printf("[engine] failed to set enforcement kill-switch: %v", err)
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
func evaluateCEL(r config.Rule, celCtx config.EventContext) bool {
	if r.Program == nil {
		return false
	}

	input := map[string]interface{}{
		"event": map[string]interface{}{
			"type":                celCtx.Type,
			"ancestor_suspicious": celCtx.AncestorSuspicious,
			"ancestor_filename":   celCtx.AncestorFilename,
			"is_suspicious_path":  celCtx.IsSuspiciousPath,
			"process": map[string]interface{}{
				"path":        celCtx.Process.Path,
				"basename":    celCtx.Process.Basename,
				"sha256":      celCtx.Process.SHA256,
				"pid":         celCtx.Process.PID,
				"ppid":        celCtx.Process.PPID,
				"uid":         celCtx.Process.UID,
				"gid":         celCtx.Process.GID,
				"comm":        celCtx.Process.Comm,
				"args":        celCtx.Process.Args,
				"is_fileless": celCtx.Process.IsFileless,
			},
		},
		"process": map[string]interface{}{
			"path":        celCtx.Process.Path,
			"basename":    celCtx.Process.Basename,
			"sha256":      celCtx.Process.SHA256,
			"pid":         celCtx.Process.PID,
			"ppid":        celCtx.Process.PPID,
			"uid":         celCtx.Process.UID,
			"gid":         celCtx.Process.GID,
			"comm":        celCtx.Process.Comm,
			"args":        celCtx.Process.Args,
			"is_fileless": celCtx.Process.IsFileless,
		},
	}

	out, _, err := r.Program.Eval(input)
	if err != nil {
		log.Printf("[engine] CEL evaluation error in rule %q: %v", r.Name, err)
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
func (e *Engine) AnalyzeExec(comm, filename string, pid, ppid, uid, gid uint32, cgroupID uint64, args string, blocked bool, ancestorSuspicious bool, ancestorFilename string, pathTruncated, isFileless bool) {
	cfg := e.cfg.Current()
	e.correlator.RecordExec(pid, ppid, comm, filename)

	if isAllowlisted(cfg, filename) {
		return // explicitly trusted
	}

	if isFileless {
		e.handleFilelessExec(comm, filename, args, pid, ppid, uid, gid, cgroupID, ancestorSuspicious, ancestorFilename, pathTruncated)
		return
	}

	if blocked {
		e.handleExecBlocked(cfg, comm, filename, args, pid, ppid, uid, gid, cgroupID, ancestorSuspicious, ancestorFilename, pathTruncated, isFileless)
		return
	}

	// Prepare CEL evaluation context payload
	h := &execHash{pid: pid}
	shaVal, err := h.get()
	if err != nil {
		e.metrics.IncHashCheckError()
	}

	celCtx := config.EventContext{
		Type:               "EXEC",
		AncestorSuspicious: ancestorSuspicious,
		AncestorFilename:   ancestorFilename,
		IsSuspiciousPath:   isSuspiciousPath(filename, cfg.SuspiciousPaths),
		Process: config.ProcessContext{
			Path:       filename,
			Basename:   filepath.Base(filename),
			SHA256:     shaVal,
			PID:        int64(pid),
			PPID:       int64(ppid),
			UID:        int64(uid),
			GID:        int64(gid),
			Comm:       comm,
			Args:       strings.Fields(args),
			IsFileless: isFileless,
		},
	}

	for _, r := range cfg.Rules {
		if !evaluateCEL(r, celCtx) {
			continue
		}

		if !e.dedup.Allow(r.Name + "|" + strconv.Itoa(int(pid))) {
			continue
		}

		if terminated := e.processExecRuleMatch(r, filename, comm, args, pid, ppid, uid, gid, cgroupID, ancestorSuspicious, ancestorFilename, pathTruncated); terminated {
			return
		}
	}
}

// Helper: Handle fileless execution events
func (e *Engine) handleFilelessExec(comm, filename, args string, pid, ppid, uid, gid uint32, cgroupID uint64, ancestorSuspicious bool, ancestorFilename string, pathTruncated bool) {
	filelessDetail := "Fileless execution detected"
	sev := config.SeverityCritical

	e.metrics.IncRuleHit("FilelessExecution", string(sev), string(config.ActionKill))

	a := alert.Alert{
		Severity:           string(sev),
		Action:             string(config.ActionKill),
		EventType:          "FILELESS_EXEC",
		Pid:                pid,
		Ppid:               ppid,
		Uid:                uid,
		Gid:                gid,
		Comm:               comm,
		CgroupID:           cgroupID,
		Filename:           filename,
		Args:               args,
		AncestorSuspicious: ancestorSuspicious,
		AncestorFilename:   ancestorFilename,
		PathTruncated:      pathTruncated,
		Detail:             filelessDetail,
	}

	e.dispatcher.Dispatch(e.enrichAlert(a))
}

// Helper: Handle pre-flight LSM blocked execution events
func (e *Engine) handleExecBlocked(cfg *config.Config, comm, filename, args string, pid, ppid, uid, gid uint32, cgroupID uint64, ancestorSuspicious bool, ancestorFilename string, pathTruncated, isFileless bool) {
	e.metrics.IncBlock()
	detail := ""
	if pathTruncated {
		detail = "path truncated during read, match against blocked_paths may be unreliable"
	}

	var ruleName string
	var mitre *config.MitreMeta
	var ruleMode config.RuleMode = config.RuleModeEnforce

	celCtx := config.EventContext{
		Type:               "EXEC_BLOCKED",
		AncestorSuspicious: ancestorSuspicious,
		AncestorFilename:   ancestorFilename,
		IsSuspiciousPath:   isSuspiciousPath(filename, cfg.SuspiciousPaths),
		Process: config.ProcessContext{
			Path:       filename,
			Basename:   filepath.Base(filename),
			PID:        int64(pid),
			PPID:       int64(ppid),
			UID:        int64(uid),
			GID:        int64(gid),
			Comm:       comm,
			Args:       strings.Fields(args),
			IsFileless: isFileless,
		},
	}

	for _, r := range cfg.Rules {
		if r.Action == config.ActionBlock {
			if r.ExactBlockPath == filename || (r.ExactBlockPrefix != "" && strings.HasPrefix(filename, r.ExactBlockPrefix)) || evaluateCEL(r, celCtx) {
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

	e.auditLogger.Log(audit.Record{
		Decision:  audit.DecisionBlock,
		EventType: "EXEC_BLOCKED",
		RuleName:  ruleName,
		Mitre:     mitre,
		PID:       pid, PPID: ppid, UID: uid,
		Comm: comm, CgroupID: cgroupID,
		Target: filename,
		Reason: reason,
	})

	a := alert.Alert{
		RuleName: ruleName, Severity: string(config.SeverityCritical), Action: string(config.ActionAlert),
		Mitre:   mitre,
		Mode:    string(ruleMode),
		Blocked: isActuallyBlocked, EventType: "EXEC_BLOCKED", Pid: pid, Ppid: ppid, Uid: uid, Gid: gid, Comm: comm,
		CgroupID: cgroupID, Filename: filename, Args: args,
		AncestorSuspicious: ancestorSuspicious, AncestorFilename: ancestorFilename,
		PathTruncated: pathTruncated, Detail: detail,
	}

	e.dispatcher.Dispatch(e.enrichAlert(a))
}

// Helper: Handle matched post-exec rules
func (e *Engine) processExecRuleMatch(r config.Rule, filename, comm, args string, pid, ppid, uid, gid uint32, cgroupID uint64, ancestorSuspicious bool, ancestorFilename string, pathTruncated bool) bool {
	sev := r.Severity
	detail := ""
	if pathTruncated && sev.Rank() < config.SeverityMedium.Rank() {
		sev = config.SeverityMedium
	}
	e.metrics.IncRuleHit(r.Name, string(sev), string(r.Action))
	if pathTruncated {
		detail = "path truncated during read, match against configured path lists may be unreliable"
	}

	a := alert.Alert{
		RuleName: r.Name, Severity: string(sev), Action: string(r.Action),
		Mitre:     r.Mitre,
		Mode:      string(r.Mode),
		EventType: "EXEC", Pid: pid, Ppid: ppid, Uid: uid, Gid: gid, Comm: comm, CgroupID: cgroupID,
		Filename: filename, Args: args, AncestorSuspicious: ancestorSuspicious, AncestorFilename: ancestorFilename,
		PathTruncated: pathTruncated, Detail: detail,
	}

	if r.Mode == config.RuleModeAudit {
		shadowDetail := fmt.Sprintf("[SHADOW MODE] Rule matched dry-run audit mode; %s action suppressed", r.Action)
		if detail != "" {
			a.Detail = detail + " | " + shadowDetail
		} else {
			a.Detail = shadowDetail
		}
		e.dispatcher.Dispatch(e.enrichAlert(a))
		return false
	}

	switch r.Action {
	case config.ActionKill, config.ActionBlock:
		if err := e.guard.SafeKill(pid, comm); err != nil {
			a.ResponseErr = err.Error()
			e.metrics.IncKillError()
		} else {
			e.metrics.IncKill()

			e.auditLogger.Log(audit.Record{
				Decision:  audit.DecisionKill,
				EventType: "EXEC",
				RuleName:  r.Name,
				Mitre:     r.Mitre,
				PID:       pid, PPID: ppid, UID: uid,
				Comm: comm, CgroupID: cgroupID,
				Target: filename,
				Reason: "Process killed post-exec via rule action",
			})
		}
		e.dispatcher.Dispatch(e.enrichAlert(a))
		return true
	}

	e.dispatcher.Dispatch(e.enrichAlert(a))
	return false
}

func (e *Engine) RecordDNSAnswer(cgroupID uint64, ip, domain string) {
	e.correlator.RecordIPDomain(cgroupID, ip, domain)
}

// AnalyzeNetworkEgress handles CONNECT and SENDTO egress sensor events, escalating
// to CRITICAL when kernel lineage marks the process as originating from a suspicious binary.
func (e *Engine) AnalyzeNetworkEgress(eventType string, pid, ppid, uid, gid uint32, comm string, cgroupID uint64, destIP string, destPort uint16, ancestorSuspicious bool, ancestorFilename string) {
	if !e.dedup.Allow(eventType + "|" + strconv.Itoa(int(pid)) + "|" + destIP) {
		return
	}

	sev := config.SeverityLow
	detail := ""

	if e.correlator != nil {
		if domain, exact := e.correlator.GetDomainByIP(cgroupID, destIP); domain != "" {
			if exact {
				detail = fmt.Sprintf("Resolved domain: %s", domain)
			} else {
				detail = fmt.Sprintf("Resolved domain: %s (cross-process match)", domain)
			}
		}
	}

	if ancestorSuspicious {
		sev = config.SeverityCritical
	}

	a := alert.Alert{
		Severity: string(sev), Action: string(config.ActionAlert),
		EventType: eventType, Pid: pid, Ppid: ppid, Uid: uid, Gid: gid, Comm: comm, CgroupID: cgroupID,
		DestIP: destIP, DestPort: destPort, Detail: detail, AncestorSuspicious: ancestorSuspicious, AncestorFilename: ancestorFilename,
	}

	e.dispatcher.Dispatch(e.enrichAlert(a))
}

// AnalyzeGeneric handles every other sensor type with a shared, simple severity
// default. each is still its own distinct EventType in the alert so sinks
// and the dashboard can filter them independently.
func (e *Engine) AnalyzeGeneric(eventType string, defaultSeverity config.Severity, pid, ppid, uid, gid uint32, comm string, cgroupID uint64, filename, detail string, ancestorSuspicious bool, ancestorFilename string, pathTruncated bool) {

	if !e.dedup.Allow(eventType + "|" + strconv.Itoa(int(pid)) + "|" + filename) {
		return
	}

	sev := defaultSeverity
	if ancestorSuspicious {
		sev = config.SeverityCritical
	}

	if pathTruncated && sev.Rank() < config.SeverityMedium.Rank() {
		sev = config.SeverityMedium
		if detail != "" {
			detail += " | "
		}
		detail += "path truncated during read, manual check the full path"
	}

	a := alert.Alert{
		Severity: string(sev), Action: string(config.ActionAlert),
		EventType: eventType, Pid: pid, Ppid: ppid, Uid: uid, Gid: gid, Comm: comm, CgroupID: cgroupID,
		Filename: filename, Detail: detail, AncestorSuspicious: ancestorSuspicious, AncestorFilename: ancestorFilename,
		PathTruncated: pathTruncated,
	}

	e.dispatcher.Dispatch(e.enrichAlert(a))
}

func (e *Engine) AnalyzeWriteBlocked(comm, filename string, pid, ppid, uid, gid uint32, cgroupID uint64, ancestorSuspicious bool, ancestorFilename string, pathTruncated bool) {
	e.metrics.IncBlock()

	e.auditLogger.Log(audit.Record{
		Decision:  audit.DecisionBlock,
		EventType: "WRITE_BLOCKED",
		PID:       pid, PPID: ppid, UID: uid,
		Comm: comm, CgroupID: cgroupID,
		Target: filename,
		Reason: "Write intent blocked pre-flight by blocked_write_paths policy",
	})

	detail := "write intent blocked pre-flight by blocked_write_paths policy"
	if pathTruncated {
		detail += " | path truncated during read"
	}

	a := alert.Alert{
		Severity:  string(config.SeverityCritical),
		Action:    string(config.ActionAlert),
		Blocked:   true,
		EventType: "WRITE_BLOCKED",
		Pid:       pid, Ppid: ppid, Uid: uid, Gid: gid,
		Comm: comm, CgroupID: cgroupID, Filename: filename,
		AncestorSuspicious: ancestorSuspicious,
		AncestorFilename:   ancestorFilename,
		PathTruncated:      pathTruncated,
		Detail:             detail,
	}

	e.dispatcher.Dispatch(e.enrichAlert(a))
}

func (e *Engine) AnalyzePtraceBlocked(comm, targetComm string, targetPid, mode, pid, ppid, uid, gid uint32, cgroupID uint64, ancestorSuspicious bool, ancestorFilename string) {
	if !e.dedup.Allow("ptrace_blocked|" + strconv.Itoa(int(pid)) + "|" + strconv.Itoa(int(targetPid))) {
		return
	}
	e.metrics.IncBlock()

	e.auditLogger.Log(audit.Record{
		Decision:  audit.DecisionBlock,
		EventType: "PTRACE_BLOCKED",
		PID:       pid, PPID: ppid, UID: uid,
		Comm: comm, CgroupID: cgroupID,
		Target: targetComm,
		Reason: fmt.Sprintf("Blocked ptrace request mode=0x%x targeting PID %d", mode, targetPid),
	})

	detail := fmt.Sprintf("BLOCKED ptrace request mode=0x%x targeting pid=%d (comm='%s')", mode, targetPid, targetComm)

	a := alert.Alert{
		Severity:  string(config.SeverityCritical),
		Action:    string(config.ActionAlert),
		Blocked:   true,
		EventType: "PTRACE_BLOCKED",
		Pid:       pid, Ppid: ppid, Uid: uid, Gid: gid,
		Comm: comm, CgroupID: cgroupID, Filename: targetComm,
		AncestorSuspicious: ancestorSuspicious,
		AncestorFilename:   ancestorFilename,
		Detail:             detail,
	}

	e.dispatcher.Dispatch(e.enrichAlert(a))
}

func (e *Engine) AnalyzeKmodBlocked(comm string, pid, ppid, uid, gid uint32, cgroupID uint64, ancestorSuspicious bool, ancestorFilename string) {
	if !e.dedup.Allow("kmod_blocked|" + strconv.Itoa(int(pid))) {
		return
	}
	e.metrics.IncBlock()

	e.auditLogger.Log(audit.Record{
		Decision:  audit.DecisionBlock,
		EventType: "KMOD_BLOCKED",
		PID:       pid, PPID: ppid, UID: uid,
		Comm: comm, CgroupID: cgroupID,
		Reason: "Kernel module load or read blocked by LSM policy",
	})

	detail := fmt.Sprintf("Kernel module load or read blocked by LSM policy (comm='%s')", comm)
	if ancestorSuspicious {
		detail += fmt.Sprintf(" [triggered via suspicious ancestor: %s]", ancestorFilename)
	}

	a := alert.Alert{
		Severity:           string(config.SeverityCritical),
		Action:             string(config.ActionAlert),
		Blocked:            true,
		EventType:          "KMOD_BLOCKED",
		Pid:                pid,
		Ppid:               ppid,
		Uid:                uid,
		Gid:                gid,
		Comm:               comm,
		CgroupID:           cgroupID,
		AncestorSuspicious: ancestorSuspicious,
		AncestorFilename:   ancestorFilename,
		Detail:             detail,
	}

	e.dispatcher.Dispatch(e.enrichAlert(a))
}

func (e *Engine) AnalyzeIoUring(pid, ppid, uid, gid uint32, comm, filename string, cgroupID uint64, opcode uint8, ancestorSuspicious bool, ancestorFilename string) {
	if !e.dedup.Allow("iouring|" + strconv.Itoa(int(pid)) + "|" + strconv.Itoa(int(opcode))) {
		return
	}

	detail := fmt.Sprintf("io_uring evasion attempt detected (opcode=%d)", opcode)
	sev := config.SeverityMedium
	if ancestorSuspicious {
		sev = config.SeverityCritical
	}

	a := alert.Alert{
		Severity: string(sev), Action: string(config.ActionAlert),
		EventType: "IO_URING", Pid: pid, Ppid: ppid, Uid: uid, Gid: gid, Comm: comm, CgroupID: cgroupID,
		Detail: detail, AncestorSuspicious: ancestorSuspicious, AncestorFilename: ancestorFilename,
	}

	e.dispatcher.Dispatch(e.enrichAlert(a))
}

func (e *Engine) AnalyzeLpeBlocked(comm string, pid, ppid, uid, gid uint32, cgroupID uint64, oldUID, newUID uint32, ancestorSuspicious bool, ancestorFilename string) {
	if !e.dedup.Allow("lpe_blocked|" + strconv.Itoa(int(pid))) {
		return
	}
	e.metrics.IncBlock()

	detail := fmt.Sprintf("Unauthorized Local Privilege Escalation blocked by LSM policy (comm='%s', uid %d -> %d)", comm, oldUID, newUID)
	if ancestorSuspicious {
		detail += fmt.Sprintf(" [triggered via suspicious ancestor: %s]", ancestorFilename)
	}

	a := alert.Alert{
		Severity:           string(config.SeverityCritical),
		Action:             string(config.ActionAlert),
		Blocked:            true,
		EventType:          "LPE_BLOCKED",
		Pid:                pid,
		Ppid:               ppid,
		Uid:                uid,
		Gid:                gid,
		Comm:               comm,
		CgroupID:           cgroupID,
		AncestorSuspicious: ancestorSuspicious,
		AncestorFilename:   ancestorFilename,
		Detail:             detail,
	}

	e.dispatcher.Dispatch(e.enrichAlert(a))
}

func (e *Engine) AnalyzePmu(pid, ppid, uid, gid uint32, comm string, cgroupID uint64, mispredCount uint64, ancestorSuspicious bool, ancestorFilename string) {
	if !e.dedup.Allow("pmu_mispredict|" + strconv.Itoa(int(pid))) {
		return
	}

	detail := fmt.Sprintf("PMU branch misprediction spike: count=%d", mispredCount)
	sev := config.SeverityMedium
	if ancestorSuspicious {
		sev = config.SeverityCritical
	}

	a := alert.Alert{
		Severity: string(sev), Action: string(config.ActionAlert),
		EventType: "BRANCH_MISPREDICT", Pid: pid, Ppid: ppid, Uid: uid, Gid: gid, Comm: comm, CgroupID: cgroupID,
		Detail: detail, AncestorSuspicious: ancestorSuspicious, AncestorFilename: ancestorFilename,
	}

	e.dispatcher.Dispatch(e.enrichAlert(a))
}

func (e *Engine) AnalyzeNsChange(pid, ppid, uid, gid uint32, comm string, cgroupID uint64, op uint32, flags uint64, nstype uint32, ancestorSuspicious bool, ancestorFilename string) {
	if !e.dedup.Allow("ns_change|" + strconv.Itoa(int(pid)) + "|" + strconv.Itoa(int(op))) {
		return
	}

	opName := "unshare"
	if op == 2 {
		opName = "setns"
	}

	detail := fmt.Sprintf("Namespace manipulation attempt via %s() (flags/fd=0x%x, nstype=0x%x)", opName, flags, nstype)
	sev := config.SeverityHigh
	if ancestorSuspicious {
		sev = config.SeverityCritical
	}

	a := alert.Alert{
		Severity: string(sev), Action: string(config.ActionAlert),
		EventType: "NS_CHANGE", Pid: pid, Ppid: ppid, Uid: uid, Gid: gid, Comm: comm, CgroupID: cgroupID,
		Detail: detail, AncestorSuspicious: ancestorSuspicious, AncestorFilename: ancestorFilename,
	}

	e.dispatcher.Dispatch(e.enrichAlert(a))
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
