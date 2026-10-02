package processor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"k-guard/internal/alert"
	"k-guard/internal/audit"
	"k-guard/internal/config"
	kebpf "k-guard/internal/ebpf"
	"k-guard/internal/metrics"
	"k-guard/internal/trust"
)

type ProcessMeta struct {
	PID                uint32
	PPID               uint32
	UID                uint32
	GID                uint32
	Comm               string
	CgroupID           uint64
	Filename           string
	Args               string
	AncestorSuspicious bool
	AncestorFilename   string
	PathTruncated      bool
	IsFileless         bool
}

func isLoopback(ip net.IP) bool {
	return ip.IsLoopback()
}

func isIgnoredComm(comms []string, comm string) bool {
	for _, c := range comms {
		if c == comm {
			return true
		}
	}
	return false
}

// Router decodes raw ring buffer samples and dispatches them to the Engine
// Kept separate from Engine itself so decoding concerns (byte layout,
// event-type dispatch) don't get tangled up with policy concerns
type Router struct {
	engine  *Engine
	metrics *metrics.Registry
	cfg     *config.Manager

	ignoredConnect *trust.Set

	telemetryChan chan MLRecord
}

type MLRecord struct {
	Timestamp uint64
	ParentDev uint64
	ParentIno uint64
	ChildDev  uint64
	ChildIno  uint64
	CgroupID  uint64
	EventType uint32
	UID       uint32
}

func NewRouter(engine *Engine, m *metrics.Registry, cfg *config.Manager, telemetryChan chan MLRecord) *Router {
	r := &Router{
		engine:         engine,
		metrics:        m,
		cfg:            cfg,
		ignoredConnect: trust.NewSet(),
		telemetryChan:  telemetryChan,
	}
	r.applyConfig(cfg.Current())
	cfg.OnChange(r.applyConfig)
	return r
}

// ProcessRawRecord decodes one ring buffer sample and routes it. Decode
// errors are logged via the metrics ring-buffer-drop counter and otherwise
// swallowed to avoid a malformed record taking down the read loop

func (r *Router) ProcessRawRecord(raw []byte) {
	var hdr kebpf.BPFEventHdr
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &hdr); err != nil {
		r.metrics.IncRingbufDrop()
		return
	}

	if r.telemetryChan != nil && (hdr.EventType == uint32(kebpf.EventExec) || hdr.EventType == uint32(kebpf.EventExecBlocked)) {
		select {
		case r.telemetryChan <- MLRecord{
			Timestamp: hdr.TimestampNs,
			ParentDev: hdr.ParentExeDev,
			ParentIno: hdr.ParentExeIno,
			ChildDev:  hdr.ExeDev,
			ChildIno:  hdr.ExeIno,
			CgroupID:  hdr.CgroupId,
			EventType: hdr.EventType,
			UID:       hdr.Uid,
		}:
		default:
			// Drop under heavy ringbuf load to protect agent latency
		}
	}

	et := kebpf.EventType(hdr.EventType)
	r.metrics.IncEvent(et.String())

	ancestorFilename := int8ToString(hdr.AncestorFilename[:])
	if ancestorFilename != "" {
		ancestorFilename = filepath.Clean(ancestorFilename)
	}

	// Build common baseline ProcessMeta context
	meta := ProcessMeta{
		PID:                hdr.Pid,
		PPID:               hdr.Ppid,
		UID:                hdr.Uid,
		GID:                hdr.Gid,
		Comm:               int8ToString(hdr.Comm[:]),
		CgroupID:           hdr.CgroupId,
		AncestorSuspicious: hdr.AncestorSuspicious == 1,
		AncestorFilename:   ancestorFilename,
	}

	switch et {
	case kebpf.EventExec, kebpf.EventExecBlocked:
		var evt kebpf.BPFExecEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
			r.metrics.IncRingbufDrop()
			return
		}

		uncleanfilename := int8ToString(evt.Filename[:])
		meta.Filename = resolveAbsolutePath(hdr.Pid, uncleanfilename)
		if meta.Filename == "" {
			meta.Filename = "UNKNOWN_OR_EMPTY"
		}
		meta.Args = parseArgs(evt.Args[:])
		meta.PathTruncated = evt.PathTruncated == 1
		meta.IsFileless = evt.IsFileless == 1

		r.engine.AnalyzeExec(meta, et == kebpf.EventExecBlocked)

	case kebpf.EventConnect, kebpf.EventSendto:
		exeID := trust.FileID{Dev: hdr.ExeDev, Ino: hdr.ExeIno}
		if r.ignoredConnect.Contains(exeID) {
			return
		}

		var evt kebpf.BPFConnectEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
			r.metrics.IncRingbufDrop()
			return
		}

		var destIP string
		destPort := evt.Dport

		switch evt.Family {
		case 1: // AF_UNIX
			path := int8ToString(evt.UnixPath[:])
			if path == "" {
				path = "(anonymous/abstract socket)"
			}
			destIP = "unix:" + path
			destPort = 0

		case 2: // AF_INET
			ip := make(net.IP, 4)
			binary.LittleEndian.PutUint32(ip, evt.Daddr)
			if isLoopback(ip) {
				return
			}
			destIP = ip.String()

		case 10: // AF_INET6
			ip := make(net.IP, 16)
			copy(ip, evt.Daddr6[:])
			if isLoopback(ip) {
				return
			}
			destIP = "[" + ip.String() + "]"

		default:
			destIP = fmt.Sprintf("(unknown address family %d)", evt.Family)
		}

		r.engine.AnalyzeNetworkEgress(meta, et.String(), destIP, destPort)

	case kebpf.EventNsChange:
		var evt kebpf.BPFNsChangeEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
			r.metrics.IncRingbufDrop()
			return
		}

		r.engine.AnalyzeNsChange(meta, evt.Op, evt.Flags, evt.Nstype)

	case kebpf.EventOpenSensitive, kebpf.EventMemfd, kebpf.EventSensitiveWrite:
		var evt kebpf.BPFOpenEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
			r.metrics.IncRingbufDrop()
			return
		}

		uncleanfilename := int8ToString(evt.Filename[:])
		meta.Filename = resolveAbsolutePath(hdr.Pid, uncleanfilename)
		meta.PathTruncated = evt.PathTruncated == 1

		switch et {
		case kebpf.EventOpenSensitive:
			r.engine.AnalyzeGeneric(meta, "OPEN_SENSITIVE", config.SeverityHigh, "")
		case kebpf.EventMemfd:
			r.engine.AnalyzeGeneric(meta, "MEMFD_CREATE", config.SeverityHigh, "")
		case kebpf.EventSensitiveWrite:
			detail := fmt.Sprintf("open flags=0x%x (write intent on protected path)", hdr.Ret)
			r.engine.AnalyzeGeneric(meta, "SENSITIVE_WRITE", config.SeverityCritical, detail)
		}

	case kebpf.EventPtrace:
		detail := fmt.Sprintf("ptrace request=%d", hdr.Ret)
		r.engine.AnalyzeGeneric(meta, "PTRACE", config.SeverityMedium, detail)

	case kebpf.EventSetuid:
		detail := fmt.Sprintf("target uid=%d", hdr.Ret)
		r.engine.AnalyzeGeneric(meta, "SETUID", config.SeverityMedium, detail)

	case kebpf.EventModuleLoad:
		r.engine.AnalyzeGeneric(meta, "MODULE_LOAD", config.SeverityCritical, "")

	case kebpf.EventWriteBlocked:
		var evt kebpf.BPFOpenEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
			r.metrics.IncRingbufDrop()
			return
		}

		meta.Filename = int8ToString(evt.Filename[:])
		meta.PathTruncated = evt.PathTruncated == 1

		r.engine.AnalyzeWriteBlocked(meta)

	case kebpf.EventPtraceBlocked:
		var evt kebpf.BPFPtraceEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
			r.metrics.IncRingbufDrop()
			return
		}

		targetComm := int8ToString(evt.TargetComm[:])
		if targetComm == "" {
			targetComm = "UNKNOWN"
		}

		r.engine.AnalyzePtraceBlocked(meta, targetComm, uint32(evt.TargetPid), uint32(evt.Mode))

	case kebpf.EventKmodBlocked:
		var evt kebpf.BPFKmodEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
			r.metrics.IncRingbufDrop()
			return
		}

		if kmodComm := int8ToString(evt.Hdr.Comm[:]); kmodComm != "" {
			meta.Comm = kmodComm
		}

		r.engine.AnalyzeKmodBlocked(meta)

	case kebpf.EventIoUring:
		var evt kebpf.BPFIouringEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
			r.metrics.IncRingbufDrop()
			return
		}

		meta.Filename = int8ToString(evt.Filename[:])
		r.engine.AnalyzeIoUring(meta, evt.Opcode)

	case kebpf.EventLpeBlocked:
		var evt kebpf.BPFLpeEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
			r.metrics.IncRingbufDrop()
			return
		}

		r.engine.AnalyzeLpeBlocked(meta, evt.OldUid, evt.NewUid)

	case kebpf.EventBranchMispredict:
		var evt kebpf.BPFPmuEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
			r.metrics.IncRingbufDrop()
			return
		}

		r.engine.AnalyzePmu(meta, evt.MispredCount)

	case kebpf.EventDnsAnswer:
		var evt kebpf.BPFDnsAnswerEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
			r.metrics.IncRingbufDrop()
			return
		}

		qname := parseDNSQName(evt.Qname[:])
		if qname == "" {
			return
		}

		var ip string
		switch evt.Family {
		case 2:
			b := make(net.IP, 4)
			binary.LittleEndian.PutUint32(b, evt.Daddr)
			ip = b.String()
		case 10:
			b := make(net.IP, 16)
			copy(b, evt.Daddr6[:])
			ip = b.String()
		default:
			return
		}

		r.engine.RecordDNSAnswer(hdr.CgroupId, ip, qname)

	case kebpf.EventReverseShell:
		var evt kebpf.BPFExecEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
			r.metrics.IncRingbufDrop()
			return
		}

		uncleanfilename := int8ToString(evt.Filename[:])
		meta.Filename = resolveAbsolutePath(hdr.Pid, uncleanfilename)
		if meta.Filename == "" {
			meta.Filename = "UNKNOWN_OR_EMPTY"
		}
		meta.Args = parseArgs(evt.Args[:])

		r.engine.AnalyzeReverseShell(meta)
	}
}

// This function is used to handle C type strings ending with \x00
// turning them into usable strings for our Processor function
func int8ToString(bs []int8) string {
	b := make([]byte, 0, len(bs))
	for _, v := range bs {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}

func resolveAbsolutePath(pid uint32, rawPath string) string {
	if rawPath == "" {
		return ""
	}

	clean := filepath.Clean(rawPath)

	// If it's already an absolute path (starts with /), return immediately
	if filepath.IsAbs(clean) {
		return clean
	}

	// For relative paths, evaluate against the process's working directory in /proc
	procCwd := fmt.Sprintf("/proc/%d/cwd/%s", pid, clean)
	if resolved, err := filepath.EvalSymlinks(procCwd); err == nil {
		return resolved
	}

	return clean
}

// parseArgs processes the null-separated argument block from mm_struct
func parseArgs(bs []int8) string {
	b := make([]byte, 0, len(bs))
	for i := 0; i < len(bs); i++ {
		v := bs[i]
		if v == 0 {
			if i+1 < len(bs) && bs[i+1] == 0 {
				break
			}
			b = append(b, ' ')
			continue
		}
		b = append(b, byte(v))
	}
	return string(bytes.TrimSpace(b))
}

func (r *Router) applyConfig(c *config.Config) {
	r.ignoredConnect.Sync(c.IgnoredConnectComms, "ignored_connect_comms")
}

func parseDNSQName(raw []int8) string {
	b := make([]byte, 0, len(raw))
	for _, v := range raw {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}

	var labels []string
	idx := 0
	for idx < len(b) {
		length := int(b[idx])
		if length == 0 {
			break
		}
		if length > 63 || idx+1+length > len(b) {
			break
		}
		label := string(b[idx+1 : idx+1+length])
		labels = append(labels, label)
		idx += 1 + length
	}

	if len(labels) == 0 {
		return ""
	}
	return strings.Join(labels, ".")
}

func (m ProcessMeta) ToAlert(eventType string, sev config.Severity, act config.Action, detail string) alert.Alert {
	return alert.Alert{
		EventType:          eventType,
		Severity:           string(sev),
		Action:             string(act),
		Pid:                m.PID,
		Ppid:               m.PPID,
		Uid:                m.UID,
		Gid:                m.GID,
		Comm:               m.Comm,
		CgroupID:           m.CgroupID,
		Filename:           m.Filename,
		Args:               m.Args,
		AncestorSuspicious: m.AncestorSuspicious,
		AncestorFilename:   m.AncestorFilename,
		PathTruncated:      m.PathTruncated,
		Detail:             detail,
	}
}

func (m ProcessMeta) ToAuditRecord(decision audit.Decision, eventType, ruleName string, mitre *config.MitreMeta, target, reason string) audit.Record {
	return audit.Record{
		Decision:  decision,
		EventType: eventType,
		RuleName:  ruleName,
		Mitre:     mitre,
		PID:       m.PID,
		PPID:      m.PPID,
		UID:       m.UID,
		Comm:      m.Comm,
		CgroupID:  m.CgroupID,
		Target:    target,
		Reason:    reason,
	}
}
