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

type EventMeta struct {
	EventType          kebpf.EventType
	TimestampNs        uint64
	PID                uint32
	PPID               uint32
	UID                uint32
	GID                uint32
	Comm               string
	CgroupID           uint64
	AncestorSuspicious bool
	AncestorFilename   string
	ExeDev             uint64
	ExeIno             uint64
	ParentExeDev       uint64
	ParentExeIno       uint64
	Ret                int64
}

type ProcessMeta struct {
	EventMeta
	Filename      string
	Args          string
	PathTruncated bool
	IsFileless    bool
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

type eventHandler func(r *Router, meta EventMeta, raw []byte) error

// Router decodes raw ring buffer samples and dispatches them to the Engine
// Kept separate from Engine itself so decoding concerns (byte layout,
// event-type dispatch) don't get tangled up with policy concerns
type Router struct {
	engine         *Engine
	metrics        *metrics.Registry
	cfg            *config.Manager
	ignoredConnect *trust.Set
	telemetryChan  chan MLRecord
	handlers       map[kebpf.EventType]eventHandler
}

func NewRouter(engine *Engine, m *metrics.Registry, cfg *config.Manager, telemetryChan chan MLRecord) *Router {
	r := &Router{
		engine:         engine,
		metrics:        m,
		cfg:            cfg,
		ignoredConnect: trust.NewSet(),
		telemetryChan:  telemetryChan,
	}
	r.initHandlers()
	r.applyConfig(cfg.Current())
	cfg.OnChange(r.applyConfig)
	return r
}

// ProcessRawRecord decodes one ring buffer sample and routes it. Decode
// errors are logged via the metrics ring-buffer-drop counter and otherwise
// swallowed to avoid a malformed record taking down the read loop

func (r *Router) initHandlers() {
	r.handlers = map[kebpf.EventType]eventHandler{
		kebpf.EventExec:             decodeExec,
		kebpf.EventExecBlocked:      decodeExec,
		kebpf.EventConnect:          decodeNetworkEgress,
		kebpf.EventSendto:           decodeNetworkEgress,
		kebpf.EventNsChange:         decodeNsChange,
		kebpf.EventOpenSensitive:    decodeOpen,
		kebpf.EventMemfd:            decodeOpen,
		kebpf.EventSensitiveWrite:   decodeOpen,
		kebpf.EventPtrace:           decodeGeneric,
		kebpf.EventSetuid:           decodeGeneric,
		kebpf.EventModuleLoad:       decodeGeneric,
		kebpf.EventWriteBlocked:     decodeWriteBlocked,
		kebpf.EventPtraceBlocked:    decodePtraceBlocked,
		kebpf.EventKmodBlocked:      decodeKmodBlocked,
		kebpf.EventIoUring:          decodeIoUring,
		kebpf.EventLpeBlocked:       decodeLpeBlocked,
		kebpf.EventBranchMispredict: decodePmu,
		kebpf.EventDnsAnswer:        decodeDnsAnswer,
		kebpf.EventReverseShell:     decodeExec,
	}
}

func (r *Router) ProcessRawRecord(raw []byte) {
	var hdr kebpf.BPFEventHdr
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &hdr); err != nil {
		r.metrics.IncRingbufDrop()
		return
	}

	et := kebpf.EventType(hdr.EventType)
	r.metrics.IncEvent(et.String())

	if r.telemetryChan != nil && (et == kebpf.EventExec || et == kebpf.EventExecBlocked) {
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
		}
	}

	ancestorFilename := int8ToString(hdr.AncestorFilename[:])
	if ancestorFilename != "" {
		ancestorFilename = filepath.Clean(ancestorFilename)
	}

	meta := EventMeta{
		EventType:          et,
		TimestampNs:        hdr.TimestampNs,
		PID:                hdr.Pid,
		PPID:               hdr.Ppid,
		UID:                hdr.Uid,
		GID:                hdr.Gid,
		Comm:               int8ToString(hdr.Comm[:]),
		CgroupID:           hdr.CgroupId,
		AncestorSuspicious: hdr.AncestorSuspicious == 1,
		AncestorFilename:   ancestorFilename,
		ExeDev:             hdr.ExeDev,
		ExeIno:             hdr.ExeIno,
		ParentExeDev:       hdr.ParentExeDev,
		ParentExeIno:       hdr.ParentExeIno,
		Ret:                int64(hdr.Ret),
	}

	handler, exists := r.handlers[et]
	if !exists {
		// Default case for unhandled or newly added BPF event types
		r.metrics.IncDecodeError()
		return
	}

	if err := handler(r, meta, raw); err != nil {
		r.metrics.IncDecodeError()
	}
}

// Handler functions (pure decoding & passing normalized structs to Engine)

func decodeExec(r *Router, meta EventMeta, raw []byte) error {
	var evt kebpf.BPFExecEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
		return err
	}

	pMeta := ProcessMeta{
		EventMeta:     meta,
		Filename:      resolveAbsolutePath(meta.PID, int8ToString(evt.Filename[:])),
		Args:          parseArgs(evt.Args[:]),
		PathTruncated: evt.PathTruncated == 1,
		IsFileless:    evt.IsFileless == 1,
	}
	if pMeta.Filename == "" {
		pMeta.Filename = "UNKNOWN_OR_EMPTY"
	}

	if meta.EventType == kebpf.EventReverseShell {
		r.engine.AnalyzeReverseShell(pMeta)
	} else {
		r.engine.AnalyzeExec(pMeta, meta.EventType == kebpf.EventExecBlocked)
	}
	return nil
}

func decodeNetworkEgress(r *Router, meta EventMeta, raw []byte) error {
	exeID := trust.FileID{Dev: meta.ExeDev, Ino: meta.ExeIno}
	if r.ignoredConnect.Contains(exeID) {
		return nil
	}

	var evt kebpf.BPFConnectEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
		return err
	}

	var destIP string
	destPort := evt.Dport

	switch evt.Family {
	case 1:
		path := int8ToString(evt.UnixPath[:])
		if path == "" {
			path = "(anonymous/abstract socket)"
		}
		destIP = "unix:" + path
		destPort = 0
	case 2:
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, evt.Daddr)
		if isLoopback(ip) {
			return nil
		}
		destIP = ip.String()
	case 10:
		ip := make(net.IP, 16)
		copy(ip, evt.Daddr6[:])
		if isLoopback(ip) {
			return nil
		}
		destIP = "[" + ip.String() + "]"
	default:
		destIP = fmt.Sprintf("(unknown address family %d)", evt.Family)
	}

	pMeta := ProcessMeta{EventMeta: meta}
	r.engine.AnalyzeNetworkEgress(pMeta, meta.EventType.String(), destIP, destPort)
	return nil
}

func decodeNsChange(r *Router, meta EventMeta, raw []byte) error {
	var evt kebpf.BPFNsChangeEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
		return err
	}
	r.engine.AnalyzeNsChange(ProcessMeta{EventMeta: meta}, evt.Op, evt.Flags, evt.Nstype)
	return nil
}

func decodeOpen(r *Router, meta EventMeta, raw []byte) error {
	var evt kebpf.BPFOpenEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
		return err
	}
	pMeta := ProcessMeta{
		EventMeta:     meta,
		Filename:      resolveAbsolutePath(meta.PID, int8ToString(evt.Filename[:])),
		PathTruncated: evt.PathTruncated == 1,
	}

	switch meta.EventType {
	case kebpf.EventOpenSensitive:
		r.engine.AnalyzeGeneric(pMeta, "OPEN_SENSITIVE", config.SeverityHigh, "")
	case kebpf.EventMemfd:
		r.engine.AnalyzeGeneric(pMeta, "MEMFD_CREATE", config.SeverityHigh, "")
	case kebpf.EventSensitiveWrite:
		detail := fmt.Sprintf("open flags=0x%x (write intent on protected path)", meta.Ret)
		r.engine.AnalyzeGeneric(pMeta, "SENSITIVE_WRITE", config.SeverityCritical, detail)
	}
	return nil
}

func decodeGeneric(r *Router, meta EventMeta, _ []byte) error {
	pMeta := ProcessMeta{EventMeta: meta}

	switch meta.EventType {
	case kebpf.EventPtrace:
		detail := fmt.Sprintf("ptrace request=%d", meta.Ret)
		r.engine.AnalyzeGeneric(pMeta, "PTRACE", config.SeverityMedium, detail)
	case kebpf.EventSetuid:
		detail := fmt.Sprintf("target uid=%d", meta.Ret)
		r.engine.AnalyzeGeneric(pMeta, "SETUID", config.SeverityMedium, detail)
	case kebpf.EventModuleLoad:
		r.engine.AnalyzeGeneric(pMeta, "MODULE_LOAD", config.SeverityCritical, "")
	default:
		r.engine.AnalyzeGeneric(pMeta, meta.EventType.String(), config.SeverityMedium, "")
	}
	return nil
}

func decodeWriteBlocked(r *Router, meta EventMeta, raw []byte) error {
	var evt kebpf.BPFOpenEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
		return err
	}
	pMeta := ProcessMeta{
		EventMeta:     meta,
		Filename:      int8ToString(evt.Filename[:]),
		PathTruncated: evt.PathTruncated == 1,
	}
	r.engine.AnalyzeWriteBlocked(pMeta)
	return nil
}

func decodePtraceBlocked(r *Router, meta EventMeta, raw []byte) error {
	var evt kebpf.BPFPtraceEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
		return err
	}
	targetComm := int8ToString(evt.TargetComm[:])
	if targetComm == "" {
		targetComm = "UNKNOWN"
	}
	r.engine.AnalyzePtraceBlocked(ProcessMeta{EventMeta: meta}, targetComm, uint32(evt.TargetPid), uint32(evt.Mode))
	return nil
}

func decodeKmodBlocked(r *Router, meta EventMeta, raw []byte) error {
	var evt kebpf.BPFKmodEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
		return err
	}
	pMeta := ProcessMeta{EventMeta: meta}
	if kmodComm := int8ToString(evt.Hdr.Comm[:]); kmodComm != "" {
		pMeta.Comm = kmodComm
	}
	r.engine.AnalyzeKmodBlocked(pMeta)
	return nil
}

func decodeIoUring(r *Router, meta EventMeta, raw []byte) error {
	var evt kebpf.BPFIouringEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
		return err
	}
	pMeta := ProcessMeta{
		EventMeta: meta,
		Filename:  int8ToString(evt.Filename[:]),
	}
	r.engine.AnalyzeIoUring(pMeta, evt.Opcode)
	return nil
}

func decodeLpeBlocked(r *Router, meta EventMeta, raw []byte) error {
	var evt kebpf.BPFLpeEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
		return err
	}
	r.engine.AnalyzeLpeBlocked(ProcessMeta{EventMeta: meta}, evt.OldUid, evt.NewUid)
	return nil
}

func decodePmu(r *Router, meta EventMeta, raw []byte) error {
	var evt kebpf.BPFPmuEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
		return err
	}
	r.engine.AnalyzePmu(ProcessMeta{EventMeta: meta}, evt.MispredCount)
	return nil
}

func decodeDnsAnswer(r *Router, meta EventMeta, raw []byte) error {
	var evt kebpf.BPFDnsAnswerEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
		return err
	}
	qname := parseDNSQName(evt.Qname[:])
	if qname == "" {
		return nil
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
		return nil
	}
	r.engine.RecordDNSAnswer(meta.CgroupID, ip, qname)
	return nil
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
