package processor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"k-guard/internal/config"
	kebpf "k-guard/internal/ebpf"
	"k-guard/internal/metrics"
	"k-guard/internal/trust"
)

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
	// Unmarshal the common header first
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

	comm := int8ToString(hdr.Comm[:])

	ancestorSuspicious := hdr.AncestorSuspicious == 1
	ancestorFilename := filepath.Clean(int8ToString(hdr.AncestorFilename[:]))

	switch et {
	case kebpf.EventExec, kebpf.EventExecBlocked:
		var evt kebpf.BPFExecEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
			r.metrics.IncRingbufDrop()
			return
		}

		uncleanfilename := int8ToString(evt.Filename[:])
		filename := resolveAbsolutePath(hdr.Pid, uncleanfilename)
		if filename == "" {
			filename = "UNKNOWN_OR_EMPTY"
		}
		args := parseArgs(evt.Args[:])
		pathTruncated := evt.PathTruncated == 1
		isFileless := evt.IsFileless == 1

		isBlocked := (et == kebpf.EventExecBlocked)

		r.engine.AnalyzeExec(
			comm, filename, hdr.Pid, hdr.Ppid, hdr.Uid, hdr.Gid,
			hdr.CgroupId, args, isBlocked, ancestorSuspicious,
			ancestorFilename, pathTruncated, isFileless,
		)

	case kebpf.EventConnect, kebpf.EventSendto:
		exeID := trust.FileID{Dev: hdr.ExeDev, Ino: hdr.ExeIno}
		if r.ignoredConnect.Contains(exeID) {
			return
		}

		var daddr uint32
		var daddr6 [16]uint8
		var dport uint16
		var family uint16
		var unixPath [108]int8

		var evt kebpf.BPFConnectEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
			r.metrics.IncRingbufDrop()
			return
		}
		daddr, daddr6, dport, family, unixPath = evt.Daddr, evt.Daddr6, evt.Dport, evt.Family, evt.UnixPath

		var destIP string
		destPort := dport

		switch family {
		case 1: // AF_UNIX
			path := int8ToString(unixPath[:])
			if path == "" {
				path = "(anonymous/abstract socket)"
			}
			destIP = "unix:" + path
			destPort = 0

		case 2: // AF_INET
			ip := make(net.IP, 4)
			binary.LittleEndian.PutUint32(ip, daddr)
			if isLoopback(ip) {
				return
			}
			destIP = ip.String()

		case 10: // AF_INET6
			ip := make(net.IP, 16)
			copy(ip, daddr6[:])
			if isLoopback(ip) {
				return
			}
			destIP = "[" + ip.String() + "]"

		default:
			destIP = fmt.Sprintf("(unknown address family %d)", family)
		}

		r.engine.AnalyzeNetworkEgress(
			string(et.String()), hdr.Pid, hdr.Ppid, hdr.Uid, hdr.Gid, comm,
			hdr.CgroupId, destIP, destPort, ancestorSuspicious, ancestorFilename,
		)

	case kebpf.EventNsChange:
		var evt kebpf.BPFNsChangeEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
			r.metrics.IncRingbufDrop()
			return
		}

		r.engine.AnalyzeNsChange(
			hdr.Pid, hdr.Ppid, hdr.Uid, hdr.Gid, comm, hdr.CgroupId,
			evt.Op, evt.Flags, evt.Nstype, ancestorSuspicious, ancestorFilename,
		)

	case kebpf.EventOpenSensitive, kebpf.EventMemfd, kebpf.EventSensitiveWrite:
		var evt kebpf.BPFOpenEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
			r.metrics.IncRingbufDrop()
			return
		}

		uncleanfilename := int8ToString(evt.Filename[:])
		filename := resolveAbsolutePath(hdr.Pid, uncleanfilename)
		pathTruncated := evt.PathTruncated == 1

		switch et {
		case kebpf.EventOpenSensitive:
			r.engine.AnalyzeGeneric("OPEN_SENSITIVE", config.SeverityHigh, hdr.Pid, hdr.Ppid, hdr.Uid, hdr.Gid, comm, hdr.CgroupId, filename, "", ancestorSuspicious, ancestorFilename, pathTruncated)
		case kebpf.EventMemfd:
			r.engine.AnalyzeGeneric("MEMFD_CREATE", config.SeverityHigh, hdr.Pid, hdr.Ppid, hdr.Uid, hdr.Gid, comm, hdr.CgroupId, filename, "", ancestorSuspicious, ancestorFilename, pathTruncated)
		case kebpf.EventSensitiveWrite:
			r.engine.AnalyzeGeneric("SENSITIVE_WRITE", config.SeverityCritical, hdr.Pid, hdr.Ppid, hdr.Uid, hdr.Gid, comm, hdr.CgroupId, filename, fmt.Sprintf("open flags=0x%x (write intent on protected path)", hdr.Ret), ancestorSuspicious, ancestorFilename, pathTruncated)
		}

	case kebpf.EventPtrace:
		r.engine.AnalyzeGeneric("PTRACE", config.SeverityMedium, hdr.Pid, hdr.Ppid, hdr.Uid, hdr.Gid, comm, hdr.CgroupId, "", fmt.Sprintf("ptrace request=%d", hdr.Ret), ancestorSuspicious, ancestorFilename, false)

	case kebpf.EventSetuid:
		r.engine.AnalyzeGeneric("SETUID", config.SeverityMedium, hdr.Pid, hdr.Ppid, hdr.Uid, hdr.Gid, comm, hdr.CgroupId, "", fmt.Sprintf("target uid=%d", hdr.Ret), ancestorSuspicious, ancestorFilename, false)

	case kebpf.EventModuleLoad:
		r.engine.AnalyzeGeneric("MODULE_LOAD", config.SeverityCritical, hdr.Pid, hdr.Ppid, hdr.Uid, hdr.Gid, comm, hdr.CgroupId, "", "", ancestorSuspicious, ancestorFilename, false)
	case kebpf.EventWriteBlocked:
		var evt kebpf.BPFOpenEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
			r.metrics.IncRingbufDrop()
			return
		}

		filename := int8ToString(evt.Filename[:])
		pathTruncated := evt.PathTruncated == 1

		r.engine.AnalyzeWriteBlocked(
			comm, filename, hdr.Pid, hdr.Ppid, hdr.Uid, hdr.Gid,
			hdr.CgroupId, ancestorSuspicious, ancestorFilename, pathTruncated,
		)

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

		r.engine.AnalyzePtraceBlocked(
			comm, targetComm, uint32(evt.TargetPid), uint32(evt.Mode),
			hdr.Pid, hdr.Ppid, hdr.Uid, hdr.Gid, hdr.CgroupId,
			ancestorSuspicious, ancestorFilename,
		)
	case kebpf.EventKmodBlocked:
		var evt kebpf.BPFKmodEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
			r.metrics.IncRingbufDrop()
			return
		}

		comm := int8ToString(evt.Hdr.Comm[:])

		r.engine.AnalyzeKmodBlocked(
			comm,
			hdr.Pid,
			hdr.Ppid,
			hdr.Uid,
			hdr.Gid,
			hdr.CgroupId,
			ancestorSuspicious,
			ancestorFilename,
		)
	case kebpf.EventIoUring:
		var evt kebpf.BPFIouringEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
			r.metrics.IncRingbufDrop()
			return
		}

		filename := int8ToString(evt.Filename[:])
		r.engine.AnalyzeIoUring(hdr.Pid, hdr.Ppid, hdr.Uid, hdr.Gid, comm, filename, hdr.CgroupId, evt.Opcode, ancestorSuspicious, ancestorFilename)

	case kebpf.EventLpeBlocked:
		var evt kebpf.BPFLpeEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
			r.metrics.IncRingbufDrop()
			return
		}

		r.engine.AnalyzeLpeBlocked(
			comm,
			hdr.Pid,
			hdr.Ppid,
			hdr.Uid,
			hdr.Gid,
			hdr.CgroupId,
			evt.OldUid,
			evt.NewUid,
			ancestorSuspicious,
			ancestorFilename,
		)

	case kebpf.EventBranchMispredict:
		var evt kebpf.BPFPmuEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
			r.metrics.IncRingbufDrop()
			return
		}

		r.engine.AnalyzePmu(
			hdr.Pid, hdr.Ppid, hdr.Uid, hdr.Gid, comm,
			hdr.CgroupId, evt.MispredCount, ancestorSuspicious, ancestorFilename,
		)

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
