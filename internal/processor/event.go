package processor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"

	"k-guard/internal/config"
	kebpf "k-guard/internal/ebpf"
	"k-guard/internal/metrics"
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
}

func NewRouter(engine *Engine, m *metrics.Registry, cfg *config.Manager) *Router {
	return &Router{engine: engine, metrics: m, cfg: cfg}
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

	case kebpf.EventConnect:
		if isIgnoredComm(r.cfg.Current().IgnoredConnectComms, comm) {
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
			// Empty sun_path with no error usually means an abstract socket
			path := int8ToString(evt.UnixPath[:])
			if path == "" {
				path = "(anonymous/abstract socket)"
			}
			destIP = "unix:" + path
			destPort = 0

		case 2: // AF_INET
			ip := make(net.IP, 4)
			// Loopback connects are near-always local tooling
			// talking to itself so not worth alerting on, will defo change it later
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

		r.engine.AnalyzeConnect(
			hdr.Pid, hdr.Ppid, hdr.Uid, hdr.Gid, comm,
			hdr.CgroupId, destIP, destPort, ancestorSuspicious, ancestorFilename,
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
