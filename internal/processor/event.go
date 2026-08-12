package processor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

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
	var event kebpf.BPFKguardEvent
	if err := binary.Read(bytes.NewBuffer(raw), binary.LittleEndian, &event); err != nil {
		r.metrics.IncRingbufDrop()
		return
	}

	et := kebpf.EventType(event.EventType)
	r.metrics.IncEvent(et.String())

	comm := int8ToString(event.Comm[:])
	filename := int8ToString(event.Filename[:])
	argv0 := int8ToString(event.Argv0[:])

	ancestorSuspicious := event.AncestorSuspicious == 1
	ancestorFilename := int8ToString(event.AncestorFilename[:])

	pathTruncated := event.PathTruncated == 1

	switch et {
	case kebpf.EventExec:
		if filename == "" {
			filename = "UNKNOWN_OR_EMPTY"
		}
		r.engine.AnalyzeExec(comm, filename, event.Pid, event.Ppid, event.Uid, event.Gid, event.CgroupId, argv0, false, ancestorSuspicious, ancestorFilename, pathTruncated)

	case kebpf.EventExecBlocked:
		if filename == "" {
			filename = "UNKNOWN_OR_EMPTY"
		}
		r.engine.AnalyzeExec(comm, filename, event.Pid, event.Ppid, event.Uid, event.Gid, event.CgroupId, argv0, true, ancestorSuspicious, ancestorFilename, pathTruncated)

	case kebpf.EventConnect:
		// Skip known noisy background processes entirely
		if isIgnoredComm(r.cfg.Current().IgnoredConnectComms, comm) {
			return
		}

		var destIP string
		destPort := event.Dport

		switch event.Family {
		case 1: // AF_UNIX
			path := int8ToString(event.UnixPath[:])
			if path == "" {
				// Empty sun_path with no error usually means an abstract socket
				path = "(anonymous/abstract socket)"
			}
			destIP = "unix:" + path
			destPort = 0

		case 2: // AF_INET
			ip := make(net.IP, 4)
			binary.LittleEndian.PutUint32(ip, event.Daddr)
			// Loopback connects are near-always local tooling
			// talking to itself so not worth alerting on, will defo change it later
			if isLoopback(ip) {
				return
			}
			destIP = ip.String()

		case 10: // AF_INET6
			ip := make(net.IP, 16)
			copy(ip, event.Daddr6[:])
			if isLoopback(ip) {
				return
			}
			destIP = "[" + ip.String() + "]"

		default:
			destIP = fmt.Sprintf("(unknown address family %d)", event.Family)
		}

		r.engine.AnalyzeConnect(event.Pid, event.Ppid, event.Uid, event.Gid, comm, event.CgroupId, destIP, destPort, ancestorSuspicious, ancestorFilename)
	case kebpf.EventOpenSensitive:
		r.engine.AnalyzeGeneric("OPEN_SENSITIVE", config.SeverityHigh, event.Pid, event.Ppid, event.Uid, event.Gid, comm, event.CgroupId, filename, "", ancestorSuspicious, ancestorFilename, pathTruncated)

	case kebpf.EventPtrace:
		r.engine.AnalyzeGeneric("PTRACE", config.SeverityMedium, event.Pid, event.Ppid, event.Uid, event.Gid, comm, event.CgroupId, "",
			fmt.Sprintf("ptrace request=%d", event.Ret), ancestorSuspicious, ancestorFilename, pathTruncated)

	case kebpf.EventSetuid:
		r.engine.AnalyzeGeneric("SETUID", config.SeverityMedium, event.Pid, event.Ppid, event.Uid, event.Gid, comm, event.CgroupId, "",
			fmt.Sprintf("target uid=%d", event.Ret), ancestorSuspicious, ancestorFilename, pathTruncated)

	case kebpf.EventModuleLoad:
		r.engine.AnalyzeGeneric("MODULE_LOAD", config.SeverityCritical, event.Pid, event.Ppid, event.Uid, event.Gid, comm, event.CgroupId, "", "", ancestorSuspicious, ancestorFilename, pathTruncated)

	case kebpf.EventMemfd:
		r.engine.AnalyzeGeneric("MEMFD_CREATE", config.SeverityHigh, event.Pid, event.Ppid, event.Uid, event.Gid, comm, event.CgroupId, filename, "", ancestorSuspicious, ancestorFilename, pathTruncated)

	case kebpf.EventSensitiveWrite:
		r.engine.AnalyzeGeneric("SENSITIVE_WRITE", config.SeverityCritical,
			event.Pid, event.Ppid, event.Uid, event.Gid, comm, event.CgroupId,
			filename, fmt.Sprintf("open flags=0x%x (write intent on protected path)", event.Ret), ancestorSuspicious, ancestorFilename, pathTruncated)
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
