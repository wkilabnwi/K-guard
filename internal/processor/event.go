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

// Router decodes raw ring buffer samples and dispatches them to the Engine
// Kept separate from Engine itself so decoding concerns (byte layout,
// event-type dispatch) don't get tangled up with policy concerns
type Router struct {
	engine  *Engine
	metrics *metrics.Registry
}

func NewRouter(engine *Engine, m *metrics.Registry) *Router {
	return &Router{engine: engine, metrics: m}
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

	switch et {
	case kebpf.EventExec:
		if filename == "" {
			filename = "UNKNOWN_OR_EMPTY"
		}
		r.engine.AnalyzeExec(comm, filename, event.Pid, event.Ppid, event.Uid, event.Gid, event.CgroupId, argv0, false)

	case kebpf.EventExecBlocked:
		if filename == "" {
			filename = "UNKNOWN_OR_EMPTY"
		}
		r.engine.AnalyzeExec(comm, filename, event.Pid, event.Ppid, event.Uid, event.Gid, event.CgroupId, argv0, true)

	case kebpf.EventConnect:
		// Only AF_INET carries a real destination right now, tp_connect in
		// kguard.c doesn't decode AF_UNIX/AF_INET6 addresses, so those show up
		// as a CONNECT alert with no destination at all. Docker (and plenty of
		// other daemons) generate a constant stream of local AF_UNIX socket
		// connects that drown out real outbound network signal, skip until
		// there's real decoding/filtering logic for those families.
		if event.Family != 2 {
			return
		}
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, event.Daddr)
		destIP := ip.String()
		r.engine.AnalyzeConnect(event.Pid, event.Ppid, event.Uid, event.Gid, comm, event.CgroupId, destIP, event.Dport)

	case kebpf.EventOpenSensitive:
		r.engine.AnalyzeGeneric("OPEN_SENSITIVE", config.SeverityHigh, event.Pid, event.Ppid, event.Uid, event.Gid, comm, event.CgroupId, filename, "")

	case kebpf.EventPtrace:
		r.engine.AnalyzeGeneric("PTRACE", config.SeverityMedium, event.Pid, event.Ppid, event.Uid, event.Gid, comm, event.CgroupId, "",
			fmt.Sprintf("ptrace request=%d", event.Ret))

	case kebpf.EventSetuid:
		r.engine.AnalyzeGeneric("SETUID", config.SeverityMedium, event.Pid, event.Ppid, event.Uid, event.Gid, comm, event.CgroupId, "",
			fmt.Sprintf("target uid=%d", event.Ret))

	case kebpf.EventModuleLoad:
		r.engine.AnalyzeGeneric("MODULE_LOAD", config.SeverityCritical, event.Pid, event.Ppid, event.Uid, event.Gid, comm, event.CgroupId, "", "")

	case kebpf.EventMemfd:
		r.engine.AnalyzeGeneric("MEMFD_CREATE", config.SeverityHigh, event.Pid, event.Ppid, event.Uid, event.Gid, comm, event.CgroupId, filename, "")
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
