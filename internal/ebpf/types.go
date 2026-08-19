package ebpf

// EventType mirrors the EVT defines in bpf/kguard.c, so better Keep it in sync
type EventType uint32

const (
	EventExec           EventType = 1  // process executed (observed after the fact, tracepoint)
	EventExecBlocked    EventType = 2  // exec blocked pre-flight by the LSM hook
	EventConnect        EventType = 3  // outbound connect()
	EventOpenSensitive  EventType = 4  // openat(),openat2() on a sensitive path
	EventPtrace         EventType = 5  // ptrace() attach/injection attempt
	EventSetuid         EventType = 6  // setuid()/privilege change
	EventModuleLoad     EventType = 7  // init_module()/finit_module()
	EventMemfd          EventType = 8  // memfd_create(), fileless-exec precursor
	EventSensitiveWrite EventType = 9  // open() with write on a protected  path
	EventWriteBlocked   EventType = 10 // for blocked write events
)

func (t EventType) String() string {
	switch t {
	case EventExec:
		return "EXEC"
	case EventExecBlocked:
		return "EXEC_BLOCKED"
	case EventConnect:
		return "CONNECT"
	case EventOpenSensitive:
		return "OPEN_SENSITIVE"
	case EventPtrace:
		return "PTRACE"
	case EventSetuid:
		return "SETUID"
	case EventModuleLoad:
		return "MODULE_LOAD"
	case EventMemfd:
		return "MEMFD_CREATE"
	case EventSensitiveWrite:
		return "SENSITIVE_WRITE"
	case EventWriteBlocked:
		return "WRITE_BLOCKED"
	default:
		return "UNKNOWN"
	}
}
