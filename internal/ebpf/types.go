package ebpf

import "k-guard/internal/types"

// EventType mirrors the EVT defines in bpf/kguard.c, so better Keep it in sync
type EventType = types.EventType

const (
	EventExec             = types.EventExec
	EventExecBlocked      = types.EventExecBlocked
	EventConnect          = types.EventConnect
	EventOpenSensitive    = types.EventOpenSensitive
	EventPtrace           = types.EventPtrace
	EventSetuid           = types.EventSetuid
	EventModuleLoad       = types.EventModuleLoad
	EventMemfd            = types.EventMemfd
	EventSensitiveWrite   = types.EventSensitiveWrite
	EventWriteBlocked     = types.EventWriteBlocked
	EventPtraceBlocked    = types.EventPtraceBlocked
	EventKmodBlocked      = types.EventKmodBlocked
	EventIoUring          = types.EventIoUring
	EventLpeBlocked       = types.EventLpeBlocked
	EventBranchMispredict = types.EventBranchMispredict
	EventSendto           = types.EventSendto
	EventNsChange         = types.EventNsChange
	EventDnsAnswer        = types.EventDnsAnswer
	EventReverseShell     = types.EventReverseShell
)
