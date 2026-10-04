package types

import "fmt"

// FileID represents a canonical VFS file identity
type FileID struct {
	Dev uint64 `json:"dev" yaml:"dev"`
	Ino uint64 `json:"ino" yaml:"ino"`
}

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var severityRank = map[Severity]int{
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

func (s Severity) Rank() int { return severityRank[s] }

type Action string

const (
	ActionAlert Action = "ALERT"
	ActionKill  Action = "KILL"
	ActionBlock Action = "BLOCK"
)

type MitreMeta struct {
	Tactic      string   `json:"tactic,omitempty" yaml:"tactic,omitempty"`
	TechniqueID string   `json:"technique_id,omitempty" yaml:"technique_id,omitempty"`
	Technique   string   `json:"technique,omitempty" yaml:"technique,omitempty"`
	Tags        []string `json:"tags,omitempty" yaml:"tags,omitempty"`
}

type EventType uint32

const (
	EventExec             EventType = 1
	EventExecBlocked      EventType = 2
	EventConnect          EventType = 3
	EventOpenSensitive    EventType = 4
	EventPtrace           EventType = 5
	EventSetuid           EventType = 6
	EventModuleLoad       EventType = 7
	EventMemfd            EventType = 8
	EventSensitiveWrite   EventType = 9
	EventWriteBlocked     EventType = 10
	EventPtraceBlocked    EventType = 11
	EventKmodBlocked      EventType = 12
	EventIoUring          EventType = 13
	EventLpeBlocked       EventType = 14
	EventBranchMispredict EventType = 15
	EventSendto           EventType = 16
	EventNsChange         EventType = 17
	EventDnsAnswer        EventType = 18
	EventReverseShell     EventType = 19
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
	case EventPtraceBlocked:
		return "PTRACE_BLOCKED"
	case EventKmodBlocked:
		return "KMOD_BLOCKED"
	case EventIoUring:
		return "IO_URING"
	case EventLpeBlocked:
		return "LPE_BLOCKED"
	case EventBranchMispredict:
		return "BRANCH_MISPREDICT"
	case EventSendto:
		return "SENDTO"
	case EventNsChange:
		return "NS_CHANGE"
	case EventDnsAnswer:
		return "DNS_ANSWER"
	case EventReverseShell:
		return "REVERSE_SHELL"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}
