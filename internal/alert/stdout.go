package alert

import "fmt"

// StdoutSink prints a human-readable line per alert
type StdoutSink struct{}

func (StdoutSink) Name() string { return "stdout" }

func (StdoutSink) Send(a Alert) {
	tag := "AUDIT"
	if a.RuleName != "" {
		tag = "SECURITY"
	}

	fmt.Printf("[%s] %-14s sev=%-8s action=%-6s blocked=%-5v | %s\n",
		tag, a.EventType, a.Severity, a.Action, a.Blocked, a.RuleName)
	fmt.Printf("   | Comm: %-16s PID: %-8d PPID: %-8d UID: %-8d\n", a.Comm, a.Pid, a.Ppid, a.Uid)
	if a.Filename != "" {
		fmt.Printf("   | Path: %s\n", a.Filename)
	}
	if a.Argv0 != "" {
		fmt.Printf("   | Argv0: %s\n", a.Argv0)
	}
	if a.DestIP != "" {
		fmt.Printf("   | Dest: %s:%d\n", a.DestIP, a.DestPort)
	}
	if a.Detail != "" {
		fmt.Printf("   | Detail: %s\n", a.Detail)
	}
	if a.ResponseErr != "" {
		fmt.Printf("   | Response: %s\n", a.ResponseErr)
	} else if a.Action == "KILL" {
		fmt.Printf("   | Response: TERMINATED\n")
	} else if a.Blocked {
		fmt.Printf("   | Response: EXEC BLOCKED PRE-FLIGHT\n")
	}
}
