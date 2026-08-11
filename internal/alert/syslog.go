//go:build linux || darwin || freebsd || netbsd || openbsd

package alert

import (
	"encoding/json"
	"fmt"
	"log"
	"log/syslog"
	"strings"
)

// SyslogSink ships every alert to the local syslog daemon at a
// severity mapped from the alert's own Severity field, tagged "k-guard"
// Uses only the Go stdlib log/syslog ,no external dependency needed
type SyslogSink struct {
	writer *syslog.Writer
}

func NewSyslogSink() (*SyslogSink, error) {
	w, err := syslog.New(syslog.LOG_WARNING|syslog.LOG_DAEMON, "k-guard")
	if err != nil {
		return nil, fmt.Errorf("connecting to syslog: %w", err)
	}
	return &SyslogSink{writer: w}, nil
}

func (s *SyslogSink) Name() string { return "syslog" }

func (s *SyslogSink) Send(a Alert) {
	line, err := json.Marshal(a)
	if err != nil {
		log.Printf("[syslog] marshal error: %v", err)
		return
	}

	msg := string(line)
	var werr error
	switch strings.ToLower(a.Severity) {
	case "critical":
		werr = s.writer.Crit(msg)
	case "high":
		werr = s.writer.Err(msg)
	case "medium":
		werr = s.writer.Warning(msg)
	default:
		werr = s.writer.Info(msg)
	}
	if werr != nil {
		log.Printf("[syslog] write error: %v", werr)
	}
}
