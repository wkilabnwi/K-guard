package config

import (
	"fmt"
	"path/filepath"
	"strings"

	"cel.dev/cel-go/cel"
)

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

// ProcessContext is exposed inside CEL expressions under process.*
type ProcessContext struct {
	Path       string   `cel:"path"`
	Basename   string   `cel:"basename"`
	SHA256     string   `cel:"sha256"`
	PID        int64    `cel:"pid"`
	PPID       int64    `cel:"ppid"`
	UID        int64    `cel:"uid"`
	GID        int64    `cel:"gid"`
	Comm       string   `cel:"comm"`
	Args       []string `cel:"args"`
	IsFileless bool     `cel:"is_fileless"`
}

// EventContext is the top-level object passed into CEL expressions under event.*
type EventContext struct {
	Type               string         `cel:"type"`
	AncestorSuspicious bool           `cel:"ancestor_suspicious"`
	AncestorFilename   string         `cel:"ancestor_filename"`
	IsSuspiciousPath   bool           `cel:"is_suspicious_path"`
	Process            ProcessContext `cel:"process"`
}

type Rule struct {
	Name       string   `yaml:"name" json:"name"`
	Severity   Severity `yaml:"severity" json:"severity"`
	Action     Action   `yaml:"action" json:"action"`
	Expression string   `yaml:"expression" json:"expression"`

	// Pre-compiled CEL program handle
	Program cel.Program `yaml:"-" json:"-"`

	// ExactBlockPath is extracted automatically from simple exact path expressions for LSM sync
	ExactBlockPath string `yaml:"-" json:"-"`
}

func (r *Rule) Validate(celEnv *cel.Env) error {
	if r.Name == "" {
		return fmt.Errorf("rule missing name")
	}
	switch r.Severity {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
	default:
		return fmt.Errorf("rule %q: unknown severity %q", r.Name, r.Severity)
	}
	switch r.Action {
	case ActionAlert, ActionKill, ActionBlock:
	default:
		return fmt.Errorf("rule %q: unknown action %q", r.Name, r.Action)
	}
	if strings.TrimSpace(r.Expression) == "" {
		return fmt.Errorf("rule %q: empty expression", r.Name)
	}

	// Compile and type-check the CEL expression
	ast, issues := celEnv.Compile(r.Expression)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("rule %q CEL syntax error: %w", r.Name, issues.Err())
	}

	prg, err := celEnv.Program(ast)
	if err != nil {
		return fmt.Errorf("rule %q failed to generate CEL program: %w", r.Name, err)
	}
	r.Program = prg

	// Helper extract for exact_path matching used by LSM pre-exec block hooks
	if r.Action == ActionBlock && strings.Contains(r.Expression, "process.path ==") {
		parts := strings.Split(r.Expression, "process.path ==")
		if len(parts) == 2 {
			r.ExactBlockPath = strings.Trim(strings.TrimSpace(parts[1]), "\"'`")
		}
	}

	return nil
}

type SinksConfig struct {
	Stdout              bool   `yaml:"stdout" json:"stdout"`
	Syslog              bool   `yaml:"syslog" json:"syslog"`
	WebhookURL          string `yaml:"webhook_url,omitempty" json:"webhook_url,omitempty"`
	StorePath           string `yaml:"store_path,omitempty" json:"store_path,omitempty"`
	MetricsListenAddr   string `yaml:"metrics_listen_addr,omitempty" json:"metrics_listen_addr,omitempty"`
	DashboardListenAddr string `yaml:"dashboard_listen_addr,omitempty" json:"dashboard_listen_addr,omitempty"`

	DashboardAuthToken string `yaml:"dashboard_auth_token,omitempty" json:"dashboard_auth_token,omitempty"`
	MetricsAuthToken   string `yaml:"metrics_auth_token,omitempty" json:"metrics_auth_token,omitempty"`
}

type Config struct {
	Rules                    []Rule      `yaml:"rules" json:"rules"`
	Allowlist                []string    `yaml:"allowlist" json:"allowlist"`
	ProtectedPIDs            []int       `yaml:"protected_pids,omitempty" json:"protected_pids,omitempty"`
	ProtectedComms           []string    `yaml:"protected_comms,omitempty" json:"protected_comms,omitempty"`
	EnforcementEnabled       bool        `yaml:"enforcement_enabled" json:"enforcement_enabled"`
	DedupWindowSeconds       int         `yaml:"dedup_window_seconds" json:"dedup_window_seconds"`
	Sinks                    SinksConfig `yaml:"sinks" json:"sinks"`
	SuspiciousPaths          []string    `yaml:"suspicious_path,omitempty" json:"suspicious_path,omitempty"`
	IgnoredConnectComms      []string    `yaml:"ignored_connect_comms,omitempty" json:"ignored_connect_comms,omitempty"`
	SensitiveWritePaths      []string    `yaml:"sensitive_write_paths,omitempty" json:"sensitive_write_paths,omitempty"`
	BlockedWritePaths        []string    `yaml:"blocked_write_paths,omitempty" json:"blocked_write_paths,omitempty"`
	PtraceEnforcementEnabled bool        `yaml:"ptrace_enforcement_enabled" json:"ptrace_enforcement_enabled"`
	AllowedPtraceAttached    []string    `yaml:"allowed_ptrace_attaches,omitempty" json:"allowed_ptrace_attaches,omitempty"`
	KmodEnforcementEnabled   bool        `yaml:"kmod_enforcement_enabled" json:"kmod_enforcement_enabled"`
	KubeletURL               string      `yaml:"kubelet_url,omitempty" json:"kubelet_url,omitempty"`
	ProcPath                 string      `yaml:"proc_path,omitempty" json:"proc_path,omitempty"`
	CgroupPath               string      `yaml:"cgroup_path,omitempty" json:"cgroup_path,omitempty"`
	KubeletInsecure          bool        `yaml:"kubelet_insecure,omitempty" json:"kubelet_insecure,omitempty"`
	KubeletCertFile          string      `yaml:"kubelet_cert_file,omitempty" json:"kubelet_cert_file,omitempty"`
	KubeletKeyFile           string      `yaml:"kubelet_key_file,omitempty" json:"kubelet_key_file,omitempty"`
}

func (c *Config) applyDefaults() {
	if c.DedupWindowSeconds == 0 {
		c.DedupWindowSeconds = 10
	}
	if c.Sinks == (SinksConfig{}) {
		c.Sinks.Stdout = true
	}
}

func (c *Config) Validate(celEnv *cel.Env) error {
	for i := range c.Rules {
		if err := c.Rules[i].Validate(celEnv); err != nil {
			return err
		}
	}
	for _, pid := range c.ProtectedPIDs {
		if pid <= 0 {
			return fmt.Errorf("invalid protected_pids entry: %d", pid)
		}
	}
	if c.DedupWindowSeconds < 0 {
		return fmt.Errorf("dedup_window_seconds must be >= 0")
	}

	for field, entries := range c.nonEmptyPathLists() {
		for _, p := range entries {
			if p == "" {
				return fmt.Errorf("%s: empty string entries are not allowed", field)
			}
		}
	}

	for field, entries := range c.commLists() {
		for _, p := range entries {
			if p == "" {
				return fmt.Errorf("%s: empty string entries are not allowed", field)
			}
			if !filepath.IsAbs(p) {
				return fmt.Errorf("%s: %q must be an absolute path", field, p)
			}
		}
	}
	return nil
}

func (c *Config) nonEmptyPathLists() map[string][]string {
	return map[string][]string{
		"suspicious_path":       c.SuspiciousPaths,
		"sensitive_write_paths": c.SensitiveWritePaths,
		"blocked_write_paths":   c.BlockedWritePaths,
		"allowlist":             c.Allowlist,
	}
}

func (c *Config) commLists() map[string][]string {
	return map[string][]string{
		"protected_comms":         c.ProtectedComms,
		"ignored_connect_comms":   c.IgnoredConnectComms,
		"allowed_ptrace_attaches": c.AllowedPtraceAttached,
	}
}

func (c *Config) BlockedPatterns() []string {
	var out []string
	for _, r := range c.Rules {
		if r.Action == ActionBlock && r.ExactBlockPath != "" {
			out = append(out, r.ExactBlockPath)
		}
	}
	return out
}
