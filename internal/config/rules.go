package config

import (
	"fmt"
	"path/filepath"
)

// MatchKind controls how Rule.Pattern is compared against filename/path
// Prefer the specific kinds over MatchSubstring: substring
// matching is what the original version used (strings.Contains(filename,
// "nc")), and it is both a false positive magnet (matches
// "/home/vincent", sorry for everyone named vincent) and trivially evadable (rename the binary,
// symlink it, wrap it in a script with a different name)
type MatchKind string

const (
	MatchExactPath MatchKind = "exact_path"
	MatchBasename  MatchKind = "basename"
	MatchPrefix    MatchKind = "prefix"
	MatchSubstring MatchKind = "substring"
	MatchSHA256    MatchKind = "sha256"
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

// Rank returns a number for severity, useful for filtering or for the dashboard

func (s Severity) Rank() int { return severityRank[s] }

type Action string

const (
	ActionAlert Action = "ALERT" // log/alert only, take no enforcement action
	ActionKill  Action = "KILL"  // SIGKILL the offending Pid, the binary might run for a very short time before, this is usually a fallback
	ActionBlock Action = "BLOCK" // if Match is exact_path, Pattern is synced into the in-kernel LSM block list for real pre-exec prevention
)

type Rule struct {
	Name     string    `json:"name"`
	Match    MatchKind `json:"match"`
	Pattern  string    `json:"pattern"`
	Severity Severity  `json:"severity"`
	Action   Action    `json:"action"`

	SuspiciousPathOnly bool `json:"suspicious_path_only,omitempty"`
}

// Validate checks each rule in our config to see for any incomplete or bad rules
func (r Rule) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("rule missing name")
	}
	switch r.Match {
	case MatchExactPath, MatchBasename, MatchPrefix, MatchSubstring, MatchSHA256:
	default:
		return fmt.Errorf("rule %q: unknown match kind %q", r.Name, r.Match)
	}
	if r.Pattern == "" {
		return fmt.Errorf("rule %q: empty pattern", r.Name)
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
	return nil
}

// SinksConfig configures where alerts go.
type SinksConfig struct {
	Stdout              bool   `json:"stdout"`
	Syslog              bool   `json:"syslog"`
	WebhookURL          string `json:"webhook_url,omitempty"`
	StorePath           string `json:"store_path,omitempty"`
	MetricsListenAddr   string `json:"metrics_listen_addr,omitempty"`
	DashboardListenAddr string `json:"dashboard_listen_addr,omitempty"`

	DashboardAuthToken string `json:"dashboard_auth_token,omitempty"`
	MetricsAuthToken   string `json:"metrics_auth_token,omitempty"`
}

// Config is the full on-disk K-Guard configuration
type Config struct {
	// Rules is the ordered policy list
	Rules []Rule `json:"rules"`

	// Allowlist entries (exact path or basename) are checked before Rules
	// and, if matched we skip all rule evaluation for that exec entirely
	Allowlist []string `json:"allowlist"`

	// ProtectedPIDs/ProtectedComms are never killed regardless of what
	// rule matched
	ProtectedPIDs  []int    `json:"protected_pids,omitempty"`
	ProtectedComms []string `json:"protected_comms,omitempty"`

	// EnforcementEnabled is the desired state of the in-kernel LSM
	EnforcementEnabled bool `json:"enforcement_enabled"`

	// DedupWindowSeconds, identical alerts (same rule + same pid) within
	// this window are suppressed after the first, 0 disables it
	DedupWindowSeconds int `json:"dedup_window_seconds"`

	Sinks SinksConfig `json:"sinks"`

	SuspiciousPaths []string `json:"suspicious_path,omitempty"`

	IgnoredConnectComms []string `json:"ignored_connect_comms,omitempty"`

	SensitiveWritePaths []string `json:"sensitive_write_paths,omitempty"`
	BlockedWritePaths   []string `json:"blocked_write_paths,omitempty"`

	// Ptrace Specific
	PtraceEnforcementEnabled bool     `json:"ptrace_enforcement_enabled"`
	AllowedPtraceAttached    []string `json:"allowed_ptrace_attaches,omitempty"`

	// Kmod Specific
	KmodEnforcementEnabled bool `json:"kmod_enforcement_enabled"`

	// K8s specific
	KubeletURL      string `json:"kubelet_url,omitempty"`
	ProcPath        string `json:"proc_path,omitempty"`
	CgroupPath      string `json:"cgroup_path,omitempty"`
	KubeletInsecure bool   `json:"kubelet_insecure,omitempty"`
	KubeletCertFile string `json:"kubelet_cert_file,omitempty"`
	KubeletKeyFile  string `json:"kubelet_key_file,omitempty"`
}

func (c *Config) applyDefaults() {
	if c.DedupWindowSeconds == 0 {
		c.DedupWindowSeconds = 10
	}
	// Stdout sink defaults to stdout if sinks are empty
	if c.Sinks == (SinksConfig{}) {
		c.Sinks.Stdout = true
	}
}

// 15 because the kernel's comm field is 16 bytes
// so having anything longer than that means it won't check
const maxCommLen = 15

// we make sure that these fields don't contain an emoty path,
// as that ends up matching with everything because of the nature
// of the strings checking function
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

func (c *Config) Validate() error {
	for _, r := range c.Rules {
		if err := r.Validate(); err != nil {
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

	if (c.KubeletCertFile == "") != (c.KubeletKeyFile == "") {
		return fmt.Errorf("kubelet_cert_file and kubelet_key_file must both be set or both be empty")
	}

	for field, entries := range c.nonEmptyPathLists() {
		for _, p := range entries {
			if p == "" {
				return fmt.Errorf("%s: empty string entries are not allowed (an empty pattern matches every path)", field)
			}
		}
	}

	for field, entries := range c.commLists() {
		for _, p := range entries {
			if p == "" {
				return fmt.Errorf("%s: empty string entries are not allowed", field)
			}
			if !filepath.IsAbs(p) {
				return fmt.Errorf("%s: %q must be an absolute path to a binary (this field now matches on resolved file identity, not process name)", field, p)
			}
		}
	}
	return nil
}

// BlockedPatterns returns the Pattern of every rule whose Action is
// ActionBlock and whose Match kind is exact-path
// matching (the LSM hook does exact hash-map lookups on the exec path, so
// only MatchExactPath pattern makes sense here
func (c *Config) BlockedPatterns() []string {
	var out []string
	for _, r := range c.Rules {
		if r.Action == ActionBlock && r.Match == MatchExactPath {
			out = append(out, r.Pattern)
		}
	}
	return out
}
