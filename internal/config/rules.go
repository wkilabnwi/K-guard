package config

import "fmt"

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
