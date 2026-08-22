package config

import "fmt"

// diffConfig compares two configs and returns what changes between them two
func diffConfig(old, new *Config) []string {
	var changes []string

	if old.EnforcementEnabled != new.EnforcementEnabled {
		changes = append(changes, fmt.Sprintf("enforcement_enabled: %v -> %v", old.EnforcementEnabled, new.EnforcementEnabled))
	}
	if old.PtraceEnforcementEnabled != new.PtraceEnforcementEnabled {
		changes = append(changes, fmt.Sprintf("ptrace_enforcement_enabled: %v -> %v", old.PtraceEnforcementEnabled, new.PtraceEnforcementEnabled))
	}
	if old.KmodEnforcementEnabled != new.KmodEnforcementEnabled {
		changes = append(changes, fmt.Sprintf("kmod_enforcement_enabled: %v -> %v", old.KmodEnforcementEnabled, new.KmodEnforcementEnabled))
	}
	if old.DedupWindowSeconds != new.DedupWindowSeconds {
		changes = append(changes, fmt.Sprintf("dedup_window_seconds: %d -> %d", old.DedupWindowSeconds, new.DedupWindowSeconds))
	}

	changes = append(changes, diffRules(old.Rules, new.Rules)...)

	changes = append(changes, diffStringList("allowlist", old.Allowlist, new.Allowlist)...)
	changes = append(changes, diffStringList("protected_comms", old.ProtectedComms, new.ProtectedComms)...)
	changes = append(changes, diffIntList("protected_pids", old.ProtectedPIDs, new.ProtectedPIDs)...)
	changes = append(changes, diffStringList("suspicious_path", old.SuspiciousPaths, new.SuspiciousPaths)...)
	changes = append(changes, diffStringList("sensitive_write_paths", old.SensitiveWritePaths, new.SensitiveWritePaths)...)
	changes = append(changes, diffStringList("blocked_write_paths", old.BlockedWritePaths, new.BlockedWritePaths)...)
	changes = append(changes, diffStringList("ignored_connect_comms", old.IgnoredConnectComms, new.IgnoredConnectComms)...)
	changes = append(changes, diffStringList("allowed_ptrace_attaches", old.AllowedPtraceAttached, new.AllowedPtraceAttached)...)

	changes = append(changes, diffSinks(old.Sinks, new.Sinks)...)

	if old.KubeletURL != new.KubeletURL {
		changes = append(changes, fmt.Sprintf("kubelet_url: %q -> %q", old.KubeletURL, new.KubeletURL))
	}
	if old.KubeletInsecure != new.KubeletInsecure {
		changes = append(changes, fmt.Sprintf("kubelet_insecure: %v -> %v", old.KubeletInsecure, new.KubeletInsecure))
	}
	if (old.KubeletCertFile != new.KubeletCertFile) || (old.KubeletKeyFile != new.KubeletKeyFile) {
		changes = append(changes, "kubelet mTLS cert/key changed")
	}
	if old.ProcPath != new.ProcPath {
		changes = append(changes, fmt.Sprintf("proc_path changed in file (%q -> %q) but this key is startup-only and will NOT take effect until restart", old.ProcPath, new.ProcPath))
	}
	if old.CgroupPath != new.CgroupPath {
		changes = append(changes, fmt.Sprintf("cgroup_path changed in file (%q -> %q) but this key is startup-only and will NOT take effect until restart", old.CgroupPath, new.CgroupPath))
	}

	return changes
}

func diffRules(old, new []Rule) []string {
	oldByName := make(map[string]Rule, len(old))
	for _, r := range old {
		oldByName[r.Name] = r
	}
	newByName := make(map[string]Rule, len(new))
	for _, r := range new {
		newByName[r.Name] = r
	}

	var changes []string
	for name, nr := range newByName {
		or, existed := oldByName[name]
		if !existed {
			changes = append(changes, fmt.Sprintf("rule %q added (%s %s, %s/%s)", name, nr.Match, nr.Pattern, nr.Severity, nr.Action))
			continue
		}
		if or != nr {
			changes = append(changes, fmt.Sprintf("rule %q changed: %s", name, ruleFieldDiff(or, nr)))
		}
	}
	for name, or := range oldByName {
		if _, stillExists := newByName[name]; !stillExists {
			changes = append(changes, fmt.Sprintf("rule %q removed (was %s %s, %s/%s)", name, or.Match, or.Pattern, or.Severity, or.Action))
		}
	}
	return changes
}

func ruleFieldDiff(old, new Rule) string {
	var parts []string
	if old.Match != new.Match {
		parts = append(parts, fmt.Sprintf("match %s->%s", old.Match, new.Match))
	}
	if old.Pattern != new.Pattern {
		parts = append(parts, fmt.Sprintf("pattern %q->%q", old.Pattern, new.Pattern))
	}
	if old.Severity != new.Severity {
		parts = append(parts, fmt.Sprintf("severity %s->%s", old.Severity, new.Severity))
	}
	if old.Action != new.Action {
		parts = append(parts, fmt.Sprintf("action %s->%s", old.Action, new.Action))
	}
	if old.SuspiciousPathOnly != new.SuspiciousPathOnly {
		parts = append(parts, fmt.Sprintf("suspicious_path_only %v->%v", old.SuspiciousPathOnly, new.SuspiciousPathOnly))
	}
	return joinComma(parts)
}

func diffSinks(old, new SinksConfig) []string {
	var changes []string
	if old.Stdout != new.Stdout {
		changes = append(changes, fmt.Sprintf("sinks.stdout: %v -> %v", old.Stdout, new.Stdout))
	}
	if old.Syslog != new.Syslog {
		changes = append(changes, fmt.Sprintf("sinks.syslog: %v -> %v", old.Syslog, new.Syslog))
	}
	if old.WebhookURL != new.WebhookURL {
		changes = append(changes, "sinks.webhook_url changed")
	}
	if old.StorePath != new.StorePath {
		changes = append(changes, fmt.Sprintf("sinks.store_path: %q -> %q", old.StorePath, new.StorePath))
	}
	if old.MetricsListenAddr != new.MetricsListenAddr {
		changes = append(changes, fmt.Sprintf("sinks.metrics_listen_addr: %q -> %q (note: listener address changes require a restart)", old.MetricsListenAddr, new.MetricsListenAddr))
	}
	if old.DashboardListenAddr != new.DashboardListenAddr {
		changes = append(changes, fmt.Sprintf("sinks.dashboard_listen_addr: %q -> %q (note: listener address changes require a restart)", old.DashboardListenAddr, new.DashboardListenAddr))
	}
	if old.DashboardAuthToken != new.DashboardAuthToken {
		changes = append(changes, "sinks.dashboard_auth_token changed")
	}
	if old.MetricsAuthToken != new.MetricsAuthToken {
		changes = append(changes, "sinks.metrics_auth_token changed")
	}
	return changes
}

func diffStringList(field string, old, new []string) []string {
	added, removed := stringSetDiff(old, new)
	var changes []string
	for _, v := range added {
		changes = append(changes, fmt.Sprintf("%s: added %q", field, v))
	}
	for _, v := range removed {
		changes = append(changes, fmt.Sprintf("%s: removed %q", field, v))
	}
	return changes
}

func diffIntList(field string, old, new []int) []string {
	oldSet := make(map[int]bool, len(old))
	for _, v := range old {
		oldSet[v] = true
	}
	newSet := make(map[int]bool, len(new))
	for _, v := range new {
		newSet[v] = true
	}
	var changes []string
	for v := range newSet {
		if !oldSet[v] {
			changes = append(changes, fmt.Sprintf("%s: added %d", field, v))
		}
	}
	for v := range oldSet {
		if !newSet[v] {
			changes = append(changes, fmt.Sprintf("%s: removed %d", field, v))
		}
	}
	return changes
}

func stringSetDiff(old, new []string) (added, removed []string) {
	oldSet := make(map[string]bool, len(old))
	for _, v := range old {
		oldSet[v] = true
	}
	newSet := make(map[string]bool, len(new))
	for _, v := range new {
		newSet[v] = true
	}
	for v := range newSet {
		if !oldSet[v] {
			added = append(added, v)
		}
	}
	for v := range oldSet {
		if !newSet[v] {
			removed = append(removed, v)
		}
	}
	return added, removed
}

func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}
