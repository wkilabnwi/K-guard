package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"k-guard/internal/config"
)

func createTempConfigFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	filePath := filepath.Join(dir, "rules.json")

	if err := os.WriteFile(filePath, []byte(content), mode); err != nil {
		t.Fatalf("failed to create temp config file: %v", err)
	}
	return filePath
}

func TestRule_Validate(t *testing.T) {
	tests := []struct {
		name    string
		rule    config.Rule
		wantErr bool
	}{
		{
			name: "valid rule",
			rule: config.Rule{
				Name:     "block-nc",
				Match:    config.MatchBasename,
				Pattern:  "nc",
				Severity: config.SeverityCritical,
				Action:   config.ActionBlock,
			},
			wantErr: false,
		},
		{
			name: "missing name",
			rule: config.Rule{
				Match:    config.MatchExactPath,
				Pattern:  "/usr/bin/nc",
				Severity: config.SeverityHigh,
				Action:   config.ActionKill,
			},
			wantErr: true,
		},
		{
			name: "unknown match kind",
			rule: config.Rule{
				Name:     "bad-match",
				Match:    "regex",
				Pattern:  "nc.*",
				Severity: config.SeverityLow,
				Action:   config.ActionAlert,
			},
			wantErr: true,
		},
		{
			name: "empty pattern",
			rule: config.Rule{
				Name:     "empty-pattern",
				Match:    config.MatchPrefix,
				Pattern:  "",
				Severity: config.SeverityMedium,
				Action:   config.ActionAlert,
			},
			wantErr: true,
		},
		{
			name: "unknown severity",
			rule: config.Rule{
				Name:     "bad-sev",
				Match:    config.MatchExactPath,
				Pattern:  "/tmp/evil",
				Severity: "super-high",
				Action:   config.ActionKill,
			},
			wantErr: true,
		},
		{
			name: "unknown action",
			rule: config.Rule{
				Name:     "bad-action",
				Match:    config.MatchExactPath,
				Pattern:  "/tmp/evil",
				Severity: config.SeverityHigh,
				Action:   "DROP",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Rule.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfig_Validate_EdgeCases(t *testing.T) {
	t.Run("empty string in path list", func(t *testing.T) {
		cfg := config.Config{
			Rules: []config.Rule{
				{Name: "valid", Match: config.MatchBasename, Pattern: "nc", Severity: config.SeverityLow, Action: config.ActionAlert},
			},
			SuspiciousPaths: []string{"/tmp/", ""},
		}
		if err := cfg.Validate(); err == nil {
			t.Errorf("expected error for empty string in suspicious_path, got nil")
		}
	})

	t.Run("non-absolute path in comm list", func(t *testing.T) {
		cfg := config.Config{
			Rules: []config.Rule{
				{Name: "valid", Match: config.MatchBasename, Pattern: "nc", Severity: config.SeverityLow, Action: config.ActionAlert},
			},
			ProtectedComms: []string{"sshd"},
		}
		if err := cfg.Validate(); err == nil {
			t.Errorf("expected error for non-absolute path in protected_comms, got nil")
		}
	})

	t.Run("negative PID in protected_pids", func(t *testing.T) {
		cfg := config.Config{
			Rules: []config.Rule{
				{Name: "valid", Match: config.MatchBasename, Pattern: "nc", Severity: config.SeverityLow, Action: config.ActionAlert},
			},
			ProtectedPIDs: []int{-5, 0},
		}
		if err := cfg.Validate(); err == nil {
			t.Errorf("expected error for invalid protected_pids, got nil")
		}
	})

	t.Run("negative dedup_window_seconds", func(t *testing.T) {
		cfg := config.Config{
			Rules: []config.Rule{
				{Name: "valid", Match: config.MatchBasename, Pattern: "nc", Severity: config.SeverityLow, Action: config.ActionAlert},
			},
			DedupWindowSeconds: -10,
		}
		if err := cfg.Validate(); err == nil {
			t.Errorf("expected error for negative dedup_window_seconds, got nil")
		}
	})

	t.Run("mismatched kubelet TLS cert and key", func(t *testing.T) {
		cfg := config.Config{
			Rules: []config.Rule{
				{Name: "valid", Match: config.MatchBasename, Pattern: "nc", Severity: config.SeverityLow, Action: config.ActionAlert},
			},
			KubeletCertFile: "/etc/k8s/client.crt",
			KubeletKeyFile:  "",
		}
		if err := cfg.Validate(); err == nil {
			t.Errorf("expected error for missing kubelet_key_file, got nil")
		}
	})
}

func TestLoad_PermissionsCheck(t *testing.T) {
	validJSON := `{
		"rules": [{"name": "test", "match": "basename", "pattern": "nc", "severity": "low", "action": "ALERT"}]
	}`

	t.Run("strict permissions 0600 passes", func(t *testing.T) {
		path := createTempConfigFile(t, validJSON, 0600)
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatalf("expected 0600 file to load successfully, got: %v", err)
		}
		if len(cfg.Rules) != 1 {
			t.Errorf("expected 1 rule loaded, got %d", len(cfg.Rules))
		}
	})

	t.Run("world writable file permissions 0666 rejected", func(t *testing.T) {
		path := createTempConfigFile(t, validJSON, 0666)
		_, err := config.Load(path)
		if err == nil {
			t.Errorf("expected error when loading world-writable 0666 config file, got nil")
		}
	})
}

func TestConfig_BlockedPatterns(t *testing.T) {
	cfg := config.Config{
		Rules: []config.Rule{
			{Name: "block-exact", Match: config.MatchExactPath, Pattern: "/usr/bin/nc", Severity: config.SeverityCritical, Action: config.ActionBlock},
			{Name: "block-basename", Match: config.MatchBasename, Pattern: "nc", Severity: config.SeverityCritical, Action: config.ActionBlock},
			{Name: "kill-exact", Match: config.MatchExactPath, Pattern: "/usr/bin/nmap", Severity: config.SeverityHigh, Action: config.ActionKill},
		},
	}

	patterns := cfg.BlockedPatterns()
	if len(patterns) != 1 {
		t.Fatalf("expected exactly 1 blocked pattern, got %d", len(patterns))
	}
	if patterns[0] != "/usr/bin/nc" {
		t.Errorf("expected blocked pattern '/usr/bin/nc', got %q", patterns[0])
	}
}

func TestManager_ReloadNow_And_OnChange(t *testing.T) {
	initialJSON := `{
		"rules": [{"name": "rule1", "match": "basename", "pattern": "nc", "severity": "low", "action": "ALERT"}],
		"enforcement_enabled": false
	}`

	path := createTempConfigFile(t, initialJSON, 0600)
	mgr, err := config.NewManager(path)
	if err != nil {
		t.Fatalf("failed to create Manager: %v", err)
	}

	notified := false
	mgr.OnChange(func(c *config.Config) {
		notified = true
	})

	updatedJSON := `{
		"rules": [{"name": "rule1", "match": "basename", "pattern": "nc", "severity": "low", "action": "ALERT"}],
		"enforcement_enabled": true
	}`
	if err := os.WriteFile(path, []byte(updatedJSON), 0600); err != nil {
		t.Fatalf("failed to update temp file: %v", err)
	}

	if err := mgr.ReloadNow(); err != nil {
		t.Fatalf("ReloadNow() failed: %v", err)
	}

	if !notified {
		t.Errorf("expected OnChange callback to be executed after ReloadNow()")
	}

	if !mgr.Current().EnforcementEnabled {
		t.Errorf("expected enforcement_enabled to update to true")
	}
}
