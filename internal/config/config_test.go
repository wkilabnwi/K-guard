package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const validYAML = `
enforcement_enabled: true
dedup_window_seconds: 5
protected_pids: [1, 2]
protected_comms: ["/usr/bin/dockerd"]
suspicious_path: ["/tmp/evil"]
rules:
  - name: "Block netcat"
    severity: "high"
    action: "BLOCK"
    expression: "process.path == '/usr/bin/nc'"
sinks:
  stdout: true
`

const updatedYAML = `
enforcement_enabled: false
dedup_window_seconds: 10
protected_pids: [1, 2, 3]
protected_comms: ["/usr/bin/dockerd"]
suspicious_path: ["/tmp/evil", "/tmp/malware"]
rules:
  - name: "Block netcat"
    severity: "critical"
    action: "BLOCK"
    expression: "process.path == '/usr/bin/nc'"
  - name: "Alert on nmap"
    severity: "medium"
    action: "ALERT"
    expression: "process.basename == 'nmap'"
sinks:
  stdout: false
  syslog: true
`

const validJSON = `{
  "enforcement_enabled": true,
  "dedup_window_seconds": 5,
  "protected_pids": [1, 2],
  "protected_comms": ["/usr/bin/dockerd"],
  "suspicious_path": ["/tmp/evil"],
  "rules": [
    {
      "name": "Block netcat",
      "severity": "high",
      "action": "BLOCK",
      "expression": "process.path == '/usr/bin/nc'"
    }
  ],
  "sinks": {
    "stdout": true
  }
}`

const updatedJSON = `{
  "enforcement_enabled": false,
  "dedup_window_seconds": 10,
  "protected_pids": [1, 2, 3],
  "protected_comms": ["/usr/bin/dockerd"],
  "suspicious_path": ["/tmp/evil", "/tmp/malware"],
  "rules": [
    {
      "name": "Block netcat",
      "severity": "critical",
      "action": "BLOCK",
      "expression": "process.path == '/usr/bin/nc'"
    },
    {
      "name": "Alert on nmap",
      "severity": "medium",
      "action": "ALERT",
      "expression": "process.basename == 'nmap'"
    }
  ],
  "sinks": {
    "stdout": false,
    "syslog": true
  }
}`

func writeTempConfigExt(t *testing.T, content string, mode os.FileMode, ext string) string {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "kguard_config_*"+ext)
	if err != nil {
		t.Fatalf("failed to create temp config: %v", err)
	}
	if err := os.Chmod(tmpFile.Name(), mode); err != nil {
		t.Fatalf("failed to set permissions: %v", err)
	}
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("failed to write content: %v", err)
	}
	tmpFile.Close()

	t.Cleanup(func() {
		os.Remove(tmpFile.Name())
	})
	return tmpFile.Name()
}

func writeTempConfig(t *testing.T, content string, mode os.FileMode) string {
	return writeTempConfigExt(t, content, mode, ".yaml")
}

func TestLoadConfig_YAMLAndJSON(t *testing.T) {
	tests := []struct {
		name    string
		content string
		ext     string
	}{
		{name: "Valid YAML (.yaml)", content: validYAML, ext: ".yaml"},
		{name: "Valid YAML (.yml)", content: validYAML, ext: ".yml"},
		{name: "Valid JSON (.json)", content: validJSON, ext: ".json"},
		{name: "Valid JSON without extension", content: validJSON, ext: ""},
		{name: "Valid YAML without extension", content: validYAML, ext: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempConfigExt(t, tt.content, 0600, tt.ext)

			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("unexpected load error: %v", err)
			}

			if !cfg.EnforcementEnabled {
				t.Errorf("expected EnforcementEnabled to be true")
			}
			if len(cfg.Rules) != 1 {
				t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
			}
			if cfg.Rules[0].ExactBlockPath != "/usr/bin/nc" {
				t.Errorf("expected ExactBlockPath '/usr/bin/nc', got %q", cfg.Rules[0].ExactBlockPath)
			}

			blocked := cfg.BlockedPatterns()
			if len(blocked) != 1 || blocked[0] != "/usr/bin/nc" {
				t.Errorf("unexpected BlockedPatterns output: %v", blocked)
			}
		})
	}
}

func TestLoadConfig_InvalidPermissions(t *testing.T) {
	path := writeTempConfig(t, validYAML, 0666) // World/group writable

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error due to overly permissive file mode, got nil")
	}
}

func TestConfig_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		ext     string
		wantErr string
	}{
		{
			name: "Invalid Protected PID (YAML)",
			content: `
protected_pids: [-1]
`,
			ext:     ".yaml",
			wantErr: "invalid protected_pids entry",
		},
		{
			name:    "Invalid Protected PID (JSON)",
			content: `{"protected_pids": [-1]}`,
			ext:     ".json",
			wantErr: "invalid protected_pids entry",
		},
		{
			name: "Relative Path in Comm List (YAML)",
			content: `
protected_comms: ["relative/path"]
`,
			ext:     ".yaml",
			wantErr: "must be an absolute path",
		},
		{
			name:    "Relative Path in Comm List (JSON)",
			content: `{"protected_comms": ["relative/path"]}`,
			ext:     ".json",
			wantErr: "must be an absolute path",
		},
		{
			name: "Invalid CEL Syntax (YAML)",
			content: `
rules:
  - name: "Bad CEL"
    severity: "low"
    action: "ALERT"
    expression: "process.path =="
`,
			ext:     ".yaml",
			wantErr: "CEL syntax error",
		},
		{
			name:    "Invalid CEL Syntax (JSON)",
			content: `{"rules": [{"name": "Bad CEL", "severity": "low", "action": "ALERT", "expression": "process.path =="}]}`,
			ext:     ".json",
			wantErr: "CEL syntax error",
		},
		{
			name: "Unknown Severity",
			content: `
rules:
  - name: "Bad Sev"
    severity: "super_high"
    action: "ALERT"
    expression: "true"
`,
			ext:     ".yaml",
			wantErr: "unknown severity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempConfigExt(t, tt.content, 0600, tt.ext)
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
		})
	}
}

func TestManager_ReloadAndSubscribe_JSON(t *testing.T) {
	path := writeTempConfigExt(t, validJSON, 0600, ".json")

	mgr, err := NewManager(path)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	initialCfg := mgr.Current()
	if initialCfg.DedupWindowSeconds != 5 {
		t.Errorf("expected dedup 5, got %d", initialCfg.DedupWindowSeconds)
	}

	notified := make(chan *Config, 1)
	mgr.OnChange(func(c *Config) {
		notified <- c
	})

	// Overwrite JSON file content
	if err := os.WriteFile(path, []byte(updatedJSON), 0600); err != nil {
		t.Fatalf("failed to overwrite config: %v", err)
	}

	if err := mgr.ReloadNow(); err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	select {
	case newCfg := <-notified:
		if newCfg.EnforcementEnabled {
			t.Errorf("expected enforcement to be false after reload")
		}
		if len(newCfg.Rules) != 2 {
			t.Errorf("expected 2 rules after reload, got %d", len(newCfg.Rules))
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for OnChange subscriber notification")
	}
}

func TestDiffConfig(t *testing.T) {
	oldCfg := &Config{
		EnforcementEnabled: true,
		DedupWindowSeconds: 5,
		ProtectedPIDs:      []int{1, 2},
		Rules: []Rule{
			{Name: "Rule1", Severity: SeverityLow, Action: ActionAlert, Expression: "true"},
		},
	}

	newCfg := &Config{
		EnforcementEnabled: false,
		DedupWindowSeconds: 10,
		ProtectedPIDs:      []int{1, 2, 3},
		Rules: []Rule{
			{Name: "Rule1", Severity: SeverityHigh, Action: ActionAlert, Expression: "true"},
			{Name: "Rule2", Severity: SeverityCritical, Action: ActionKill, Expression: "false"},
		},
	}

	changes := diffConfig(oldCfg, newCfg)
	if len(changes) == 0 {
		t.Fatal("expected diff changes, got none")
	}

	hasRule2 := false
	for _, ch := range changes {
		if filepath.Base(ch) != ch && ch == "rule \"Rule2\" added (critical/KILL)" {
			hasRule2 = true
		}
	}

	if !hasRule2 {
		t.Logf("Detected changes:\n%v", changes)
	}
}
