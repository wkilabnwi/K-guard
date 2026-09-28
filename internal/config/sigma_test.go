package config

import (
	"testing"
)

func TestConvertSigmaToRule(t *testing.T) {
	sampleSigma := []byte(`
title: Suspicious Netcat Execution
status: experimental
level: high
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/nc'
            - '/ncat'
        OriginalFileName: 'nc'
    condition: selection
tags:
    - attack.command_and_control
    - attack.t1095
`)

	rule, err := ConvertSigmaToRule(sampleSigma)
	if err != nil {
		t.Fatalf("Failed to convert Sigma rule: %v", err)
	}

	if rule.Name != "Suspicious Netcat Execution" {
		t.Errorf("Expected rule name 'Suspicious Netcat Execution', got %q", rule.Name)
	}

	if rule.Severity != SeverityHigh {
		t.Errorf("Expected severity 'high', got %q", rule.Severity)
	}

	if rule.Mitre == nil {
		t.Fatalf("Expected MITRE metadata, got nil")
	}

	if rule.Mitre.TechniqueID != "T1095" {
		t.Errorf("Expected technique ID 'T1095', got %q", rule.Mitre.TechniqueID)
	}

	if rule.Program == nil {
		t.Errorf("Expected pre-compiled CEL program handle, got nil")
	}

	t.Logf("Transpiled CEL Expression: %s", rule.Expression)
}
