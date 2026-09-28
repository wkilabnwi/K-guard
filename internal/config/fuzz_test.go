package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func FuzzParseConfig(f *testing.F) {
	exts := []string{".json", ".yaml", ".yml", ""}

	f.Add([]byte(`{"enforcement_enabled": true, "rules": []}`), uint8(0))
	f.Add([]byte("rules:\n  - name: x\n    severity: high\n    action: BLOCK\n    expression: \"process.path == '/usr/bin/nc'\"\n"), uint8(1))

	// Real configs as seeds
	for _, name := range []string{"rules.json", "rules.yaml"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "configs", name))
		if err != nil {
			f.Fatalf("reading seed %s: %v", name, err)
		}
		f.Add(b, uint8(0))
		f.Add(b, uint8(1))
		f.Add(b, uint8(3))
	}

	f.Fuzz(func(t *testing.T, data []byte, e uint8) {
		start := time.Now()
		c, err := parseConfig(data, exts[int(e)%len(exts)])
		if d := time.Since(start); d > 500*time.Millisecond {
			t.Fatalf("parseConfig took %v on %d bytes", d, len(data))
		}
		if err != nil {
			return
		}
		for _, r := range c.Rules {
			if r.Program == nil {
				t.Fatalf("rule %q accepted without a compiled program", r.Name)
			}
			if r.ExactBlockPath != "" && strings.ContainsAny(r.ExactBlockPath, `'"`+"`") {
				t.Fatalf("garbage block path extracted: %q from %q", r.ExactBlockPath, r.Expression)
			}
		}
	})
}

func FuzzSigma(f *testing.F) {
	celEnv, err := GetCELEnvironment() // build once, it's expensive
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte("title: t\nlevel: high\ndetection:\n  selection:\n    Image|endswith: '/nc'\n  condition: selection\n"))
	// quote-injection attempt: should never produce broken or injected CEL
	f.Add([]byte("title: t\nlevel: high\ndetection:\n  selection:\n    Image|endswith: \"x' || true || '\"\n  condition: selection\n"))
	f.Add([]byte("title: t\nlevel: low\ntags:\n  - attack.execution\n  - attack.t1059\ndetection:\n  selection:\n    Image|contains:\n      - 'a'\n      - 'b'\n  condition: selection\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		start := time.Now()
		rule, err := ConvertSigmaToRule(data)
		if d := time.Since(start); d > 500*time.Millisecond {
			t.Fatalf("ConvertSigmaToRule took %v on %d bytes", d, len(data))
		}
		if err != nil {
			return
		}
		// Invariant: if the converter accepts the input, the CEL it
		// generated must at least compile
		if _, iss := celEnv.Compile(rule.Expression); iss != nil && iss.Err() != nil {
			t.Fatalf("converter produced invalid CEL: %v\nexpr: %s", iss.Err(), rule.Expression)
		}
	})
}
