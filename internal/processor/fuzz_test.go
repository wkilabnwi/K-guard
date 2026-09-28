package processor

import (
	"testing"
	"time"

	"k-guard/internal/config"
)

func FuzzTestExpression(f *testing.F) {
	celEnv, err := config.GetCELEnvironment()
	if err != nil {
		f.Fatal(err)
	}

	f.Add("process.basename == 'nc'")
	f.Add("process.path.startsWith('/tmp/') && event.is_suspicious_path")
	f.Add("process.sha256 == 'abc'")
	f.Add("process.path")
	f.Add("event.type == 'EXEC' && process.uid == 0")

	f.Fuzz(func(t *testing.T, expr string) {
		start := time.Now()
		_ = TestExpression(celEnv, expr, DefaultMockEvent())
		if d := time.Since(start); d > 500*time.Millisecond {
			t.Fatalf("TestExpression took %v on %q", d, expr)
		}
	})
}
