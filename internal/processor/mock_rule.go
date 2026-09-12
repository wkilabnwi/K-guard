package processor

import (
	"fmt"

	"cel.dev/cel-go/cel"
)

type TestRuleResult struct {
	Valid          bool   `json:"valid"`
	Result         bool   `json:"result"`
	CompilationErr string `json:"compilation_error,omitempty"`
	EvalErr        string `json:"eval_error,omitempty"`
}

// TestExpression compiles and evaluates a raw CEL expression against a mock dataset
func TestExpression(celEnv *cel.Env, expr string, mockData map[string]any) TestRuleResult {
	ast, iss := celEnv.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return TestRuleResult{
			Valid:          false,
			CompilationErr: iss.Err().Error(),
		}
	}

	prg, err := celEnv.Program(ast)
	if err != nil {
		return TestRuleResult{
			Valid:          false,
			CompilationErr: fmt.Sprintf("program construction error: %v", err),
		}
	}

	out, _, err := prg.Eval(mockData)
	if err != nil {
		return TestRuleResult{
			Valid:   true,
			EvalErr: err.Error(),
		}
	}

	matched, ok := out.Value().(bool)
	if !ok {
		return TestRuleResult{
			Valid:   true,
			EvalErr: "expression did not evaluate to a boolean result",
		}
	}

	return TestRuleResult{
		Valid:  true,
		Result: matched,
	}
}

// DefaultMockEvent provides a sensible fallback if no JSON event is passed in.
func DefaultMockEvent() map[string]any {
	return map[string]any{
		"event": map[string]any{
			"type":                "EXEC",
			"ancestor_suspicious": false,
			"ancestor_filename":   "",
			"is_suspicious_path":  true,
			"mispred_count":       uint64(0),
			"process": map[string]any{
				"path":        "/tmp/nc",
				"basename":    "nc",
				"sha256":      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				"pid":         int64(1337),
				"ppid":        int64(1),
				"uid":         int64(0),
				"gid":         int64(0),
				"comm":        "nc",
				"args":        []string{"-lvp", "4444"},
				"is_fileless": false,
			},
		},
		"process": map[string]any{
			"path":        "/tmp/nc",
			"basename":    "nc",
			"sha256":      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"pid":         int64(1337),
			"ppid":        int64(1),
			"uid":         int64(0),
			"gid":         int64(0),
			"comm":        "nc",
			"args":        []string{"-lvp", "4444"},
			"is_fileless": false,
		},
	}
}
