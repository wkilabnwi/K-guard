package config

import (
	"fmt"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

// SigmaRule defines the structural representation of a standard Sigma rule document
type SigmaRule struct {
	Title       string                 `yaml:"title"`
	Description string                 `yaml:"description"`
	Status      string                 `yaml:"status"`
	Level       string                 `yaml:"level"`
	Logsource   SigmaLogsource         `yaml:"logsource"`
	Detection   map[string]interface{} `yaml:"detection"`
	Tags        []string               `yaml:"tags"`
}

type SigmaLogsource struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
	Service  string `yaml:"service"`
}

var sigmaFieldMapping = map[string]string{
	"image":            "process.path",
	"process.path":     "process.path",
	"originalfilename": "process.basename",
	"process.basename": "process.basename",
	"commandline":      "process.path",
	"hashes.sha256":    "process.sha256",
	"sha256":           "process.sha256",
	"user":             "process.uid",
	"parentimage":      "event.ancestor_filename",
}

func ConvertSigmaFile(path string) (*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading sigma file %s: %w", path, err)
	}
	return ConvertSigmaToRule(data)
}

func ConvertSigmaToRule(data []byte) (*Rule, error) {
	var sigma SigmaRule
	if err := yaml.Unmarshal(data, &sigma); err != nil {
		return nil, fmt.Errorf("parsing sigma YAML: %w", err)
	}

	if sigma.Title == "" {
		return nil, fmt.Errorf("sigma rule is missing title")
	}

	celExpr, err := buildCELFromDetection(sigma.Detection)
	if err != nil {
		return nil, fmt.Errorf("building CEL expression for rule %q: %w", sigma.Title, err)
	}

	rule := &Rule{
		Name:       sigma.Title,
		Severity:   mapSigmaLevelToSeverity(sigma.Level),
		Action:     ActionAlert,
		Mode:       RuleModeEnforce,
		Expression: celExpr,
		Mitre:      extractMitreFromTags(sigma.Tags),
	}

	env, err := GetCELEnvironment()
	if err != nil {
		return nil, fmt.Errorf("fetching CEL env: %w", err)
	}
	if err := rule.Validate(env); err != nil {
		return nil, fmt.Errorf("generated CEL expression invalid: %w", err)
	}

	return rule, nil
}

func buildCELFromDetection(detection map[string]interface{}) (string, error) {
	if len(detection) == 0 {
		return "", fmt.Errorf("detection section is empty")
	}

	var clauses []string

	for key, val := range detection {
		if key == "condition" {
			continue
		}

		switch v := val.(type) {
		case map[string]interface{}:
			clause, err := buildSelectionClause(v)
			if err != nil {
				return "", err
			}
			if clause != "" {
				clauses = append(clauses, clause)
			}
		}
	}

	if len(clauses) == 0 {
		return "", fmt.Errorf("no valid selection clauses could be transpiled")
	}

	if len(clauses) == 1 {
		return clauses[0], nil
	}

	return strings.Join(clauses, " && "), nil
}

func buildSelectionClause(selection map[string]interface{}) (string, error) {
	var subClauses []string

	for fieldSpec, rawVal := range selection {
		parts := strings.Split(fieldSpec, "|")
		fieldName := strings.ToLower(parts[0])
		modifier := ""
		if len(parts) > 1 {
			modifier = strings.ToLower(parts[1])
		}

		celVar, ok := sigmaFieldMapping[fieldName]
		if !ok {
			celVar = "process.path"
		}

		expr, err := formatFieldConstraint(celVar, modifier, rawVal)
		if err != nil {
			return "", err
		}
		if expr != "" {
			subClauses = append(subClauses, expr)
		}
	}

	if len(subClauses) == 0 {
		return "", nil
	}

	if len(subClauses) == 1 {
		return subClauses[0], nil
	}

	return "(" + strings.Join(subClauses, " && ") + ")", nil
}

func formatFieldConstraint(celVar, modifier string, val interface{}) (string, error) {
	switch v := val.(type) {
	case string:
		return formatSingleMatch(celVar, modifier, v), nil
	case []interface{}:
		var listMatches []string
		for _, item := range v {
			if strVal, ok := item.(string); ok {
				listMatches = append(listMatches, formatSingleMatch(celVar, modifier, strVal))
			}
		}
		if len(listMatches) == 0 {
			return "", nil
		}
		if len(listMatches) == 1 {
			return listMatches[0], nil
		}
		return "(" + strings.Join(listMatches, " || ") + ")", nil
	default:
		return fmt.Sprintf("%s == %v", celVar, val), nil
	}
}

func formatSingleMatch(celVar, modifier, value string) string {
	escapedVal := strings.ReplaceAll(value, "'", "\\'")
	switch modifier {
	case "endswith":
		return fmt.Sprintf("%s.endsWith('%s')", celVar, escapedVal)
	case "startswith":
		return fmt.Sprintf("%s.startsWith('%s')", celVar, escapedVal)
	case "contains":
		return fmt.Sprintf("%s.contains('%s')", celVar, escapedVal)
	default:
		return fmt.Sprintf("%s == '%s'", celVar, escapedVal)
	}
}

func mapSigmaLevelToSeverity(level string) Severity {
	switch strings.ToLower(level) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low", "informational":
		return SeverityLow
	default:
		return SeverityMedium
	}
}

func extractMitreFromTags(tags []string) *MitreMeta {
	if len(tags) == 0 {
		return nil
	}

	meta := &MitreMeta{}
	for _, tag := range tags {
		lower := strings.ToLower(tag)
		if strings.HasPrefix(lower, "attack.t") {
			meta.TechniqueID = strings.ToUpper(strings.TrimPrefix(lower, "attack."))
		} else if strings.HasPrefix(lower, "attack.") {
			tactic := strings.TrimPrefix(lower, "attack.")
			tactic = strings.ReplaceAll(tactic, "_", " ")
			if len(tactic) > 0 {
				meta.Tactic = strings.ToUpper(tactic[:1]) + strings.ToLower(tactic[1:])
			}
		} else {
			meta.Tags = append(meta.Tags, tag)
		}
	}

	if meta.TechniqueID == "" && meta.Tactic == "" && len(meta.Tags) == 0 {
		return nil
	}
	return meta
}
