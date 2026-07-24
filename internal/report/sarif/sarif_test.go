package sarif

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

func TestRender_SARIF(t *testing.T) {
	res := finding.ScanResult{
		Metadata: finding.Metadata{TatarVersion: "1.0.0"},
		Findings: []finding.Finding{
			{CanonicalControl: "TATAR-CON-001", Resource: "deployment/api", Namespace: "production", Severity: finding.SeverityHigh, Title: "Privileged", Remediation: "fix", FoundBy: []string{"trivy", "kubescape"}, Confidence: finding.ConfidenceHigh},
			{CanonicalControl: "TATAR-OPS-003", Resource: "service/orphan", Severity: finding.SeverityInfo, Title: "Orphan", FoundBy: []string{"popeye"}},
		},
	}
	var b bytes.Buffer
	if err := Render(&b, res); err != nil {
		t.Fatalf("Render: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b.Bytes(), &m); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if m["version"] != "2.1.0" {
		t.Errorf("version=%v, want 2.1.0", m["version"])
	}
	if !strings.Contains(b.String(), "TATAR-CON-001") {
		t.Error("ruleId TATAR-CON-001 алга")
	}
	if !strings.Contains(b.String(), `"level": "error"`) {
		t.Error("HIGH -> level error байх ёстой")
	}
	if !strings.Contains(b.String(), `"level": "note"`) {
		t.Error("INFO -> level note байх ёстой")
	}
}
