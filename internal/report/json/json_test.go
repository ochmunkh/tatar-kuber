package json

import (
	"bytes"
	stdjson "encoding/json"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

func sample() finding.ScanResult {
	return finding.ScanResult{
		SchemaVersion: "1.0",
		Summary:       finding.Summary{Counts: map[finding.Severity]int{finding.SeverityHigh: 1}, RiskScore: 80, RiskBand: "Good", TotalFindings: 1},
		Findings: []finding.Finding{{
			ID: "TK-abc123", CanonicalControl: "TATAR-CON-001", Resource: "deployment/api",
			Severity: finding.SeverityHigh, Title: "Privileged", FoundBy: []string{"trivy"},
		}},
	}
}

func TestRender_RoundTrip(t *testing.T) {
	var b bytes.Buffer
	if err := Render(&b, sample()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	var back finding.ScanResult
	if err := stdjson.Unmarshal(b.Bytes(), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Summary.TotalFindings != 1 || back.Findings[0].CanonicalControl != "TATAR-CON-001" {
		t.Errorf("round-trip алдаа: %+v", back.Summary)
	}
}
