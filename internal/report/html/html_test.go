package html

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

func TestRender_HTML(t *testing.T) {
	res := finding.ScanResult{
		Metadata: finding.Metadata{ClusterName: "production", ScanMode: "remote", ResultHash: "sha256:abc"},
		Summary:  finding.Summary{Counts: map[finding.Severity]int{finding.SeverityHigh: 1}, RiskScore: 78, RiskBand: "Good", TotalFindings: 1},
		Findings: []finding.Finding{{CanonicalControl: "TATAR-CON-001", Resource: "deployment/api", Namespace: "production", Severity: finding.SeverityHigh, Title: "Privileged container", Remediation: "securityContext.privileged=false болгоно", FoundBy: []string{"trivy", "kubescape"}, Confidence: finding.ConfidenceHigh}},
	}
	var b bytes.Buffer
	if err := Render(&b, res); err != nil {
		t.Fatalf("Render: %v", err)
	}
	s := b.String()
	for _, want := range []string{"TATAR-Kuber Security Report", "78/100", "TATAR-CON-001", "Privileged container", "production", "securityContext.privileged=false", "Засвар (Fix)"} {
		if !strings.Contains(s, want) {
			t.Errorf("HTML-д %q алга", want)
		}
	}
}
