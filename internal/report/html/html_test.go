package html

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

func TestRender_HTML(t *testing.T) {
	res := finding.ScanResult{
		SchemaVersion: "1.0",
		Metadata:      finding.Metadata{ClusterName: "production", ScanMode: "remote", Lang: "mn", ResultHash: "sha256:abc", TatarVersion: "1.0.0", ScannerVersions: map[string]string{"trivy": "0.67.2", "kubescape": "3.1.4"}, Inventory: map[string]int{"Nodes": 5, "Pods": 142}},
		Summary:       finding.Summary{Counts: map[finding.Severity]int{finding.SeverityHigh: 1}, RiskScore: 78, RiskBand: "Good", TotalFindings: 1},
		Findings: []finding.Finding{{CanonicalControl: "TATAR-CON-001", Resource: "deployment/api", Namespace: "production", Severity: finding.SeverityHigh, Title: "Privileged container", RiskContribution: 12.6, References: []string{"CIS-5.2.5", "MITRE-T1611", "https://avd.aquasec.com/misconfig/ksv017"}, Evidence: []finding.Evidence{{Scanner: "kubescape", Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "зөвлөмж: false"}}, Remediation: "securityContext.privileged=false болгоно", FoundBy: []string{"trivy", "kubescape"}, Confidence: finding.ConfidenceHigh}},
	}
	var b bytes.Buffer
	if err := Render(&b, res); err != nil {
		t.Fatalf("Render: %v", err)
	}
	s := b.String()
	for _, want := range []string{
		"TATAR-Kuber Security Report", "78/100", "TATAR-CON-001", "Privileged container", "production",
		"securityContext.privileged=false",
		"spec.template.spec.containers[0].securityContext.privileged",
		// mn UI шошго (Lang: mn)
		"Гүйцэтгэх хураангуй", "Гол эрсдэлүүд", "Зөвлөмж", "Засвар", "Нотолгоо", "Кластерын нөөц",
		"CIS-5.2.5", "MITRE-T1611", // compliance badges
		"Scanner хувилбар", "0.67.2", // metadata footer (mn label)
		"Nodes", "142", // inventory section
		"Trivy Advisory", "https://avd.aquasec.com/misconfig/ksv017", // labeled reference link
		"Онооны зурвас", // band legend (mn)
	} {
		if !strings.Contains(s, want) {
			t.Errorf("HTML-д %q алга", want)
		}
	}
}
