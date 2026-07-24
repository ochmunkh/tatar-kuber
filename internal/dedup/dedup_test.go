package dedup

import "testing"

import (
	"github.com/ochmunkh/tatar-kuber/internal/canonical"
	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

func base() finding.Finding {
	return finding.Finding{
		CanonicalControl: "TATAR-CON-001",
		Resource:         "deployment/api",
		Namespace:        "production",
		Category:         "Container Security",
		Type:             finding.TypeMisconfig,
		Severity:         finding.SeverityMedium,
		OriginalSeverity: finding.SeverityMedium,
		Title:            "Privileged container enabled",
		FoundBy:          []string{"trivy"},
		RawRefs:          []finding.RawRef{{Scanner: "trivy", RuleID: "AVD-KSV0017"}},
		Status:           finding.StatusOpen,
		FirstSeen:        "2026-07-24T09:00:00Z",
		LastSeen:         "2026-07-24T09:00:00Z",
	}
}

func TestDeduplicate_MergesSameIssue(t *testing.T) {
	reg, err := canonical.Load("../../schema/canonical-controls.yaml")
	if err != nil {
		t.Fatalf("registry: %v", err)
	}

	trivyF := base() // MEDIUM, trivy
	ksF := base()    // same issue via kubescape, but HIGH
	ksF.Severity = finding.SeverityHigh
	ksF.FoundBy = []string{"kubescape"}
	ksF.RawRefs = []finding.RawRef{{Scanner: "kubescape", RuleID: "C-0057"}}
	other := base() // different resource -> separate
	other.Resource = "deployment/web"

	out := Deduplicate([]finding.Finding{trivyF, ksF, other}, reg)

	if len(out) != 2 {
		t.Fatalf("findings=%d, want 2 (api merged, web separate)", len(out))
	}

	// api-г ол
	var api *finding.Finding
	for i := range out {
		if out[i].Resource == "deployment/api" {
			api = &out[i]
		}
	}
	if api == nil {
		t.Fatal("merged api finding алга")
	}
	if api.Severity != finding.SeverityHigh {
		t.Errorf("severity=%s, want HIGH (worst)", api.Severity)
	}
	if len(api.FoundBy) != 2 || api.FoundBy[0] != "kubescape" || api.FoundBy[1] != "trivy" {
		t.Errorf("found_by=%v, want [kubescape trivy]", api.FoundBy)
	}
	if api.Confidence != finding.ConfidenceHigh {
		t.Errorf("confidence=%s, want HIGH (2 scanners)", api.Confidence)
	}
	if len(api.RawRefs) != 2 {
		t.Errorf("raw_refs=%d, want 2", len(api.RawRefs))
	}
}

// Ганц scanner + heuristic control -> confidence MEDIUM.
func TestDeduplicate_HeuristicSingleScanner(t *testing.T) {
	reg, _ := canonical.Load("../../schema/canonical-controls.yaml")
	f := base()
	f.CanonicalControl = "TATAR-NET-003" // heuristic: true
	f.Resource = "service/public"
	f.Category = "Network Security"
	out := Deduplicate([]finding.Finding{f}, reg)
	if len(out) != 1 {
		t.Fatalf("findings=%d, want 1", len(out))
	}
	if out[0].Confidence != finding.ConfidenceMedium {
		t.Errorf("confidence=%s, want MEDIUM (1 scanner, heuristic)", out[0].Confidence)
	}
}
