package trivy

import (
	"os"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/canonical"
	"github.com/ochmunkh/tatar-kuber/internal/scanner"
)

// Trivy fixture -> canonical-аар баяжуулсан findings.
func TestNormalize_Fixture(t *testing.T) {
	reg, err := canonical.Load("../../../schema/canonical-controls.yaml")
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	data, err := os.ReadFile("../../../tests/fixtures/trivy_k8s.json")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	s := New(reg.NewResolver())
	findings, err := s.Normalize(scanner.RawResult{Scanner: "trivy", Format: "json", Data: data})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	want := []string{"TATAR-CON-001", "TATAR-CON-002", "TATAR-IMG-001", "TATAR-IMG-002", "TATAR-SEC-001"}
	if len(findings) != len(want) {
		t.Fatalf("findings=%d, want %d", len(findings), len(want))
	}
	for i, f := range findings {
		if f.CanonicalControl != want[i] {
			t.Errorf("[%d] canonical=%s, want %s", i, f.CanonicalControl, want[i])
		}
		if f.ID == "" || f.FirstSeen == "" || len(f.FoundBy) != 1 {
			t.Errorf("[%d] бүрэн бус finding: %+v", i, f)
		}
	}

	// CVE CRITICAL нь ганц scanner ч deterministic тул confidence HIGH.
	if findings[2].Confidence != "HIGH" {
		t.Errorf("CVE confidence=%s, want HIGH (deterministic)", findings[2].Confidence)
	}
}
