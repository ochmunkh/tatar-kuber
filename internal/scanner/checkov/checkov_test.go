package checkov

import (
	"os"
	"sort"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/canonical"
	"github.com/ochmunkh/tatar-kuber/internal/scanner"
)

func TestNormalize_Fixture(t *testing.T) {
	reg, err := canonical.Load("../../../schema/canonical-controls.yaml")
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	data, err := os.ReadFile("../../../testdata/checkov/scan.json")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	s := New(reg.NewResolver())
	findings, err := s.Normalize(scanner.RawResult{Scanner: "checkov", Format: "json", Data: data})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	got := []string{}
	for _, f := range findings {
		got = append(got, f.CanonicalControl)
	}
	sort.Strings(got)
	want := []string{"TATAR-CON-001", "TATAR-CON-003", "TATAR-OPS-002", "TATAR-RBAC-002"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] %s, want %s", i, got[i], want[i])
		}
	}

	// cluster-scoped RBAC-ийн resource зөв задарсан эсэх
	for _, f := range findings {
		if f.CanonicalControl == "TATAR-RBAC-002" && f.Resource != "clusterrole/cluster-reader" {
			t.Errorf("RBAC-002 resource=%s, want clusterrole/cluster-reader", f.Resource)
		}
	}
}
