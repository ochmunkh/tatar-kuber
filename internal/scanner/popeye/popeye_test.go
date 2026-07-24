package popeye

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
	data, err := os.ReadFile("../../../testdata/popeye/scan.json")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	s := New(reg.NewResolver())
	findings, err := s.Normalize(scanner.RawResult{Scanner: "popeye", Format: "json", Data: data})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	got := []string{}
	for _, f := range findings {
		got = append(got, f.CanonicalControl)
		if len(f.FoundBy) != 1 || f.FoundBy[0] != "popeye" {
			t.Errorf("found_by=%v, want [popeye]", f.FoundBy)
		}
	}
	sort.Strings(got)
	want := []string{"TATAR-OPS-003", "TATAR-OPS-004", "TATAR-OPS-005"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] %s, want %s", i, got[i], want[i])
		}
	}
}
