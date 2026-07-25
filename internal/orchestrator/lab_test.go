package orchestrator

import (
	"os"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/canonical"
	"github.com/ochmunkh/tatar-kuber/internal/scanner"
	"github.com/ochmunkh/tatar-kuber/internal/scanner/checkov"
	"github.com/ochmunkh/tatar-kuber/internal/scanner/kubescape"
	"github.com/ochmunkh/tatar-kuber/internal/scanner/popeye"
	"github.com/ochmunkh/tatar-kuber/internal/scanner/trivy"
)

// TATAR-Kuber Lab regression: бодит Checkov гаралт (lab/raw/checkov.json)-ыг
// pipeline-аар оруулж, эмзэг manifest-уудын хүлээгдсэн canonical control-ууд
// гарч байгааг батална. (checkov -d lab/broken-аас үүсгэсэн.)
func TestLab_CheckovBroken(t *testing.T) {
	reg, err := canonical.Load("../../schema/canonical-controls.yaml")
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	data, err := os.ReadFile("../../testdata/lab/checkov.json")
	if err != nil {
		t.Skipf("lab checkov.json алга: %v", err)
	}
	rs := reg.NewResolver()
	p := New(reg, trivy.New(rs), kubescape.New(rs), checkov.New(rs), popeye.New(rs))

	res, err := p.Process([]scanner.RawResult{{Scanner: "checkov", Version: "3.3.8", Data: data}},
		Meta{ClusterName: "tatar-kuber-lab", ScanMode: "local", Lang: "en"})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.CanonicalControl] = true
	}
	// Checkov-аар барих ёстой хүлээгдсэн control-ууд (SEC-001/NET нь Trivy/Kubescape-д)
	want := []string{
		"TATAR-CON-001", "TATAR-CON-002", "TATAR-CON-003", "TATAR-CON-005", "TATAR-CON-006",
		"TATAR-CON-009", "TATAR-CON-010", "TATAR-CON-011", "TATAR-IMG-003",
		"TATAR-OPS-001", "TATAR-OPS-002", "TATAR-OPS-005", "TATAR-RBAC-002", "TATAR-SEC-003",
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("lab: %s хүлээгдсэн ч гарсангүй", w)
		}
	}
	if res.Summary.TotalFindings < len(want) {
		t.Errorf("total findings=%d, дор хаяж %d байх ёстой", res.Summary.TotalFindings, len(want))
	}
}
