package orchestrator

import (
	"os"
	"strings"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/canonical"
	"github.com/ochmunkh/tatar-kuber/internal/finding"
	"github.com/ochmunkh/tatar-kuber/internal/scanner"
	"github.com/ochmunkh/tatar-kuber/internal/scanner/checkov"
	"github.com/ochmunkh/tatar-kuber/internal/scanner/kubescape"
	"github.com/ochmunkh/tatar-kuber/internal/scanner/popeye"
	"github.com/ochmunkh/tatar-kuber/internal/scanner/trivy"
)

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return b
}

func TestPipeline_EndToEnd(t *testing.T) {
	reg, err := canonical.Load("../../schema/canonical-controls.yaml")
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	rs := reg.NewResolver()

	p := New(reg,
		trivy.New(rs), kubescape.New(rs), checkov.New(rs), popeye.New(rs),
	)

	raws := []scanner.RawResult{
		{Scanner: "trivy", Version: "0.53.0", Data: mustRead(t, "../../tests/fixtures/trivy_k8s.json")},
		{Scanner: "kubescape", Version: "3.0.8", Data: mustRead(t, "../../testdata/kubescape/scan.json")},
		{Scanner: "checkov", Version: "3.2.0", Data: mustRead(t, "../../testdata/checkov/scan.json")},
		{Scanner: "popeye", Version: "0.21.5", Data: mustRead(t, "../../testdata/popeye/scan.json")},
	}

	res, err := p.Process(raws, Meta{ClusterName: "production", ScanMode: "remote"})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	// --- WOW moment: privileged container-ыг Trivy+Kubescape+Checkov хоёул олсон ---
	var priv *struct {
		FoundBy    []string
		Confidence string
		Severity   string
		Evidence   []finding.Evidence
	}
	for _, f := range res.Findings {
		if f.CanonicalControl == "TATAR-CON-001" && f.Resource == "deployment/api" {
			priv = &struct {
				FoundBy    []string
				Confidence string
				Severity   string
				Evidence   []finding.Evidence
			}{f.FoundBy, string(f.Confidence), string(f.Severity), f.Evidence}
		}
	}
	if priv == nil {
		t.Fatal("TATAR-CON-001 (privileged) олдсонгүй")
	}
	// trivy + kubescape + checkov гурвуулаа CON-001-ийг deployment/api дээр олсон
	has := map[string]bool{}
	for _, s := range priv.FoundBy {
		has[s] = true
	}
	if !has["trivy"] || !has["kubescape"] || !has["checkov"] {
		t.Errorf("CON-001 found_by=%v, want trivy+kubescape+checkov бүгд", priv.FoundBy)
	}
	if priv.Confidence != "HIGH" {
		t.Errorf("CON-001 confidence=%s, want HIGH (олон scanner)", priv.Confidence)
	}
	// dedup нь бүх scanner-ийн evidence-ийг нэгтгэсэн бөгөөд spec зам агуулсан эсэх
	hasPath := false
	for _, e := range priv.Evidence {
		if strings.Contains(e.Path, "securityContext.privileged") {
			hasPath = true
		}
	}
	if !hasPath {
		t.Errorf("CON-001 evidence=%+v, securityContext.privileged spec зам агуулаагүй", priv.Evidence)
	}
	if len(priv.Evidence) < 2 {
		t.Errorf("CON-001 evidence=%d ширхэг, олон scanner-ийн нотолгоо нэгдсэн байх ёстой", len(priv.Evidence))
	}

	// summary + score
	if res.Summary.TotalFindings == 0 {
		t.Error("total findings = 0")
	}
	if res.Summary.RiskScore < 0 || res.Summary.RiskScore > 100 {
		t.Errorf("risk_score=%d, 0..100 хооронд байх ёстой", res.Summary.RiskScore)
	}
	if res.Summary.RiskBand == "" {
		t.Error("risk_band хоосон")
	}

	// result_hash detrministik (findings ижил бол ижил hash)
	res2, _ := p.Process(raws, Meta{ClusterName: "production", ScanMode: "remote"})
	if res.Metadata.ResultHash != res2.Metadata.ResultHash {
		t.Errorf("result_hash detrministik биш: %s vs %s", res.Metadata.ResultHash, res2.Metadata.ResultHash)
	}
	if res.Metadata.ResultHash == "" {
		t.Error("result_hash хоосон")
	}
}
