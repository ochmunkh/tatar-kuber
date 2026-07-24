package risk

import (
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

func TestApplyScores(t *testing.T) {
	// CRITICAL, production, MEDIUM confidence -> 10 * 1.5 * 1.0 * 1.0 = 15
	f := finding.Finding{
		CanonicalControl: "TATAR-RBAC-001",
		Namespace:        "production",
		Severity:         finding.SeverityCritical,
		Confidence:       finding.ConfidenceMedium,
	}
	scored, score, band := ApplyScores([]finding.Finding{f})
	if scored[0].RiskContribution != 15 {
		t.Errorf("risk_contribution=%v, want 15", scored[0].RiskContribution)
	}
	if score != 85 || band != "Good" {
		t.Errorf("score=%d (%s), want 85 (Good)", score, band)
	}
}

func TestDetectAssetContext(t *testing.T) {
	cases := map[string]float64{
		"production": CtxProduction,
		"prod-eu":    CtxProduction,
		"dev":        CtxDevelopment,
		"staging":    CtxDevelopment,
		"payments":   CtxUnknown,
	}
	for ns, want := range cases {
		if got := DetectAssetContext(ns); got != want {
			t.Errorf("DetectAssetContext(%q)=%v, want %v", ns, got, want)
		}
	}
}
