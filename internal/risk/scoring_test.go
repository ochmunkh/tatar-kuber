package risk

import (
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// Doc #4 §9-ийн ажилласан жишээг баталгаажуулна.
func TestClusterScore_DocExamples(t *testing.T) {
	// Cluster A: 1 CRITICAL (prod, internal, MEDIUM conf) + 100 LOW (dev, internal, MEDIUM conf)
	var penA []float64
	var sevA []finding.Severity
	// critical: 10 * 1.5 * 1.0 * 1.0 = 15
	penA = append(penA, 10*CtxProduction*ExpInternal*1.0)
	sevA = append(sevA, finding.SeverityCritical)
	for i := 0; i < 100; i++ {
		// low: 1 * 0.8 * 1.0 * 1.0 = 0.8
		penA = append(penA, 1*CtxDevelopment*ExpInternal*1.0)
		sevA = append(sevA, finding.SeverityLow)
	}
	// Diminishing: total=25 -> 100/(1+0.25)=80 (Good)
	if got, band := ClusterScore(penA, sevA); got != 80 || band != "Good" {
		t.Errorf("Cluster A: got %d (%s), want 80 (Good)", got, band)
	}

	// Cluster B: 10 HIGH (prod, internet, MEDIUM conf) — 7*1.5*1.5*1.0=15.75 each → cap 100
	var penB []float64
	var sevB []finding.Severity
	for i := 0; i < 10; i++ {
		penB = append(penB, 7*CtxProduction*ExpInternet*1.0)
		sevB = append(sevB, finding.SeverityHigh)
	}
	// Diminishing: total=157.5 -> 100/(1+1.575)=39 (Poor)
	if got, band := ClusterScore(penB, sevB); got != 39 || band != "Poor" {
		t.Errorf("Cluster B: got %d (%s), want 39 (Poor)", got, band)
	}
}
