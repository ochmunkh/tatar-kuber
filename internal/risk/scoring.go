// Package risk implements the TATAR-Kuber Risk Scoring Model v1.2.
// Level 1: Finding Risk = base_weight × asset_context × exposure × confidence
// Level 2: Security Score = 100 − Total Penalty (LOW pool cap = 10)
package risk

import (
	"math"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// ---- Level 1 multipliers (LOCK, Doc #4) ----

var baseWeight = map[finding.Severity]float64{
	finding.SeverityCritical: 10,
	finding.SeverityHigh:     7,
	finding.SeverityMedium:   3,
	finding.SeverityLow:      1,
	finding.SeverityInfo:     0,
}

var confidenceMul = map[finding.Confidence]float64{
	finding.ConfidenceHigh:   1.2,
	finding.ConfidenceMedium: 1.0,
	finding.ConfidenceLow:    0.8,
}

// AssetContext / Exposure үржүүлэгч.
const (
	CtxProduction  = 1.5
	CtxUnknown     = 1.0
	CtxDevelopment = 0.8

	ExpInternet = 1.5
	ExpInternal = 1.0
	ExpUnknown  = 1.0
)

// LowPoolCap — бүх LOW finding-ийн нийт penalty дээд хязгаар.
const LowPoolCap = 10.0

// Context — finding-ийн орчны мэдээлэл (илрүүлэгчээс).
type Context struct {
	AssetContext float64 // Ctx*
	Exposure     float64 // Exp*
}

// FindingRisk — Level 1 оноо (finding.RiskContribution).
func FindingRisk(f finding.Finding, ctx Context) float64 {
	w := baseWeight[f.Severity]
	c := confidenceMul[f.Confidence]
	if c == 0 {
		c = 1.0
	}
	ac := ctx.AssetContext
	if ac == 0 {
		ac = CtxUnknown
	}
	ex := ctx.Exposure
	if ex == 0 {
		ex = ExpUnknown
	}
	return w * ac * ex * c
}

// ClusterScore — Level 2 (0..100). penalties нь FindingRisk утгууд,
// severities нь тэдгээрт харгалзах severity (LOW pool cap-д хэрэгтэй).
func ClusterScore(penalties []float64, severities []finding.Severity) (int, string) {
	var high, low float64
	for i, p := range penalties {
		if i < len(severities) && severities[i] == finding.SeverityLow {
			low += p
		} else if i < len(severities) && severities[i] == finding.SeverityInfo {
			// INFO оноонд нөлөөлөхгүй
		} else {
			high += p
		}
	}
	total := high + math.Min(LowPoolCap, low)
	total = math.Min(100, total)
	score := int(math.Round(100 - total))
	if score < 0 {
		score = 0
	}
	return score, Band(score)
}

// Band — оноо → эрсдэлийн зурвас.
func Band(score int) string {
	switch {
	case score >= 90:
		return "Excellent"
	case score >= 70:
		return "Good"
	case score >= 50:
		return "Fair"
	case score >= 30:
		return "Poor"
	default:
		return "Critical"
	}
}

// Confidence — итгэлийн зэргийг scanner corroboration БА check determinism
// хоёулангаас тодорхойлно (Doc #4 §4.3, v1.2 уточнение).
//
//	scannerCount >= 2            -> HIGH  (олон scanner санал нийлсэн)
//	scannerCount == 1 && !heur   -> HIGH  (deterministic шалгалт, ж: CVE, талбар)
//	scannerCount == 1 && heur    -> MEDIUM (ганц scanner, эвристик)
//	scannerCount == 0            -> LOW   (зөвхөн контекст/дүгнэлт)
//
// heuristic нь canonical control-ийн шинж (Registry.Control.Heuristic).
func Confidence(scannerCount int, heuristic bool) finding.Confidence {
	switch {
	case scannerCount >= 2:
		return finding.ConfidenceHigh
	case scannerCount == 1 && !heuristic:
		return finding.ConfidenceHigh
	case scannerCount == 1 && heuristic:
		return finding.ConfidenceMedium
	default:
		return finding.ConfidenceLow
	}
}
