// Risk scoring-ийн context илрүүлэлт ба findings дээр хэрэглэх wiring.
package risk

import (
	"strings"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// DetectAssetContext — namespace нэрээс production/development/unknown үржүүлэгч.
// (MVP: namespace нэрийн эвристик. Дараа label-аар баяжуулж болно.)
func DetectAssetContext(namespace string) float64 {
	n := strings.ToLower(namespace)
	switch {
	case n == "prod" || n == "production" || strings.Contains(n, "prod"):
		return CtxProduction
	case strings.Contains(n, "dev") || strings.Contains(n, "test") ||
		strings.Contains(n, "stag") || strings.Contains(n, "qa"):
		return CtxDevelopment
	default:
		return CtxUnknown
	}
}

// DetectExposure — MVP-д Unknown (1.0). Ил гарсан байдлыг тодорхойлоход
// Service type / Ingress хэрэгтэй тул orchestrator дараа баяжуулна.
func DetectExposure(f finding.Finding) float64 {
	return ExpUnknown
}

// ApplyScores — finding бүрийн RiskContribution-ыг тооцоолж, cluster оноо
// (0..100) ба band-ыг буцаана.
func ApplyScores(findings []finding.Finding) ([]finding.Finding, int, string) {
	out := make([]finding.Finding, len(findings))
	copy(out, findings)

	penalties := make([]float64, len(out))
	severities := make([]finding.Severity, len(out))
	for i := range out {
		ctx := Context{
			AssetContext: DetectAssetContext(out[i].Namespace),
			Exposure:     DetectExposure(out[i]),
		}
		p := FindingRisk(out[i], ctx)
		out[i].RiskContribution = round1(p)
		penalties[i] = p
		severities[i] = out[i].Severity
	}
	score, band := ClusterScore(penalties, severities)
	return out, score, band
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}
