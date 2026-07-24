// Package normalizer — scanner-агностик Finding байгуулагч. Adapter бүр raw
// илрүүлэлтээ (scanner, ruleID, context, meta) болгож дамжуулахад энэ helper
// canonical-аар баяжуулж, severity/confidence/stable ID-г тохируулна.
package normalizer

import (
	"github.com/ochmunkh/tatar-kuber/internal/canonical"
	"github.com/ochmunkh/tatar-kuber/internal/finding"
	"github.com/ochmunkh/tatar-kuber/internal/risk"
)

// Meta — нэг илрүүлэлтийн хүний уншиж болох мэдээлэл.
type Meta struct {
	Resource    string // kind/name (жишээ: deployment/api)
	Namespace   string
	Title       string
	Description string
	Evidence    []finding.Evidence // асуудал яг хаана (scanner бүрээр)
	Remediation string
	Severity    string // scanner-ийн severity (хоосон бол canonical default)
	References  []string
}

// Build — нэг илрүүлэлтийг canonical-аар баяжуулж Finding болгоно.
// canonical registry-д зураглал олдоогүй бол (Finding{}, false).
func Build(rs *canonical.Resolver, scanner, ruleID string, ctx canonical.ResolverContext, m Meta, now func() string) (finding.Finding, bool) {
	cid, ok := rs.ResolveOne(scanner, ruleID, ctx)
	if !ok {
		return finding.Finding{}, false
	}
	ctrl, _ := rs.Control(cid)

	sev := finding.NormalizeSeverity(m.Severity)
	if sev == "" {
		sev = finding.Severity(ctrl.DefaultSeverity)
	}
	// Анхдагч хэл нь en (canonical). Orchestrator сонгосон --lang-аар дарж бичнэ.
	title := m.Title
	if title == "" {
		title = ctrl.Title.Get("en")
	}
	rem := ctrl.Remediation.Get("en")
	if rem == "" {
		rem = m.Remediation
	}
	ts := now()

	ev := m.Evidence
	for i := range ev {
		if ev[i].Scanner == "" {
			ev[i].Scanner = scanner
		}
	}

	return finding.Finding{
		ID:               finding.StableID(cid, m.Resource, m.Namespace),
		CanonicalControl: cid,
		Resource:         m.Resource,
		Namespace:        m.Namespace,
		Type:             finding.Type(ctrl.Type),
		Category:         ctrl.Category,
		Severity:         sev,
		OriginalSeverity: sev,
		Title:            title,
		Description:      m.Description,
		Evidence:         m.Evidence,
		Remediation:      rem,
		FoundBy:          []string{scanner},
		Confidence:       risk.Confidence(1, ctrl.Heuristic),
		BlindShot:        false,
		Status:           finding.StatusOpen,
		FirstSeen:        ts,
		LastSeen:         ts,
		References:       m.References,
		RawRefs:          []finding.RawRef{{Scanner: scanner, RuleID: ruleID}},
	}, true
}
