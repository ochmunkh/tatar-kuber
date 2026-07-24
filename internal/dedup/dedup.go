// Package dedup merges findings that describe the same security issue
// (Doc #2 §6-7). Энэ бол TATAR-Kuber-ийн signature feature: олон scanner-ийн
// ижил илрүүлэлтийг НЭГ finding болгож, found_by-д бүх scanner-ыг хадгална.
package dedup

import (
	"sort"

	"github.com/ochmunkh/tatar-kuber/internal/canonical"
	"github.com/ochmunkh/tatar-kuber/internal/finding"
	"github.com/ochmunkh/tatar-kuber/internal/risk"
)

var sevRank = map[finding.Severity]int{
	finding.SeverityCritical: 5,
	finding.SeverityHigh:     4,
	finding.SeverityMedium:   3,
	finding.SeverityLow:      2,
	finding.SeverityInfo:     1,
}

// key — dedup түлхүүр: canonical_control + resource (kind/name) + namespace.
func key(f finding.Finding) string {
	return f.CanonicalControl + "|" + f.Resource + "|" + f.Namespace
}

// Deduplicate — ижил түлхүүртэй findings-ийг нэг болгоно.
//   - severity: хамгийн муу (max)
//   - found_by / references / raw_refs: union
//   - confidence: scanner тоо + determinism-ээс дахин тооцоолно
//   - id: canonical+resource+namespace-аас тогтвортой дахин үүсгэнэ
//   - гаралт: ID-аар эрэмбэлэгдсэн (detrministik result_hash)
func Deduplicate(findings []finding.Finding, reg *canonical.Registry) []finding.Finding {
	order := []string{}
	groups := map[string][]finding.Finding{}
	for _, f := range findings {
		k := key(f)
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], f)
	}

	out := make([]finding.Finding, 0, len(groups))
	for _, k := range order {
		g := groups[k]
		merged := g[0]
		foundBy := map[string]bool{}
		refs := map[string]bool{}

		for _, f := range g {
			if sevRank[f.Severity] > sevRank[merged.Severity] {
				merged.Severity = f.Severity
			}
			if sevRank[f.OriginalSeverity] > sevRank[merged.OriginalSeverity] {
				merged.OriginalSeverity = f.OriginalSeverity
			}
			// хамгийн дэлгэрэнгүй evidence-ийг сонгоно (ж: kubescape-ийн spec зам)
			if len(f.Evidence) > len(merged.Evidence) {
				merged.Evidence = f.Evidence
			}
			for _, s := range f.FoundBy {
				foundBy[s] = true
			}
			for _, r := range f.References {
				refs[r] = true
			}
			if f.FirstSeen != "" && (merged.FirstSeen == "" || f.FirstSeen < merged.FirstSeen) {
				merged.FirstSeen = f.FirstSeen
			}
			if f.LastSeen > merged.LastSeen {
				merged.LastSeen = f.LastSeen
			}
		}

		merged.FoundBy = sortedKeys(foundBy)
		merged.References = sortedKeys(refs)
		merged.RawRefs = mergeRawRefs(g)

		heur := false
		if c, ok := reg.Get(merged.CanonicalControl); ok {
			heur = c.Heuristic
		}
		merged.Confidence = risk.Confidence(len(merged.FoundBy), heur)
		merged.ID = finding.StableID(merged.CanonicalControl, merged.Resource, merged.Namespace)

		out = append(out, merged)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sortedKeys(m map[string]bool) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func mergeRawRefs(g []finding.Finding) []finding.RawRef {
	seen := map[string]bool{}
	var out []finding.RawRef
	for _, f := range g {
		for _, rr := range f.RawRefs {
			k := rr.Scanner + "|" + rr.RuleID
			if !seen[k] {
				seen[k] = true
				out = append(out, rr)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Scanner != out[j].Scanner {
			return out[i].Scanner < out[j].Scanner
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}
