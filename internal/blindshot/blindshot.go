// Package blindshot — контекст дээр суурилсан severity downgrade engine.
// ЗАРЧИМ: finding-ийг ХЭЗЭЭ Ч устгахгүй. Зөвхөн severity-г бууруулж
// (original_severity хадгална), blind_shot=true + шалтгаан тэмдэглэнэ.
// Аудитын үүднээс бүх зүйл ил үлдэнэ (Doc #4 §5).
package blindshot

import (
	"strings"

	"github.com/ochmunkh/tatar-kuber/internal/canonical"
	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// Apply — canonical control-ийн blind_shot_rules-аар findings-ийг тохируулна.
func Apply(findings []finding.Finding, reg *canonical.Registry) []finding.Finding {
	out := make([]finding.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		f := &out[i]
		ctrl, ok := reg.Get(f.CanonicalControl)
		if !ok || len(ctrl.BlindShotRules) == 0 {
			continue
		}
		for _, rule := range ctrl.BlindShotRules {
			if !matches(rule, *f) {
				continue
			}
			if f.OriginalSeverity == "" {
				f.OriginalSeverity = f.Severity
			}
			down := finding.Severity(rule.DowngradeTo)
			if down == "" {
				down = finding.SeverityInfo
			}
			f.Severity = down
			f.BlindShot = true
			f.BlindShotReason = rule.Reason
			break // эхний тохирсон дүрэм
		}
	}
	return out
}

func matches(rule canonical.BlindShotRule, f finding.Finding) bool {
	if rule.Namespace != "" && rule.Namespace != f.Namespace {
		return false
	}
	if rule.ResourceMatch != "" && !strings.Contains(f.Resource, rule.ResourceMatch) {
		return false
	}
	return true
}
