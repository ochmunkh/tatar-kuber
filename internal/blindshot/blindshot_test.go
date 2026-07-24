package blindshot

import (
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/canonical"
	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

func TestApply_DowngradesKnownComponent(t *testing.T) {
	reg, err := canonical.Load("../../schema/canonical-controls.yaml")
	if err != nil {
		t.Fatalf("registry: %v", err)
	}

	// CON-001 (privileged) blind_shot_rule: kube-system + calico-node -> INFO
	match := finding.Finding{
		CanonicalControl: "TATAR-CON-001",
		Resource:         "daemonset/calico-node",
		Namespace:        "kube-system",
		Severity:         finding.SeverityHigh,
	}
	// Ижил control, өөр resource -> өөрчлөгдөхгүй
	noMatch := finding.Finding{
		CanonicalControl: "TATAR-CON-001",
		Resource:         "deployment/api",
		Namespace:        "production",
		Severity:         finding.SeverityHigh,
	}

	out := Apply([]finding.Finding{match, noMatch}, reg)

	if !out[0].BlindShot {
		t.Error("calico-node blind_shot=false, want true")
	}
	if out[0].Severity != finding.SeverityInfo {
		t.Errorf("severity=%s, want INFO (downgraded)", out[0].Severity)
	}
	if out[0].OriginalSeverity != finding.SeverityHigh {
		t.Errorf("original_severity=%s, want HIGH (preserved)", out[0].OriginalSeverity)
	}
	if out[0].BlindShotReason == "" {
		t.Error("blind_shot_reason хоосон")
	}
	// finding УСТГАГДААГҮЙ байх ёстой
	if len(out) != 2 {
		t.Fatalf("findings=%d, want 2 (blind-shot нь устгахгүй)", len(out))
	}
	if out[1].BlindShot {
		t.Error("production/api буруугаар downgrade хийгдсэн")
	}
}
