// Package canonical loads and queries the TATAR Canonical Control Registry
// (schema/canonical-controls.yaml) — product-ийн гол хөрөнгө.
package canonical

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// BlindShotRule — контекстээр severity downgrade хийх дүрэм (устгахгүй).
type BlindShotRule struct {
	Namespace     string `yaml:"namespace"`
	ResourceMatch string `yaml:"resource_match"`
	Reason        string `yaml:"reason"`
	DowngradeTo   string `yaml:"downgrade_to"`
}

// Control — нэг canonical control.
type Control struct {
	ID              string              `yaml:"id"`
	Title           string              `yaml:"title"`
	Category        string              `yaml:"category"`
	Type            string              `yaml:"type"`
	DefaultSeverity string              `yaml:"default_severity"`
	Status          string              `yaml:"status"` // active | deprecated
	Description     string              `yaml:"description"`
	Remediation     string              `yaml:"remediation"`
	References      []string            `yaml:"references"`
	Mappings        map[string][]string `yaml:"mappings"` // scanner -> rule IDs
	BlindShotRules  []BlindShotRule     `yaml:"blind_shot_rules"`
	SupersededBy    string              `yaml:"superseded_by,omitempty"`

	// Heuristic — контекст шаарддаг эвристик шалгалт эсэх. false (default)
	// бол deterministic (CVE, тодорхой талбарын шалгалт). Confidence-д нөлөөлнө.
	Heuristic bool `yaml:"heuristic"`
}

// Category — ангилал.
type Category struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
}

// Registry — бүх canonical control.
type Registry struct {
	SchemaVersion string     `yaml:"schema_version"`
	LastUpdated   string     `yaml:"last_updated"`
	Categories    []Category `yaml:"categories"`
	Controls      []Control  `yaml:"controls"`

	// байгуулагдах index: scanner -> ruleID -> []canonicalID
	// Тэмдэглэл: нэг scanner rule ОЛОН canonical control руу зурагдаж болно
	// (ж: trivy "CVE-*" -> IMG-001/IMG-002 severity-ээр; kubescape C-0018 ->
	// OPS-001/OPS-002 probe төрлөөр). Тиймээс утга нь жагсаалт.
	index map[string]map[string][]string
}

// Load — canonical-controls.yaml ачаалж index байгуулна.
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("canonical registry уншиж чадсангүй: %w", err)
	}
	var r Registry
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("canonical registry parse алдаа: %w", err)
	}
	if err := r.buildIndex(); err != nil {
		return nil, err
	}
	return &r, nil
}

func (r *Registry) buildIndex() error {
	r.index = map[string]map[string][]string{}
	seen := map[string]bool{}
	for _, c := range r.Controls {
		if seen[c.ID] {
			return fmt.Errorf("давхардсан canonical ID: %s", c.ID)
		}
		seen[c.ID] = true
		for scanner, rules := range c.Mappings {
			if r.index[scanner] == nil {
				r.index[scanner] = map[string][]string{}
			}
			for _, rule := range rules {
				r.index[scanner][rule] = append(r.index[scanner][rule], c.ID)
			}
		}
	}
	return nil
}

// Resolve — scanner + rule ID-аас canonical control ID-уудыг (candidates) олно.
// Нэг rule олон control руу зурагдаж болох тул жагсаалт буцаана. Хэрэв нэгээс
// олон бол normalizer нь finding-ийн дэд мэдээллээр (CVE severity, probe төрөл,
// resource kind г.м) дискриминаци хийж зөв canonical-ыг сонгоно.
// Олдоогүй бол (nil, false).
func (r *Registry) Resolve(scanner, ruleID string) ([]string, bool) {
	m, ok := r.index[scanner]
	if !ok {
		return nil, false
	}
	ids, ok := m[ruleID]
	return ids, ok
}

// Get — canonical ID-аар Control авна.
func (r *Registry) Get(id string) (Control, bool) {
	for _, c := range r.Controls {
		if c.ID == id {
			return c, true
		}
	}
	return Control{}, false
}

// ResolverContext — нэг scanner rule олон canonical руу зурагдсан үед
// зөв canonical-ыг сонгоход хэрэглэх finding-ийн дэд мэдээлэл.
// Жишээ: trivy "CVE-*" -> IMG-001(CRITICAL)/IMG-002(HIGH)-ыг Severity-ээр;
//        kubescape "C-0018" -> OPS-001(readiness)/OPS-002(liveness)-ыг Detail-ээр.
type ResolverContext struct {
	ResourceKind string // Deployment, Service, Role, ...
	Namespace    string
	Severity     string // scanner-ийн өгсөн severity (CVE-д чухал)
	Detail       string // rule-specific тэмдэг (ж: "readiness", "liveness", "image", "env")
}

// Resolver — Registry дээр суурилсан, олон candidate-аас нэгийг сонгодог.
// disamb: (candidateIDs, ctx) -> сонгосон canonicalID.
type Resolver struct {
	reg   *Registry
	rules map[string]func([]string, ResolverContext) string // scanner|ruleID -> selector
}

// NewResolver — resolver үүсгэж, олон-candidate rule-уудад selector бүртгэнэ.
func (r *Registry) NewResolver() *Resolver {
	res := &Resolver{reg: r, rules: map[string]func([]string, ResolverContext) string{}}

	// CVE severity-ээр IMG-001(CRITICAL) vs IMG-002(HIGH)
	bySeverity := func(cands []string, ctx ResolverContext) string {
		if ctx.Severity == "CRITICAL" {
			return pick(cands, "TATAR-IMG-001")
		}
		return pick(cands, "TATAR-IMG-002")
	}
	res.rules["trivy|CVE-*"] = bySeverity
	res.rules["kubescape|C-0078"] = bySeverity

	// probe төрлөөр OPS-001(readiness) vs OPS-002(liveness)
	res.rules["kubescape|C-0018"] = func(cands []string, ctx ResolverContext) string {
		if ctx.Detail == "liveness" {
			return pick(cands, "TATAR-OPS-002")
		}
		return pick(cands, "TATAR-OPS-001")
	}

	// secret байршлаар SEC-001(env) / SEC-002(image) / SEC-004(configmap)
	res.rules["trivy|secret"] = func(cands []string, ctx ResolverContext) string {
		switch ctx.Detail {
		case "image":
			return pick(cands, "TATAR-SEC-002")
		case "configmap":
			return pick(cands, "TATAR-SEC-004")
		default:
			return pick(cands, "TATAR-SEC-001")
		}
	}

	// default-deny эсэхээр NET-001 vs NET-002
	res.rules["kubescape|C-0260"] = func(cands []string, ctx ResolverContext) string {
		if ctx.Detail == "default-deny" {
			return pick(cands, "TATAR-NET-002")
		}
		return pick(cands, "TATAR-NET-001")
	}
	return res
}

// ResolveOne — scanner + ruleID + context-оос ганц canonical ID сонгоно.
func (rs *Resolver) ResolveOne(scanner, ruleID string, ctx ResolverContext) (string, bool) {
	cands, ok := rs.reg.Resolve(scanner, ruleID)
	if !ok || len(cands) == 0 {
		return "", false
	}
	if len(cands) == 1 {
		return cands[0], true
	}
	if sel, ok := rs.rules[scanner+"|"+ruleID]; ok {
		if id := sel(cands, ctx); id != "" {
			return id, true
		}
	}
	// Selector алга бол эхний candidate-ыг сонгоод анхааруулга үлдээх ёстой.
	// (TODO: normalizer-т warning лог гаргах.)
	return cands[0], true
}

func pick(cands []string, want string) string {
	for _, c := range cands {
		if c == want {
			return c
		}
	}
	return ""
}

// Control — Resolver-оос canonical control авах туслах.
func (rs *Resolver) Control(id string) (Control, bool) { return rs.reg.Get(id) }
