// Package trivy — Trivy ScannerAdapter (image CVE, secret, misconfiguration).
package trivy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ochmunkh/tatar-kuber/internal/canonical"
	"github.com/ochmunkh/tatar-kuber/internal/finding"
	"github.com/ochmunkh/tatar-kuber/internal/risk"
	"github.com/ochmunkh/tatar-kuber/internal/scanner"
)

// Scanner implements scanner.ScannerAdapter.
type Scanner struct {
	resolver *canonical.Resolver
	now      func() string
}

// New — canonical resolver-ийг тарьж adapter үүсгэнэ.
func New(resolver *canonical.Resolver) *Scanner {
	return &Scanner{
		resolver: resolver,
		now:      func() string { return time.Now().UTC().Format(time.RFC3339) },
	}
}

func (s *Scanner) Name() string { return "trivy" }

func (s *Scanner) Available() (bool, error) {
	// TODO: PATH / ~/.tatar-kuber/tools/trivy шалгах.
	return false, nil
}

func (s *Scanner) Version(ctx context.Context) (string, error) {
	// TODO: "trivy --version" -> parse.
	return "", errors.New("not implemented")
}

func (s *Scanner) Supports(mode scanner.Mode) bool { return true } // local + remote

func (s *Scanner) Scan(ctx context.Context, t scanner.Target) (scanner.RawResult, error) {
	// TODO: local: "trivy config -f json <path>"; remote: "trivy k8s --format json".
	return scanner.RawResult{Scanner: "trivy", Format: "json"}, errors.New("not implemented")
}

// ---- Trivy JSON бүтэц (trivy k8s / config --format json) ----

type trivyReport struct {
	Resources []struct {
		Namespace string `json:"Namespace"`
		Kind      string `json:"Kind"`
		Name      string `json:"Name"`
		Results   []struct {
			Target           string `json:"Target"`
			Class            string `json:"Class"`
			Misconfigurations []struct {
				AVDID       string   `json:"AVDID"`
				ID          string   `json:"ID"`
				Title       string   `json:"Title"`
				Description string   `json:"Description"`
				Severity    string   `json:"Severity"`
				Resolution  string   `json:"Resolution"`
				References  []string `json:"References"`
			} `json:"Misconfigurations"`
			Vulnerabilities []struct {
				VulnerabilityID string `json:"VulnerabilityID"`
				PkgName         string `json:"PkgName"`
				FixedVersion    string `json:"FixedVersion"`
				Severity        string `json:"Severity"`
				Title           string `json:"Title"`
				PrimaryURL      string `json:"PrimaryURL"`
			} `json:"Vulnerabilities"`
			Secrets []struct {
				RuleID   string `json:"RuleID"`
				Category string `json:"Category"`
				Severity string `json:"Severity"`
				Title    string `json:"Title"`
				Match    string `json:"Match"`
			} `json:"Secrets"`
		} `json:"Results"`
	} `json:"Resources"`
}

// Normalize — Trivy raw JSON -> []finding.Finding (canonical-оор баяжуулсан).
func (s *Scanner) Normalize(raw scanner.RawResult) ([]finding.Finding, error) {
	var rep trivyReport
	if err := json.Unmarshal(raw.Data, &rep); err != nil {
		return nil, fmt.Errorf("trivy JSON parse: %w", err)
	}
	var out []finding.Finding
	for _, res := range rep.Resources {
		resource := fmt.Sprintf("%s/%s", strings.ToLower(res.Kind), res.Name)
		for _, r := range res.Results {
			for _, m := range r.Misconfigurations {
				ctx := canonical.ResolverContext{ResourceKind: res.Kind, Namespace: res.Namespace, Severity: m.Severity}
				if f, ok := s.build(m.AVDID, ctx, resource, res.Namespace, m.Title, m.Description, m.Resolution, m.Severity, m.References); ok {
					out = append(out, f)
				}
			}
			for _, v := range r.Vulnerabilities {
				ctx := canonical.ResolverContext{ResourceKind: res.Kind, Namespace: res.Namespace, Severity: v.Severity, Detail: "image"}
				rem := "Багц шинэчлэх"
				if v.FixedVersion != "" {
					rem = fmt.Sprintf("%s-г %s руу шинэчилнэ", v.PkgName, v.FixedVersion)
				}
				title := fmt.Sprintf("%s: %s", v.VulnerabilityID, v.Title)
				if f, ok := s.build("CVE-*", ctx, resource, res.Namespace, title, v.Title, rem, v.Severity, refs(v.PrimaryURL, v.VulnerabilityID)); ok {
					out = append(out, f)
				}
			}
			for _, sec := range r.Secrets {
				detail := "env"
				if strings.Contains(strings.ToLower(r.Target), "image") || strings.Contains(strings.ToLower(r.Class), "image") {
					detail = "image"
				}
				ctx := canonical.ResolverContext{ResourceKind: res.Kind, Namespace: res.Namespace, Severity: sec.Severity, Detail: detail}
				if f, ok := s.build("secret", ctx, resource, res.Namespace, sec.Title, "Илэрсэн нууц: "+sec.Category, "Нууцыг кодоос салгаж Secret store руу шилжүүлнэ", sec.Severity, nil); ok {
					out = append(out, f)
				}
			}
		}
	}
	return out, nil
}

// build — нэг Trivy илрүүлэлтийг canonical-аар баяжуулж Finding болгоно.
func (s *Scanner) build(ruleID string, ctx canonical.ResolverContext, resource, ns, title, desc, rem, sev string, references []string) (finding.Finding, bool) {
	cid, ok := s.resolver.ResolveOne("trivy", ruleID, ctx)
	if !ok {
		// canonical registry-д зураглал алга — алгасаж, normalizer-т warning.
		return finding.Finding{}, false
	}
	ctrl, _ := s.resolver.Control(cid)
	severity := normSeverity(sev)
	if severity == "" {
		severity = finding.Severity(ctrl.DefaultSeverity)
	}
	ts := s.now()
	return finding.Finding{
		ID:               finding.StableID(cid, resource, ns),
		CanonicalControl: cid,
		Resource:         resource,
		Namespace:        ns,
		Type:             finding.Type(ctrl.Type),
		Category:         ctrl.Category,
		Severity:         severity,
		Title:            title,
		Description:      desc,
		Remediation:      rem,
		FoundBy:          []string{"trivy"},
		Confidence:       risk.Confidence(1, ctrl.Heuristic), // ганц scanner + determinism
		BlindShot:        false,
		Status:           finding.StatusOpen,
		FirstSeen:        ts,
		LastSeen:         ts,
		References:       references,
		RawRefs:          []finding.RawRef{{Scanner: "trivy", RuleID: ruleID}},
	}, true
}

func normSeverity(s string) finding.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return finding.SeverityCritical
	case "HIGH":
		return finding.SeverityHigh
	case "MEDIUM":
		return finding.SeverityMedium
	case "LOW":
		return finding.SeverityLow
	case "UNKNOWN", "":
		return finding.SeverityInfo
	default:
		return finding.SeverityInfo
	}
}

func refs(url, cve string) []string {
	var r []string
	if cve != "" {
		r = append(r, cve)
	}
	if url != "" {
		r = append(r, url)
	}
	return r
}
