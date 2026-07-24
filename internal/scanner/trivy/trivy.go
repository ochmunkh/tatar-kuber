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
	"github.com/ochmunkh/tatar-kuber/internal/normalizer"
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
			Target            string `json:"Target"`
			Class             string `json:"Class"`
			Misconfigurations []struct {
				AVDID         string   `json:"AVDID"`
				ID            string   `json:"ID"`
				Title         string   `json:"Title"`
				Description   string   `json:"Description"`
				Severity      string   `json:"Severity"`
				Resolution    string   `json:"Resolution"`
				References    []string `json:"References"`
				CauseMetadata struct {
					Resource  string `json:"Resource"`
					StartLine int    `json:"StartLine"`
				} `json:"CauseMetadata"`
			} `json:"Misconfigurations"`
			Vulnerabilities []struct {
				VulnerabilityID  string `json:"VulnerabilityID"`
				PkgName          string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
				FixedVersion     string `json:"FixedVersion"`
				Severity         string `json:"Severity"`
				Title            string `json:"Title"`
				PrimaryURL       string `json:"PrimaryURL"`
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

// Normalize — Trivy raw JSON -> []finding.Finding (canonical-аар баяжуулсан).
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
				ev := finding.Evidence{Scanner: "trivy", Path: m.CauseMetadata.Resource}
				if ev.Path == "" && m.CauseMetadata.StartLine > 0 {
					ev.Path = fmt.Sprintf("%s:%d", r.Target, m.CauseMetadata.StartLine)
				}
				meta := normalizer.Meta{Resource: resource, Namespace: res.Namespace, Title: m.Title, Description: m.Description, Evidence: []finding.Evidence{ev}, Remediation: m.Resolution, Severity: m.Severity, References: m.References}
				if f, ok := normalizer.Build(s.resolver, "trivy", m.AVDID, ctx, meta, s.now); ok {
					out = append(out, f)
				}
			}
			for _, v := range r.Vulnerabilities {
				ctx := canonical.ResolverContext{ResourceKind: res.Kind, Namespace: res.Namespace, Severity: v.Severity, Detail: "image"}
				rem := "Багц шинэчлэх"
				if v.FixedVersion != "" {
					rem = fmt.Sprintf("%s-г %s руу шинэчилнэ", v.PkgName, v.FixedVersion)
				}
				pkg := v.PkgName
				if v.InstalledVersion != "" {
					pkg = v.PkgName + "@" + v.InstalledVersion
				}
				val := ""
				if v.FixedVersion != "" {
					val = "fixed in " + v.FixedVersion
				}
				ev := finding.Evidence{Scanner: "trivy", Detail: pkg, Value: val}
				meta := normalizer.Meta{Resource: resource, Namespace: res.Namespace, Title: v.VulnerabilityID + ": " + v.Title, Description: v.Title, Evidence: []finding.Evidence{ev}, Remediation: rem, Severity: v.Severity, References: refs(v.PrimaryURL, v.VulnerabilityID)}
				if f, ok := normalizer.Build(s.resolver, "trivy", "CVE-*", ctx, meta, s.now); ok {
					out = append(out, f)
				}
			}
			for _, sec := range r.Secrets {
				detail := "env"
				if strings.Contains(strings.ToLower(r.Target), "image") || strings.Contains(strings.ToLower(r.Class), "image") {
					detail = "image"
				}
				ctx := canonical.ResolverContext{ResourceKind: res.Kind, Namespace: res.Namespace, Severity: sec.Severity, Detail: detail}
				ev := finding.Evidence{Scanner: "trivy", Detail: sec.Match}
				meta := normalizer.Meta{Resource: resource, Namespace: res.Namespace, Title: sec.Title, Description: "Илэрсэн нууц: " + sec.Category, Evidence: []finding.Evidence{ev}, Remediation: "Нууцыг кодоос салгаж Secret store руу шилжүүлнэ", Severity: sec.Severity}
				if f, ok := normalizer.Build(s.resolver, "trivy", "secret", ctx, meta, s.now); ok {
					out = append(out, f)
				}
			}
		}
	}
	return out, nil
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
