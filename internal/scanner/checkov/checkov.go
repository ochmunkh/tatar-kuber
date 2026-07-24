// Package checkov — Checkov ScannerAdapter (IaC: YAML/Helm/Terraform).
package checkov

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

type Scanner struct {
	resolver *canonical.Resolver
	now      func() string
}

func New(resolver *canonical.Resolver) *Scanner {
	return &Scanner{resolver: resolver, now: func() string { return time.Now().UTC().Format(time.RFC3339) }}
}

func (s *Scanner) Name() string { return "checkov" }

func (s *Scanner) Available() (bool, error) { return false, nil } // TODO

func (s *Scanner) Version(ctx context.Context) (string, error) { return "", errors.New("not implemented") }

func (s *Scanner) Supports(mode scanner.Mode) bool { return mode == scanner.ModeLocal } // static / local

func (s *Scanner) Scan(ctx context.Context, t scanner.Target) (scanner.RawResult, error) {
	// TODO: "checkov -d <path> -o json".
	return scanner.RawResult{Scanner: "checkov", Format: "json"}, errors.New("not implemented")
}

// ---- Checkov JSON бүтэц (checkov -o json) ----

type checkovBlock struct {
	CheckType string `json:"check_type"`
	Results   struct {
		FailedChecks []struct {
			CheckID   string `json:"check_id"`
			CheckName string `json:"check_name"`
			Resource  string `json:"resource"` // Kind.namespace.name эсвэл Kind.name
			Guideline string `json:"guideline"`
			Severity  string `json:"severity"`
		} `json:"failed_checks"`
	} `json:"results"`
}

// Normalize — Checkov raw JSON -> []finding.Finding. Гаралт нь массив эсвэл
// ганц объект байж болно — хоёуланг зохицуулна.
func (s *Scanner) Normalize(raw scanner.RawResult) ([]finding.Finding, error) {
	var blocks []checkovBlock
	if err := json.Unmarshal(raw.Data, &blocks); err != nil {
		var one checkovBlock
		if err2 := json.Unmarshal(raw.Data, &one); err2 != nil {
			return nil, fmt.Errorf("checkov JSON parse: %w", err)
		}
		blocks = []checkovBlock{one}
	}

	var out []finding.Finding
	for _, b := range blocks {
		for _, fc := range b.Results.FailedChecks {
			kind, ns, name := parseResource(fc.Resource)
			resource := strings.ToLower(kind) + "/" + name
			ctx := canonical.ResolverContext{ResourceKind: kind, Namespace: ns, Severity: fc.Severity}
			var refsList []string
			if fc.Guideline != "" {
				refsList = []string{fc.Guideline}
			}
			meta := normalizer.Meta{Resource: resource, Namespace: ns, Title: fc.CheckName, Severity: fc.Severity, References: refsList}
			if f, ok := normalizer.Build(s.resolver, "checkov", fc.CheckID, ctx, meta, s.now); ok {
				out = append(out, f)
			}
		}
	}
	return out, nil
}

// parseResource — "Kind.namespace.name" эсвэл "Kind.name" -> (kind, ns, name).
func parseResource(r string) (kind, ns, name string) {
	parts := strings.Split(r, ".")
	switch len(parts) {
	case 3:
		return parts[0], parts[1], parts[2]
	case 2:
		return parts[0], "", parts[1]
	default:
		if len(parts) > 0 {
			kind = parts[0]
		}
		if len(parts) > 0 {
			name = parts[len(parts)-1]
		}
		return kind, "", name
	}
}
