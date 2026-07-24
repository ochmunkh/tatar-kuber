// Package kubescape — Kubescape ScannerAdapter (NSA/MITRE/RBAC, primary posture engine).
package kubescape

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

func (s *Scanner) Name() string { return "kubescape" }

func (s *Scanner) Available() (bool, error) { return false, nil } // TODO

func (s *Scanner) Version(ctx context.Context) (string, error) { return "", errors.New("not implemented") }

func (s *Scanner) Supports(mode scanner.Mode) bool { return true } // local + remote

func (s *Scanner) Scan(ctx context.Context, t scanner.Target) (scanner.RawResult, error) {
	// TODO: "kubescape scan --format json --output -".
	return scanner.RawResult{Scanner: "kubescape", Format: "json"}, errors.New("not implemented")
}

// ---- Kubescape JSON бүтэц (kubescape scan --format json) ----

type ksReport struct {
	Results []struct {
		ResourceID string `json:"resourceID"`
		Controls   []struct {
			ControlID string `json:"controlID"`
			Name      string `json:"name"`
			Status    struct {
				Status string `json:"status"`
			} `json:"status"`
			Rules []struct {
				Paths []struct {
					FailedPath string `json:"failedPath"`
					FixPath    struct {
						Path  string `json:"path"`
						Value string `json:"value"`
					} `json:"fixPath"`
				} `json:"paths"`
			} `json:"rules"`
		} `json:"controls"`
	} `json:"results"`
	Resources []struct {
		ResourceID string `json:"resourceID"`
		Object     struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
		} `json:"object"`
	} `json:"resources"`
}

// Normalize — Kubescape raw JSON -> []finding.Finding.
func (s *Scanner) Normalize(raw scanner.RawResult) ([]finding.Finding, error) {
	var rep ksReport
	if err := json.Unmarshal(raw.Data, &rep); err != nil {
		return nil, fmt.Errorf("kubescape JSON parse: %w", err)
	}
	// resourceID -> object
	objs := map[string]struct{ Kind, Name, NS string }{}
	for _, r := range rep.Resources {
		objs[r.ResourceID] = struct{ Kind, Name, NS string }{r.Object.Kind, r.Object.Metadata.Name, r.Object.Metadata.Namespace}
	}

	var out []finding.Finding
	for _, res := range rep.Results {
		o := objs[res.ResourceID]
		resource := strings.ToLower(o.Kind) + "/" + o.Name
		for _, c := range res.Controls {
			if c.Status.Status != "failed" {
				continue // зөвхөн унасан control-ыг finding болгоно
			}
			var evs []finding.Evidence
			for _, rule := range c.Rules {
				for _, pth := range rule.Paths {
					e := finding.Evidence{Scanner: "kubescape"}
					if pth.FixPath.Path != "" {
						e.Path = pth.FixPath.Path
						if pth.FixPath.Value != "" {
							e.Value = "зөвлөмж: " + pth.FixPath.Value
						}
					} else if pth.FailedPath != "" {
						e.Path = pth.FailedPath
					}
					if e.Path != "" {
						evs = append(evs, e)
					}
				}
			}
			ctx := canonical.ResolverContext{ResourceKind: o.Kind, Namespace: o.NS}
			meta := normalizer.Meta{Resource: resource, Namespace: o.NS, Title: c.Name, Evidence: evs}
			if f, ok := normalizer.Build(s.resolver, "kubescape", c.ControlID, ctx, meta, s.now); ok {
				out = append(out, f)
			}
		}
	}
	return out, nil
}
