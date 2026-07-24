// Package popeye — Popeye ScannerAdapter (runtime hygiene: dead service, unused, broken ref).
package popeye

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
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

func (s *Scanner) Name() string { return "popeye" }

func (s *Scanner) Available() (bool, error) { return false, nil } // TODO

func (s *Scanner) Version(ctx context.Context) (string, error) { return "", errors.New("not implemented") }

func (s *Scanner) Supports(mode scanner.Mode) bool { return mode == scanner.ModeRemote } // live cluster only

func (s *Scanner) Scan(ctx context.Context, t scanner.Target) (scanner.RawResult, error) {
	// TODO: "popeye --out json".
	return scanner.RawResult{Scanner: "popeye", Format: "json"}, errors.New("not implemented")
}

// ---- Popeye JSON бүтэц (popeye --out json) ----

type popReport struct {
	Popeye struct {
		Sanitizers []struct {
			Sanitizer string `json:"sanitizer"`
			Issues    map[string][]struct {
				Level   int    `json:"level"`
				Message string `json:"message"`
			} `json:"issues"`
		} `json:"sanitizers"`
	} `json:"popeye"`
}

var popCode = regexp.MustCompile(`\[(POP-\d+)\]`)

// levelSeverity — Popeye level -> TATAR severity (Doc #4 §2).
func levelSeverity(l int) string {
	switch l {
	case 3:
		return "HIGH"
	case 2:
		return "MEDIUM"
	case 1:
		return "LOW"
	default:
		return "INFO"
	}
}

// Normalize — Popeye raw JSON -> []finding.Finding.
func (s *Scanner) Normalize(raw scanner.RawResult) ([]finding.Finding, error) {
	var rep popReport
	if err := json.Unmarshal(raw.Data, &rep); err != nil {
		return nil, fmt.Errorf("popeye JSON parse: %w", err)
	}
	var out []finding.Finding
	for _, san := range rep.Popeye.Sanitizers {
		kind := strings.TrimSuffix(san.Sanitizer, "s") // services -> service
		for resKey, issues := range san.Issues {
			ns, name := splitResKey(resKey)
			resource := kind + "/" + name
			for _, iss := range issues {
				m := popCode.FindStringSubmatch(iss.Message)
				if len(m) < 2 {
					continue // POP код олдсонгүй
				}
				code := m[1]
				ctx := canonical.ResolverContext{ResourceKind: kind, Namespace: ns, Severity: levelSeverity(iss.Level)}
				detail := strings.TrimSpace(popCode.ReplaceAllString(iss.Message, ""))
				evs := []finding.Evidence{{Scanner: "popeye", Detail: detail}}
				meta := normalizer.Meta{Resource: resource, Namespace: ns, Evidence: evs, Severity: levelSeverity(iss.Level)}
				if f, ok := normalizer.Build(s.resolver, "popeye", code, ctx, meta, s.now); ok {
					out = append(out, f)
				}
			}
		}
	}
	return out, nil
}

// splitResKey — "namespace/name" эсвэл "name" -> (ns, name).
func splitResKey(k string) (ns, name string) {
	if i := strings.Index(k, "/"); i >= 0 {
		return k[:i], k[i+1:]
	}
	return "", k
}
