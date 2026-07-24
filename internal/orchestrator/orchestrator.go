// Package orchestrator wires the full TATAR-Kuber pipeline:
// raw scanner output -> normalize -> dedup -> blind-shot -> score -> ScanResult.
package orchestrator

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"

	"github.com/ochmunkh/tatar-kuber/internal/blindshot"
	"github.com/ochmunkh/tatar-kuber/internal/canonical"
	"github.com/ochmunkh/tatar-kuber/internal/dedup"
	"github.com/ochmunkh/tatar-kuber/internal/finding"
	"github.com/ochmunkh/tatar-kuber/internal/risk"
	"github.com/ochmunkh/tatar-kuber/internal/scanner"
)

const tatarVersion = "1.0.0"

// Pipeline — scanner-агностик цөм.
type Pipeline struct {
	reg      *canonical.Registry
	adapters []scanner.ScannerAdapter
}

// New — registry + adapter-уудаас pipeline үүсгэнэ.
func New(reg *canonical.Registry, adapters ...scanner.ScannerAdapter) *Pipeline {
	return &Pipeline{reg: reg, adapters: adapters}
}

// Meta — scan-ий тодорхойлолт.
type Meta struct {
	ClusterName string
	ScanMode    string // local | remote
}

// Run — Available adapter-уудыг ажиллуулж raw цуглуулаад Process руу дамжуулна.
// (Scanner binary байхгүй бол тухайн adapter алгасагдана.)
func (p *Pipeline) Run(ctx context.Context, t scanner.Target, m Meta) (finding.ScanResult, error) {
	var raws []scanner.RawResult
	for _, a := range p.adapters {
		if !a.Supports(t.Mode) {
			continue
		}
		ok, _ := a.Available()
		if !ok {
			continue
		}
		raw, err := a.Scan(ctx, t)
		if err != nil {
			continue // graceful degradation
		}
		if v, err := a.Version(ctx); err == nil {
			raw.Version = v
		}
		raws = append(raws, raw)
	}
	return p.Process(raws, m)
}

// Process — цуглуулсан raw үр дүнгээс бүрэн ScanResult байгуулна.
// (Тест болон CLI хоёулаа энэ замыг ашиглана.)
func (p *Pipeline) Process(raws []scanner.RawResult, m Meta) (finding.ScanResult, error) {
	started := time.Now().UTC()

	byName := map[string]scanner.ScannerAdapter{}
	for _, a := range p.adapters {
		byName[a.Name()] = a
	}

	var all []finding.Finding
	versions := map[string]string{}
	for _, raw := range raws {
		a, ok := byName[raw.Scanner]
		if !ok {
			continue
		}
		versions[raw.Scanner] = raw.Version
		fs, err := a.Normalize(raw)
		if err != nil {
			continue // graceful degradation
		}
		all = append(all, fs...)
	}

	deduped := dedup.Deduplicate(all, p.reg)
	shot := blindshot.Apply(deduped, p.reg)
	scored, score, band := risk.ApplyScores(shot)

	res := finding.ScanResult{
		SchemaVersion: "1.0",
		Metadata: finding.Metadata{
			ScanID:          randID(),
			ClusterName:     m.ClusterName,
			ScanMode:        m.ScanMode,
			TatarVersion:    tatarVersion,
			ScannerVersions: versions,
			StartedAt:       started.Format(time.RFC3339),
			FinishedAt:      time.Now().UTC().Format(time.RFC3339),
		},
		Summary:  summarize(scored, score, band),
		Findings: scored,
	}
	res.Metadata.ResultHash = resultHash(scored)
	return res, nil
}

func summarize(fs []finding.Finding, score int, band string) finding.Summary {
	counts := map[finding.Severity]int{
		finding.SeverityCritical: 0, finding.SeverityHigh: 0, finding.SeverityMedium: 0,
		finding.SeverityLow: 0, finding.SeverityInfo: 0,
	}
	blind := 0
	for _, f := range fs {
		counts[f.Severity]++
		if f.BlindShot {
			blind++
		}
	}
	return finding.Summary{
		Counts:        counts,
		BlindShot:     blind,
		RiskScore:     score,
		RiskBand:      band,
		TotalFindings: len(fs),
	}
}

// randID — санамсаргүй scan_id (гадаад хамааралгүй).
func randID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// resultHash — findings-ийн detrministik hash (id+severity, эрэмбэлсэн).
// Нотолгоо (immutability) ба scan хоорондын diff-д ашиглагдана.
func resultHash(fs []finding.Finding) string {
	lines := make([]string, len(fs))
	for i, f := range fs {
		lines[i] = f.ID + ":" + string(f.Severity)
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte("\n"))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
