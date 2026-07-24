// Package popeye — Popeye ScannerAdapter (skeleton stub).
package popeye

import (
	"context"
	"errors"
	"time"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
	"github.com/ochmunkh/tatar-kuber/internal/scanner"
)

// Scanner implements scanner.ScannerAdapter.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "popeye" }

func (s *Scanner) Available() (bool, error) {
	// TODO: PATH / ~/.tatar-kuber/tools/ дотор binary шалгах.
	return false, nil
}

func (s *Scanner) Version(ctx context.Context) (string, error) {
	// TODO: "popeye --version" ажиллуулж хувилбар авах.
	return "", errors.New("not implemented")
}

func (s *Scanner) Supports(mode scanner.Mode) bool {
	// TODO: Popeye local/remote горимын дэмжлэгийг тодорхойлно.
	return true
}

func (s *Scanner) Scan(ctx context.Context, t scanner.Target) (scanner.RawResult, error) {
	// TODO: popeye-г дэд процессоор ажиллуулж raw JSON/SARIF авах.
	return scanner.RawResult{Scanner: "popeye", Format: "json", Duration: time.Duration(0)}, errors.New("not implemented")
}

func (s *Scanner) Normalize(raw scanner.RawResult) ([]finding.Finding, error) {
	// TODO: raw → []finding.Finding, canonical-оор баяжуулах.
	return nil, errors.New("not implemented")
}
