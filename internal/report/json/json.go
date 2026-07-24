// Package json renders ScanResult as machine-readable JSON (Unified Schema).
package json

import (
	stdjson "encoding/json"
	"io"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// Render — ScanResult-ийг indent JSON болгож бичнэ.
func Render(w io.Writer, res finding.ScanResult) error {
	enc := stdjson.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}
