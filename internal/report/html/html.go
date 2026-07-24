// Package html renders a human-readable dashboard (Risk Score, Blind Shot, findings).
package html

import (
	"errors"
	"io"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// Render — TODO: html/template dashboard.
func Render(w io.Writer, res finding.ScanResult) error {
	return errors.New("html: not implemented")
}
