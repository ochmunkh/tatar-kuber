// Package sarif renders findings as SARIF 2.1.0 (GitHub/GitLab/Azure DevOps).
// Тогтвортой rule ID (canonical) ашиглаж дедуп эвдэхгүй.
package sarif

import (
	"errors"
	"io"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// Render — TODO: SARIF 2.1.0 схем рүү хөрвүүлэх.
func Render(w io.Writer, res finding.ScanResult) error {
	return errors.New("sarif: not implemented")
}
