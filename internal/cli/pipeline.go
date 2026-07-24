package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ochmunkh/tatar-kuber/internal/canonical"
	"github.com/ochmunkh/tatar-kuber/internal/orchestrator"
	"github.com/ochmunkh/tatar-kuber/internal/scanner"
	"github.com/ochmunkh/tatar-kuber/internal/scanner/checkov"
	"github.com/ochmunkh/tatar-kuber/internal/scanner/kubescape"
	"github.com/ochmunkh/tatar-kuber/internal/scanner/popeye"
	"github.com/ochmunkh/tatar-kuber/internal/scanner/trivy"
)

// resolveRegistry — canonical-controls.yaml замыг олно.
// Дараалал: --registry флаг > $TATAR_REGISTRY > ./schema/canonical-controls.yaml.
func resolveRegistry(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	if env := os.Getenv("TATAR_REGISTRY"); env != "" {
		return env, nil
	}
	def := filepath.Join("schema", "canonical-controls.yaml")
	if _, err := os.Stat(def); err == nil {
		return def, nil
	}
	return "", fmt.Errorf("canonical registry олдсонгүй: --registry эсвэл $TATAR_REGISTRY заана уу")
}

// buildPipeline — registry + 4 adapter-аас pipeline угсарна.
func buildPipeline(registryPath string) (*orchestrator.Pipeline, error) {
	reg, err := canonical.Load(registryPath)
	if err != nil {
		return nil, err
	}
	rs := reg.NewResolver()
	return orchestrator.New(reg,
		trivy.New(rs), kubescape.New(rs), checkov.New(rs), popeye.New(rs),
	), nil
}

// loadRawDir — <dir>/{trivy,kubescape,checkov,popeye}.json файлуудыг RawResult болгож ачаална.
func loadRawDir(dir string) ([]scanner.RawResult, error) {
	names := []string{"trivy", "kubescape", "checkov", "popeye"}
	var raws []scanner.RawResult
	for _, n := range names {
		path := filepath.Join(dir, n+".json")
		data, err := os.ReadFile(path)
		if err != nil {
			continue // тухайн scanner-ийн raw байхгүй бол алгасна
		}
		raws = append(raws, scanner.RawResult{Scanner: n, Format: "json", Data: data})
	}
	if len(raws) == 0 {
		return nil, fmt.Errorf("%s дотор scanner raw JSON олдсонгүй", dir)
	}
	return raws, nil
}
