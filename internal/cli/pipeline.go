package cli

import (
	"encoding/json"
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

// loadRawDir — <dir>/{trivy,kubescape,checkov,popeye}.json-г RawResult болгож ачаална.
// Сонголттойгоор versions.json (scanner->version) ба inventory.json (объект->тоо)-г уншина.
func loadRawDir(dir string) ([]scanner.RawResult, map[string]int, error) {
	names := []string{"trivy", "kubescape", "checkov", "popeye"}
	var raws []scanner.RawResult
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join(dir, n+".json"))
		if err != nil {
			continue // тухайн scanner-ийн raw байхгүй бол алгасна
		}
		raws = append(raws, scanner.RawResult{Scanner: n, Format: "json", Data: data})
	}
	if len(raws) == 0 {
		return nil, nil, fmt.Errorf("%s дотор scanner raw JSON олдсонгүй", dir)
	}

	// versions.json (сонголт): scanner -> version
	if vb, err := os.ReadFile(filepath.Join(dir, "versions.json")); err == nil {
		var vers map[string]string
		if json.Unmarshal(vb, &vers) == nil {
			for i := range raws {
				if v, ok := vers[raws[i].Scanner]; ok {
					raws[i].Version = v
				}
			}
		}
	}

	// inventory.json (сонголт): объект -> тоо
	var inv map[string]int
	if ib, err := os.ReadFile(filepath.Join(dir, "inventory.json")); err == nil {
		_ = json.Unmarshal(ib, &inv)
	}

	return raws, inv, nil
}
