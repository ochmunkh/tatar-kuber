package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ochmunkh/tatar-kuber/internal/orchestrator"
	"github.com/ochmunkh/tatar-kuber/internal/scanner"
)

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	file := fs.String("f", "", "local manifest/Helm зам (Mode A)")
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig файл (Mode B)")
	context_ := fs.String("context", "", "kubeconfig context (Mode B)")
	rawDir := fs.String("raw-dir", "", "цуглуулсан scanner raw JSON-уудын хавтас (offline ingest)")
	cluster := fs.String("cluster", "cluster", "cluster/target нэр (тайланд)")
	outDir := fs.String("o", ".", "гаралтын хавтас")
	registry := fs.String("registry", "", "canonical-controls.yaml зам")
	_ = fs.Parse(args)

	regPath, err := resolveRegistry(*registry)
	if err != nil {
		fmt.Fprintln(os.Stderr, "алдаа:", err)
		return 3
	}
	p, err := buildPipeline(regPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "алдаа:", err)
		return 2
	}

	mode := "remote"
	if *file != "" {
		mode = "local"
	}

	if *rawDir != "" {
		// Offline ingest: цуглуулсан raw-г нэгтгэнэ.
		raws, err := loadRawDir(*rawDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "алдаа:", err)
			return 2
		}
		r, err := p.Process(raws, orchestrator.Meta{ClusterName: *cluster, ScanMode: mode})
		if err != nil {
			fmt.Fprintln(os.Stderr, "алдаа:", err)
			return 2
		}
		return writeResult(r, *outDir)
	}

	// Live scan: adapter-уудыг ажиллуулна (scanner binary шаардлагатай).
	if *file == "" && *kubeconfig == "" && *context_ == "" {
		fmt.Fprintln(os.Stderr, "scan: -f, --kubeconfig/--context эсвэл --raw-dir шаардлагатай")
		return 3
	}
	target := scanner.Target{
		Mode:       scanner.Mode(mode),
		Path:       *file,
		Kubeconfig: *kubeconfig,
		Context:    *context_,
	}
	r, err := p.Run(context.Background(), target, orchestrator.Meta{ClusterName: *cluster, ScanMode: mode})
	if err != nil {
		fmt.Fprintln(os.Stderr, "алдаа:", err)
		return 2
	}
	if r.Summary.TotalFindings == 0 {
		fmt.Fprintln(os.Stderr, "анхаар: ямар ч scanner ажиллаагүй/finding алга (scanner binary суулгасан эсэхээ шалгана уу). Offline горим: --raw-dir")
	}
	return writeResult(r, *outDir)
}

func writeResult(r interface{}, outDir string) int {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "алдаа:", err)
		return 2
	}
	path := filepath.Join(outDir, "scan-result.json")
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "алдаа:", err)
		return 2
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "алдаа:", err)
		return 2
	}
	fmt.Println("scan-result.json бичигдлээ:", path)
	return 0
}
