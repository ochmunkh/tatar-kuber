package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
	htmlrep "github.com/ochmunkh/tatar-kuber/internal/report/html"
	jsonrep "github.com/ochmunkh/tatar-kuber/internal/report/json"
	sarifrep "github.com/ochmunkh/tatar-kuber/internal/report/sarif"
)

func cmdReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	input := fs.String("input", "scan-result.json", "scan-result.json зам")
	format := fs.String("o", "html", "формат: json|sarif|html")
	out := fs.String("out", "", "гаралтын файл (default: stdout, html бол report.html)")
	failOn := fs.String("fail-on", "", "энэ severity-с дээш finding байвал exit 1: CRITICAL|HIGH|MEDIUM|LOW")
	_ = fs.Parse(args)

	data, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintln(os.Stderr, "алдаа:", err)
		return 2
	}
	var res finding.ScanResult
	if err := jsonUnmarshal(data, &res); err != nil {
		fmt.Fprintln(os.Stderr, "scan-result.json parse алдаа:", err)
		return 2
	}

	target := *out
	if target == "" && *format == "html" {
		target = "report.html"
	}

	w := os.Stdout
	if target != "" {
		f, err := os.Create(target)
		if err != nil {
			fmt.Fprintln(os.Stderr, "алдаа:", err)
			return 2
		}
		defer f.Close()
		w = f
	}

	switch *format {
	case "json":
		err = jsonrep.Render(w, res)
	case "sarif":
		err = sarifrep.Render(w, res)
	case "html":
		err = htmlrep.Render(w, res)
	default:
		fmt.Fprintln(os.Stderr, "тодорхойгүй формат:", *format)
		return 3
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "render алдаа:", err)
		return 2
	}
	if target != "" {
		fmt.Println("тайлан бичигдлээ:", target)
	}

	if *failOn != "" && exceedsThreshold(res, finding.Severity(*failOn)) {
		return 1
	}
	return 0
}

var sevOrder = map[finding.Severity]int{
	finding.SeverityInfo: 1, finding.SeverityLow: 2, finding.SeverityMedium: 3,
	finding.SeverityHigh: 4, finding.SeverityCritical: 5,
}

func exceedsThreshold(res finding.ScanResult, th finding.Severity) bool {
	t := sevOrder[th]
	for _, f := range res.Findings {
		if sevOrder[f.Severity] >= t {
			return true
		}
	}
	return false
}
