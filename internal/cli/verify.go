package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// expectedSpec — expected-findings.json бүтэц (lab regression).
type expectedSpec struct {
	Scenario    string   `json:"scenario"`
	MinFindings int      `json:"min_findings"`
	Controls    []string `json:"controls"`
}

// cmdVerifyLab — scan-result.json-ыг expected-findings.json-той тулгана.
// PASS -> exit 0; дутуу control эсвэл finding цөөн -> exit 1.
func cmdVerifyLab(args []string) int {
	fs := flag.NewFlagSet("verify-lab", flag.ExitOnError)
	input := fs.String("input", "scan-result.json", "scan-result.json зам")
	expected := fs.String("expected", "expected-findings.json", "expected-findings.json зам")
	_ = fs.Parse(args)

	rb, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintln(os.Stderr, "алдаа:", err)
		return 2
	}
	var res finding.ScanResult
	if err := json.Unmarshal(rb, &res); err != nil {
		fmt.Fprintln(os.Stderr, "scan-result.json parse:", err)
		return 2
	}
	eb, err := os.ReadFile(*expected)
	if err != nil {
		fmt.Fprintln(os.Stderr, "алдаа:", err)
		return 2
	}
	var exp expectedSpec
	if err := json.Unmarshal(eb, &exp); err != nil {
		fmt.Fprintln(os.Stderr, "expected-findings.json parse:", err)
		return 2
	}

	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.CanonicalControl] = true
	}
	var missing []string
	for _, c := range exp.Controls {
		if !got[c] {
			missing = append(missing, c)
		}
	}

	fmt.Printf("verify-lab: %s\n", exp.Scenario)
	fmt.Printf("  expected controls: %d, min findings: %d\n", len(exp.Controls), exp.MinFindings)
	fmt.Printf("  actual findings:   %d\n", res.Summary.TotalFindings)

	fail := false
	if len(missing) > 0 {
		fail = true
		fmt.Printf("  MISSING controls (%d):\n", len(missing))
		for _, m := range missing {
			fmt.Printf("    - %s\n", m)
		}
	}
	if res.Summary.TotalFindings < exp.MinFindings {
		fail = true
		fmt.Printf("  findings %d < expected min %d\n", res.Summary.TotalFindings, exp.MinFindings)
	}

	if fail {
		fmt.Println("RESULT: FAIL")
		return 1
	}
	fmt.Println("RESULT: PASS")
	return 0
}
