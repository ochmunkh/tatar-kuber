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
	Scenario    string         `json:"scenario"`
	MinFindings int            `json:"min_findings"`         // зөөлөн доод хязгаар (сонголт)
	Total       *int           `json:"total,omitempty"`      // яг нийт тоо (сонголт)
	Counts      map[string]int `json:"counts,omitempty"`     // severity бүрээр яг тоо (сонголт)
	Controls    []string       `json:"controls"`
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
	fmt.Printf("  controls: expected %d, missing %d\n", len(exp.Controls), len(missing))
	fmt.Printf("  findings: actual %d\n", res.Summary.TotalFindings)

	fail := false
	if len(missing) > 0 {
		fail = true
		fmt.Printf("  MISSING controls:\n")
		for _, m := range missing {
			fmt.Printf("    - %s\n", m)
		}
	}
	if exp.Total != nil && res.Summary.TotalFindings != *exp.Total {
		fail = true
		fmt.Printf("  total findings: expected %d, actual %d\n", *exp.Total, res.Summary.TotalFindings)
	}
	if exp.MinFindings > 0 && res.Summary.TotalFindings < exp.MinFindings {
		fail = true
		fmt.Printf("  findings %d < expected min %d\n", res.Summary.TotalFindings, exp.MinFindings)
	}
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		want, ok := exp.Counts[sev]
		if !ok {
			continue
		}
		act := res.Summary.Counts[finding.Severity(sev)]
		mark := "ok"
		if act != want {
			mark, fail = "MISMATCH", true
		}
		fmt.Printf("  %-8s expected %d, actual %d  [%s]\n", sev, want, act, mark)
	}

	if fail {
		fmt.Println("RESULT: FAIL")
		return 1
	}
	fmt.Println("RESULT: PASS")
	return 0
}
