// Package cli implements the TATAR-Kuber command dispatch.
// Skeleton нь stdlib (flag)-ээр; production-д spf13/cobra руу шилжинэ.
package cli

import (
	"fmt"
	"os"
)

// Version — build-time-д тохируулагдана (-ldflags).
var Version = "1.0.0-dev"

const usage = `TATAR-Kuber — Kubernetes security posture assessment framework

Ашиглах:
  tatar-kuber <command> [flags]

Commands:
  scan      Cluster/manifest шалгах эсвэл цуглуулсан raw-г нэгтгэж scan-result.json үүсгэнэ
  report    scan-result.json-оос тайлан (json|sarif|html) үүсгэнэ
  verify-lab expected-findings.json-той тулгаж regression шалгана
  update    Scanner binary-уудыг татаж, баталгаажуулж шинэчилнэ
  version   Хувилбар харуулна

Жишээ:
  tatar-kuber scan --raw-dir ./raw --cluster prod -o ./out
  tatar-kuber report --input ./out/scan-result.json -o html --out report.html
`

// Execute — entrypoint.
func Execute() int {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		return 3
	}
	switch os.Args[1] {
	case "scan":
		return cmdScan(os.Args[2:])
	case "report":
		return cmdReport(os.Args[2:])
	case "verify-lab":
		return cmdVerifyLab(os.Args[2:])
	case "update":
		fmt.Println("update: not implemented (download -> verify checksum/cosign -> tools.lock.yaml)")
		return 2
	case "version":
		fmt.Printf("TATAR-Kuber %s\n", Version)
		return 0
	case "-h", "--help", "help":
		fmt.Print(usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "тодорхойгүй команд: %s\n\n", os.Args[1])
		fmt.Print(usage)
		return 3
	}
}
