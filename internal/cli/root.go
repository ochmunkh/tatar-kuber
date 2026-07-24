// Package cli implements the TATAR-Kuber command dispatch.
// Тэмдэглэл: skeleton нь stdlib (flag)-ээр хийгдсэн — гадаад
// хамааралгүй build хийхийн тулд. Production-д spf13/cobra руу шилжинэ.
package cli

import (
	"flag"
	"fmt"
	"os"
)

// Version — build-time-д тохируулагдана (-ldflags).
var Version = "1.0.0-dev"

const usage = `TATAR-Kuber — Kubernetes security posture assessment framework

Ашиглах:
  tatar-kuber <command> [flags]

Commands:
  scan      Cluster эсвэл manifest шалгаж scan-result.json цуглуулна
  report    Цуглуулсан үр дүнгээс тайлан (json|sarif|html) үүсгэнэ
  update    Scanner binary-уудыг татаж, баталгаажуулж шинэчилнэ
  version   Хувилбар харуулна
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
	case "update":
		return cmdUpdate(os.Args[2:])
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

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	file := fs.String("f", "", "local manifest/Helm зам (Mode A)")
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig файл (Mode B)")
	context := fs.String("context", "", "kubeconfig context (Mode B)")
	_ = fs.Parse(args)

	if *file == "" && *kubeconfig == "" && *context == "" {
		fmt.Fprintln(os.Stderr, "scan: -f эсвэл --kubeconfig/--context шаардлагатай")
		return 3
	}
	// TODO: orchestrator.Run(target) → normalize → dedup → blindshot → score → scan-result.json
	fmt.Println("scan: not implemented (skeleton)")
	return 2
}

func cmdReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	out := fs.String("o", "html", "гаралтын формат: json|sarif|html")
	_ = fs.Parse(args)
	// TODO: load scan-result.json → report.Render(*out)
	fmt.Printf("report (-o %s): not implemented (skeleton)\n", *out)
	return 2
}

func cmdUpdate(args []string) int {
	// TODO: download → verify checksum → verify cosign → install → tools.lock.yaml
	fmt.Println("update: not implemented (skeleton)")
	return 2
}
