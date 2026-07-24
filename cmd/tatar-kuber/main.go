// Command tatar-kuber — TATAR-Kuber CLI entrypoint.
package main

import (
	"os"

	"github.com/ochmunkh/tatar-kuber/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
