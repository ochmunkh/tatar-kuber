// Package scanner defines the ScannerAdapter contract (Doc #3).
// TATAR-Kuber өөрөө scanner биш — orchestrator. Scanner бүр энэ
// interface-ийг хэрэгжүүлдэг тул цөм нь тодорхой scanner-ийг мэдэхгүй.
package scanner

import (
	"context"
	"time"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// Mode — scan горим.
type Mode string

const (
	ModeLocal  Mode = "local"
	ModeRemote Mode = "remote"
)

// Target — scan оролт.
type Target struct {
	Mode       Mode
	Path       string        // -f ./k8s/ (local)
	Kubeconfig string        // remote
	Context    string        // --context production
	Namespaces []string      // хязгаарлах (сонголт)
	Timeout    time.Duration
}

// RawResult — scanner-ийн боловсруулаагүй гаралт (нотолгоо).
type RawResult struct {
	Scanner  string
	Version  string
	Format   string // json | sarif
	Data     []byte
	ExitCode int
	Duration time.Duration
}

// ScannerAdapter — scanner бүрийн контракт.
type ScannerAdapter interface {
	Name() string
	Available() (bool, error)
	Version(ctx context.Context) (string, error)
	Supports(mode Mode) bool
	Scan(ctx context.Context, t Target) (RawResult, error)
	Normalize(raw RawResult) ([]finding.Finding, error)
}
