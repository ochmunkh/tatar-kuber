#!/usr/bin/env bash
set -euo pipefail
# TATAR-Kuber cross-platform build
VERSION="${1:-1.0.0-dev}"
LDFLAGS="-s -w -X github.com/ochmunkh/tatar-kuber/internal/cli.Version=${VERSION}"
mkdir -p dist
GOOS=windows GOARCH=amd64 go build -ldflags "$LDFLAGS" -o dist/tatar-kuber.exe   ./cmd/tatar-kuber
GOOS=linux   GOARCH=amd64 go build -ldflags "$LDFLAGS" -o dist/tatar-kuber-linux ./cmd/tatar-kuber
GOOS=darwin  GOARCH=arm64 go build -ldflags "$LDFLAGS" -o dist/tatar-kuber-macos ./cmd/tatar-kuber
echo "built dist/ (version ${VERSION})"
