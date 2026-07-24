#!/usr/bin/env bash
# Run the TATAR-Kuber lab end-to-end (real scanners if installed, else offline raw).
set -euo pipefail
cd "$(dirname "$0")/.."
LANG_OPT="${1:-en}"

if command -v checkov >/dev/null 2>&1; then
  echo "[lab] running checkov on lab/broken ..."
  checkov -d lab/broken --framework kubernetes -o json > lab/raw/checkov.json 2>/dev/null || true
fi
if command -v trivy >/dev/null 2>&1; then
  echo "[lab] running trivy config on lab/broken ..."
  trivy config lab/broken --format json > lab/raw/trivy.json 2>/dev/null || true
fi

echo "[lab] scan + report (--lang $LANG_OPT) ..."
go run ./cmd/tatar-kuber scan   --raw-dir lab/raw --cluster tatar-kuber-lab --lang "$LANG_OPT" -o lab/out
go run ./cmd/tatar-kuber report --input lab/out/scan-result.json -o html --out lab/out/report.html
echo "[lab] done -> lab/out/report.html"
