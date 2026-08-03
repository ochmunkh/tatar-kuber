# Contributing to TATAR-Kuber

Thanks for your interest — contributions are very welcome! 🎉
TATAR-Kuber is early-stage and there is lots of high-impact work available.

Монголоор: доод хэсгийг үзнэ үү.

## Ways to contribute

- **Add a new scanner adapter** (e.g. kubeaudit, kube-bench, Kubescape frameworks) — the
  cleanest entry point, see below.
- **Improve the canonical control registry** (`schema/canonical-controls.yaml`) — mappings,
  new controls, better compliance references.
- **Bug fixes / tests** — especially CLI test coverage and concurrency (parallel adapters).
- **Docs & translations** — English/Mongolian, or a new language for the reports.

## Dev setup

```bash
git clone https://github.com/ochmunkh/Tatar-Kuber && cd Tatar-Kuber
go build ./...
go test ./...          # 12 packages, must stay green
python3 scripts/validate_registry.py   # canonical registry sanity
```

Requires **Go 1.22+**. The Go module path is lowercase (`github.com/ochmunkh/tatar-kuber`) —
please keep it that way.

## Workflow

1. **Fork** the repo and create a branch: `feat/<short-name>` or `fix/<short-name>`.
2. Make focused changes. Keep PRs small and single-purpose.
3. Ensure `go vet ./...`, `gofmt`, and `go test ./...` all pass.
4. Open a **Pull Request** describing *what* and *why*. Link any related issue.

A maintainer will review. Please be patient and kind — see the Code of Conduct.

## Adding a scanner adapter (step by step)

This is the recommended first contribution. See `docs/03-Scanner-Adapter-Interface.md`.

1. Create `internal/scanner/<name>/<name>.go` implementing `scanner.ScannerAdapter`
   (`Name`, `Available`, `Version`, `Supports`, `Scan`, `Normalize`).
2. In `Normalize`, convert the scanner's raw output into `[]finding.Finding` via the shared
   `normalizer.Build(...)` helper — it handles canonical mapping, severity, confidence and ID.
3. Add the scanner's rule-ID → canonical mappings in `schema/canonical-controls.yaml`
   (never reuse or renumber a `TATAR-*` id; only `status: deprecated`).
4. Add a fixture under `testdata/<name>/` and a `Normalize` test asserting the expected
   canonical controls.
5. Register the adapter in `internal/cli/pipeline.go` and `internal/orchestrator`.
6. Run `go test ./...` and `python3 scripts/validate_registry.py`.

## Canonical controls & mappings

- `TATAR-*` control IDs are an **immutable contract** (SARIF, history, diff depend on them).
- Scanner rule IDs are **provisional** — validate them against real scanner output. The
  [tatar-kuber-lab](https://github.com/ochmunkh/Tatar-Kuber-Lab) repo is the regression harness:

```bash
tatar-kuber verify-lab --input scan-result.json --expected expected-findings.json
```

## Code style

- `gofmt` + `go vet` clean; small, well-named functions; comments where non-obvious.
- Deterministic output (stable IDs, sorted results) — don't break `result_hash` reproducibility.

## Reporting bugs / requesting features

Open an issue using the templates in `.github/ISSUE_TEMPLATE/`.

---

## Монгол хэл дээр

Хувь нэмэр оруулах хүсэлд баярлалаа! 🎉 Төсөл эрт шатанд байгаа тул хийх ажил их байна.

**Хувь нэмэр оруулах гол чиглэлүүд:**
- Шинэ **scanner adapter** нэмэх (kubeaudit г.м) — хамгийн цэвэр эхлэл.
- **canonical-controls.yaml**-ийг сайжруулах (mapping, шинэ control, compliance).
- **Bug fix / тест** — ялангуяа CLI тест, concurrency (adapter-уудыг зэрэгцүүлэх).
- **Баримт / орчуулга** — англи/монгол, эсвэл тайлангийн шинэ хэл.

**Эхлэх:**
```bash
git clone https://github.com/ochmunkh/Tatar-Kuber && cd Tatar-Kuber
go build ./...   &&   go test ./...
```
Go 1.22+ шаардлагатай. Module path жижиг үсэгтэй (`github.com/ochmunkh/tatar-kuber`) хэвээр.

**Ажлын урсгал:** fork → `feat/...` салбар → фокустай өөрчлөлт → `go test ./...` ногоон →
Pull Request (юу, яагаад хийснийг тайлбарла). Maintainer хянана.

Асуудал/санал: `.github/ISSUE_TEMPLATE/` доторх template ашиглана. Code of Conduct-ыг дагана уу.
