# TATAR-Kuber

![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)
![Kubernetes](https://img.shields.io/badge/Kubernetes-security-326CE5?logo=kubernetes&logoColor=white)
![Scanners](https://img.shields.io/badge/scanners-Trivy%20%C2%B7%20Kubescape%20%C2%B7%20Checkov%20%C2%B7%20Popeye-2A4D69)
![Output](https://img.shields.io/badge/output-JSON%20%C2%B7%20SARIF%20%C2%B7%20HTML-1F6F54)
![Tests](https://img.shields.io/badge/tests-12%20packages%20green-brightgreen)
![Release](https://img.shields.io/badge/release-v1.0.0--rc1-orange)

**Kubernetes security posture assessment framework — one command, four scanners, one standard report.**

TATAR-Kuber runs **Trivy · Kubescape · Checkov · Popeye**, unifies their output into one
**canonical control model**, de-duplicates it (so "3 scanners found 1 issue" instead of
"3 findings"), scores risk, and produces a single report — **JSON / SARIF / HTML**, in
**English or Mongolian** — that engineers, auditors and CISOs can all read.

**Author:** Enkhbat.O — Security Analyst

```bash
tatar-kuber scan   --kubeconfig ~/.kube/config -o out      # or: --raw-dir ./raw  (offline)
tatar-kuber report --input out/scan-result.json -o html --out report.html
# Mongolian report:  tatar-kuber scan ... --lang mn
```

## Report — one issue, every scanner, both languages

The same scan rendered in **English** and **Mongolian** (`--lang en|mn`). Note
`found_by = checkov · kubescape · trivy` on the privileged container: the unified,
de-duplicated view with confidence, evidence and remediation.

**🇬🇧 English report**

![TATAR-Kuber report — English](docs/img/report-en.jpg)

**🇲🇳 Монгол тайлан**

![TATAR-Kuber тайлан — Монгол](docs/img/report-mn.jpg)

## Design principles

- **Read-Only First** — never modifies the customer environment (`get` / `list` / `watch` only).
- **Scanner Agnostic** — TATAR-Kuber is not a scanner; it is an Orchestrator + Normalizer +
  Risk Engine + Reporting Engine. Scanners are pluggable adapters.

## Scanner stack

| Scanner | Purpose |
|---|---|
| Trivy | Image CVEs, secrets, misconfiguration |
| Kubescape | NSA / MITRE / RBAC / compliance (primary posture engine) |
| Checkov | IaC (YAML / Helm / Terraform) |
| Popeye | Runtime hygiene (dead service, unused, broken reference) |

> `kube-bench` (node/CIS) needs a privileged DaemonSet and is out of MVP scope (Enterprise Agent).

## Features

- Local (Mode A) + Remote (Mode B) scanning, plus **offline ingest** of pre-collected raw output
- **Canonical Control Mapping** — every scanner's rule IDs unified into stable `TATAR-*` controls
- **Deduplication** — merges the same issue across scanners; keeps `found_by` + evidence
- **Confidence engine** — multi-scanner agreement and check determinism (a Trivy-only CVE is still HIGH)
- **Blind-shot engine** — context-aware severity down-grade (never suppresses; stays visible)
- **Risk scoring v1.2** — per-finding + cluster score (0–100, diminishing model)
- **Reports** — JSON · SARIF 2.1.0 (GitHub/GitLab/Azure) · HTML dashboard (bilingual)
- **verify-lab** — regression check against an expected-findings baseline

## Scope & positioning

TATAR-Kuber focuses on **security posture, configuration, IaC, image and RBAC analysis
with unified reporting**. It is **complementary to — not a replacement for** — runtime
detection, admission control and secrets management. Run it *alongside* Falco/Tetragon,
Kyverno/OPA and Vault for full coverage.

**In scope**

| Domain | | Notes |
|---|:--:|---|
| Cluster configuration & posture | ✅ | via Kubescape / Trivy (live Mode B in progress) |
| Kubernetes misconfiguration | ✅ | Trivy · Kubescape · Checkov |
| RBAC security | ✅ | excessive permissions, wildcard, cluster-admin |
| Pod / Workload security | ✅ | privileged, hostPath, capabilities, runAsRoot… |
| Image vulnerabilities | ✅ | CVEs via Trivy |
| IaC security | ✅ | YAML / Helm (Terraform partial, via Checkov) |
| Compliance mapping | ✅ | NSA / CIS / MITRE refs via canonical controls (partial) |
| Reporting & risk scoring | ✅ | dedup, risk score, JSON / SARIF / HTML |
| Runtime hygiene | ⚠️ | Popeye (dead / unused / broken refs) — not threat detection |

**Out of scope (by design) — use alongside**

| Not covered | Use instead |
|---|---|
| Runtime threat detection | Falco · Tetragon |
| Network traffic monitoring (eBPF) | Cilium/Hubble · Falco |
| Container behavioral detection | Falco · Tetragon |
| Admission control (block deploys) | Kyverno · OPA Gatekeeper |
| Secrets management | HashiCorp Vault · External Secrets |

## Quick start (offline, no cluster, no scanner install)

The companion [**tatar-kuber-lab**](https://github.com/ochmunkh/tatar-kuber-lab) repo ships
real scanner output so you can try the full pipeline in ~30 seconds:

```bash
git clone https://github.com/ochmunkh/tatar-kuber-lab
tatar-kuber scan --raw-dir tatar-kuber-lab/raw \
    --registry schema/canonical-controls.yaml -o out
tatar-kuber report    --input out/scan-result.json -o html --out report.html
tatar-kuber verify-lab --input out/scan-result.json \
    --expected tatar-kuber-lab/expected/expected-findings.json
```

## How it works

```
raw scanner output → normalize → canonical mapping → dedup → blind-shot → risk score → report
```

## Build

```bash
go build ./...
go test ./...          # 12 packages, all green
./scripts/build.sh 1.0.0
```

## CLI

```
tatar-kuber scan        --kubeconfig | --context | -f | --raw-dir  [--lang en|mn]
tatar-kuber report      -o json | sarif | html  [--fail-on HIGH]
tatar-kuber verify-lab  --input scan-result.json --expected expected-findings.json
tatar-kuber version
```

## Documentation

Six engineering documents in `docs/` (01 Unified Schema, 02 Canonical Mapping, 03 Scanner
Adapter Interface, 04 Severity & Risk Scoring, 05 CLI Spec, 06 Repository Structure).

## Status

`v1.0.0-rc1` — all tests green. Next: concurrency (parallel adapters), CLI test coverage,
live-cluster runs.

## Contributing

Contributions are welcome! 🎉 The cleanest first PR is a **new scanner adapter** — see
[CONTRIBUTING.md](CONTRIBUTING.md) and [`docs/03-Scanner-Adapter-Interface.md`](docs).
Please keep `go test ./...` green and read the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Open Core. Community CLI — Apache-2.0.

---

## Монгол хэл дээр

**Kubernetes аюулгүй байдлын үнэлгээний framework — нэг команд, дөрвөн scanner, нэг стандарт тайлан.**

TATAR-Kuber нь **Trivy · Kubescape · Checkov · Popeye**-ийг ажиллуулж, тэдгээрийн гаралтыг
нэг **canonical control загвар** руу нэгтгэж, давхардлыг арилгаж ("3 scanner нэг асуудал
олсон" — 3 finding биш), эрсдэлийг үнэлж, нэг тайлан гаргана — **JSON / SARIF / HTML**,
**англи эсвэл монгол** хэлээр. Инженер / auditor / CISO бүгд ойлгоно.

**Зохиогч:** Enkhbat.O — Security Analyst

### Гол зарчим

- **Read-Only First** — customer орчинг хэзээ ч өөрчлөхгүй (зөвхөн `get` / `list` / `watch`).
- **Scanner Agnostic** — өөрөө scanner биш; Orchestrator + Normalizer + Risk Engine + Reporting.

### Scanner-ууд

| Scanner | Зорилго |
|---|---|
| Trivy | Image CVE, secret, misconfiguration |
| Kubescape | NSA / MITRE / RBAC / compliance (үндсэн posture engine) |
| Checkov | IaC (YAML / Helm / Terraform) |
| Popeye | Runtime hygiene (dead service, unused, broken reference) |

> `kube-bench` (node/CIS) нь privileged DaemonSet шаарддаг тул MVP-д багтаагүй (Enterprise Agent).

### Онцлог

- Local (Mode A) + Remote (Mode B) + **offline ingest** (урьдчилан цуглуулсан raw)
- **Canonical Control Mapping** — scanner бүрийн rule ID-г нэг `TATAR-*` control руу
- **Deduplication** — олон scanner-ийн ижил асуудлыг нэгтгэж `found_by`-г хадгална
- **Confidence engine** — олон scanner-ийн санал нийлэлт + determinism (Trivy ганц CVE ч HIGH)
- **Blind-shot engine** — контекстээр severity бууруулна (устгахгүй, ил үлдэнэ)
- **Risk scoring v1.2** — finding бүр + cluster оноо (0–100)
- **Reports** — JSON · SARIF 2.1.0 · HTML dashboard (хоёр хэлт)
- **verify-lab** — expected baseline-тай тулгаж regression шалгах

### Хамрах хүрээ (Scope)

TATAR-Kuber нь **posture / configuration / IaC / image / RBAC + нэгдсэн тайлан**-д
төвлөрдөг. Runtime threat detection (Falco/Tetragon), admission control (Kyverno/OPA),
secrets management (Vault)-ыг **орлохгүй — тэдгээртэй хамт ажилладаг (complementary).**

**Хийдэг**

| Домэйн | | Тайлбар |
|---|:--:|---|
| Cluster configuration & posture | ✅ | Kubescape / Trivy (live Mode B хийгдэж байна) |
| Kubernetes misconfiguration | ✅ | Trivy · Kubescape · Checkov |
| RBAC аюулгүй байдал | ✅ | хэт их эрх, wildcard, cluster-admin |
| Pod / Workload аюулгүй байдал | ✅ | privileged, hostPath, capabilities, runAsRoot… |
| Image эмзэг байдал | ✅ | Trivy CVE |
| IaC аюулгүй байдал | ✅ | YAML / Helm (Terraform хэсэгчлэн, Checkov) |
| Compliance mapping | ✅ | NSA / CIS / MITRE (canonical, хэсэгчлэн) |
| Тайлан & risk scoring | ✅ | dedup, оноо, JSON / SARIF / HTML |
| Runtime hygiene | ⚠️ | Popeye — threat detection БИШ |

**Хийхгүй (зориудаар) — хамт ашигла**

| Хамрахгүй | Оронд нь |
|---|---|
| Runtime threat detection | Falco · Tetragon |
| Network traffic monitoring (eBPF) | Cilium/Hubble · Falco |
| Container behavioral detection | Falco · Tetragon |
| Admission control (deploy блоклох) | Kyverno · OPA Gatekeeper |
| Secrets management | HashiCorp Vault · External Secrets |

### Түргэн эхлэл (offline, cluster/суулгац хэрэггүй)

```bash
git clone https://github.com/ochmunkh/tatar-kuber-lab
tatar-kuber scan --raw-dir tatar-kuber-lab/raw \
    --registry schema/canonical-controls.yaml --lang mn -o out
tatar-kuber report --input out/scan-result.json -o html --out report.html
```

### Хэрхэн ажилладаг вэ

```
raw scanner гаралт → normalize → canonical mapping → dedup → blind-shot → risk score → тайлан
```

### CLI командууд

```
tatar-kuber scan        --kubeconfig | --context | -f | --raw-dir  [--lang en|mn]
tatar-kuber report      -o json | sarif | html  [--fail-on HIGH]
tatar-kuber verify-lab  --input scan-result.json --expected expected-findings.json
tatar-kuber version
```

### Build

```bash
go build ./...
go test ./...          # 12 багц, бүгд ногоон
./scripts/build.sh 1.0.0
```

### Баримт бичиг

`docs/` дотор 6 инженерийн баримт (01 Unified Schema, 02 Canonical Mapping, 03 Scanner
Adapter Interface, 04 Severity & Risk Scoring, 05 CLI Spec, 06 Repository Structure).

### Туршилтын лаборатори

Эмзэг/аюулгүй manifest + regression baseline тусдаа repo-д:
[**tatar-kuber-lab**](https://github.com/ochmunkh/tatar-kuber-lab).

### Төлөв

`v1.0.0-rc1` — бүх тест ногоон. Дараа нь: concurrency, CLI тест, бодит cluster.
