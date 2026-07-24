# TATAR-Kuber

**Kubernetes security posture assessment framework.**
Нэг команд, олон scanner, нэг стандарт тайлан.

> Агент суулгалгүйгээр (Mode B) эсвэл локал manifest дээр (Mode A) Kubernetes
> орчны аюулгүй байдлыг шалгаж, олон scanner-ийн үр дүнг нэг стандарт
> (Unified Finding Schema) руу нэгтгэн, инженер / auditor / CISO ойлгох
> нэг тайлан гаргана.

```bash
tatar-kuber scan --kubeconfig ~/.kube/config
tatar-kuber report -o html --open
```

## Design Principles

- **Read-Only First** — customer орчинг хэзээ ч өөрчлөхгүй (get/list/watch).
- **Scanner Agnostic** — TATAR-Kuber өөрөө scanner биш; Orchestrator +
  Normalizer + Risk Engine + Reporting Engine.

## Scanner Stack (v1.0)

| Scanner | Зорилго |
|---|---|
| Trivy | Image CVE, secret, misconfiguration |
| Kubescape | NSA / MITRE / RBAC / compliance (primary posture engine) |
| Checkov | IaC (YAML / Helm / Terraform) |
| Popeye | Runtime hygiene (dead service, unused, broken ref) |

> `kube-bench` (node/CIS) нь privileged DaemonSet шаарддаг тул MVP-д
> багтаагүй — Enterprise Agent (Mode C, v2).

## Features (v1.0)

- Local (Mode A) + Remote (Mode B) scan
- **Canonical Control Mapping** — scanner rule ID-г нэг хэл рүү
- **Deduplication** — давхардлыг арилгах (canonical + resource + namespace)
- **Severity normalization** + **Risk Scoring v1.2** (Level 1 finding + Level 2 cluster 0–100)
- **Blind Shot** — контекстээр downgrade (устгахгүй, ил үлдэнэ)
- Output: **JSON** · **SARIF** (GitHub/GitLab/Azure) · **HTML dashboard**

## Гол хөрөнгө (product asset)

`schema/canonical-controls.yaml` — TATAR Canonical Control Registry.
Scanner солигдоно; canonical registry + risk model + normalization engine
бол бүтээгдэхүүний оюун ухаан.

## Project Layout

```
cmd/tatar-kuber/       CLI entrypoint
internal/
  cli/                 команд dispatch
  scanner/             ScannerAdapter + trivy|kubescape|checkov|popeye
  canonical/           canonical-controls.yaml loader + resolve
  finding/             Unified Finding Schema
  risk/                Risk Scoring Model v1.2 (+ test)
  report/              json | sarif | html
  kube/                read-only client-go wrapper (Mode B)
schema/                canonical-controls.yaml, tatar-schema-v1.json
deploy/                least-privilege-clusterrole.yaml
docs/                  01–06 engineering documents
```

## Build

```bash
go build ./...
go test ./...
./scripts/build.sh 1.0.0     # cross-platform dist/
```

## Mode B RBAC

Remote scan-д зориулсан least-privilege ClusterRole:
`deploy/least-privilege-clusterrole.yaml` (зөвхөн get/list/watch).

## Status

`v1.0` — architecture LOCKED, skeleton scaffolding. Adapter/engine
хэрэгжүүлэлт хийгдэж байна.

## License

Open Core. Community CLI — Apache-2.0.
