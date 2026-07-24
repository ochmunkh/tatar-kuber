# TATAR-Kuber Lab

Reproducible vulnerable + secure Kubernetes manifests to **try TATAR-Kuber in ~30 seconds**.

`broken/` intentionally violates security controls; `good/` is hardened. Scan them and
TATAR-Kuber produces exactly the expected canonical findings.

## 30-second demo (no scanner install needed)

`lab/raw/` ships **real Checkov output** for `broken/`, so you can try the full
normalize → dedup → score → report pipeline offline:

```bash
go run ./cmd/tatar-kuber scan --raw-dir lab/raw --cluster tatar-kuber-lab -o lab/out
go run ./cmd/tatar-kuber report --input lab/out/scan-result.json -o html --out lab/out/report.html
# Монголоор:  --lang mn
```

## Full run (real scanners, local — no cluster)

Checkov/Trivy scan **manifest files** without a cluster:

```bash
checkov -d lab/broken --framework kubernetes -o json > lab/raw/checkov.json
trivy   config lab/broken --format json          > lab/raw/trivy.json
go run ./cmd/tatar-kuber scan --raw-dir lab/raw -o lab/out
```

## Full run (live cluster — Popeye + runtime)

```bash
kind create cluster
kubectl create namespace production
kubectl apply -f lab/broken/
# collect scanner output, then:
go run ./cmd/tatar-kuber scan --raw-dir lab/raw --cluster prod
```

## Broken manifests → expected canonical controls

| File | Expected TATAR controls | Detected by |
|---|---|---|
| `privileged.yaml` | TATAR-CON-001 | Trivy, Kubescape, Checkov |
| `root-user.yaml` | TATAR-CON-002, TATAR-CON-003 | Checkov, Trivy, Kubescape |
| `latest-tag.yaml` | TATAR-IMG-003, TATAR-CON-010, TATAR-OPS-001/002/005 | Checkov, Trivy |
| `wildcard-rbac.yaml` | TATAR-RBAC-002 | Checkov, Kubescape |
| `secret-env.yaml` | TATAR-SEC-001 | **Trivy secret** (Checkov CKV_K8S_35 нь plaintext дээр асдаггүй) |
| `host-namespaces.yaml` | TATAR-CON-005, TATAR-CON-006 | Checkov, Trivy, Kubescape |
| (missing NetworkPolicy) | TATAR-NET-001/002 | **Kubescape / live cluster** |

`good/` (secure-deployment, secure-rbac, secure-networkpolicy) нь дээрх finding-үүдийг
гаргах ЁСГҮЙ — hardening зөв хийгдсэн эсэхийг батлах baseline.

## Validated (real Checkov 3.3.8)

`checkov -d lab/broken`-ийг ажиллуулж дараах check_id-ууд яг таарч гарсныг баталсан:
`CKV_K8S_16/17/19/20/22/23/31/43/49/8/9/10/11/15/38`. TATAR-Kuber эдгээрийг
**14 canonical control** болгож нэгтгэв (score 28/100, Critical band).

> Тэмдэглэл: scanner rule ID-ууд PROVISIONAL. Энэ лаб нь тэдгээрийг бодит scanner
> хувилбартай тулгах regression орчин болно.
