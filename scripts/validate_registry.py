#!/usr/bin/env python3
"""TATAR canonical registry validator (CI-д ажиллана).
Go compile хийхгүйгээр canonical-controls.yaml-ийн бүрэн бүтэн байдлыг шалгана."""
import sys, re, yaml

REG = "schema/canonical-controls.yaml"
ALLOWED_SCANNERS = {"trivy", "kubescape", "checkov", "popeye"}
CATS = {"CON", "RBAC", "NET", "IMG", "SEC", "OPS"}
SEV = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
TYPES = {"misconfiguration", "vulnerability", "secret", "rbac", "network", "hygiene"}
STATUS = {"active", "deprecated"}
IDRE = re.compile(r"^TATAR-(CON|RBAC|NET|IMG|SEC|OPS)-\d{3}$")

# Утга зүйн хувьд ЗӨВШӨӨРӨГДСӨН олон-candidate rule-ууд (ResolverContext шийднэ).
EXPECTED_MULTI = {
    ("trivy", "CVE-*"):     {"TATAR-IMG-001", "TATAR-IMG-002"},
    ("kubescape", "C-0078"):{"TATAR-IMG-001", "TATAR-IMG-002"},
    ("kubescape", "C-0018"):{"TATAR-OPS-001", "TATAR-OPS-002"},
    ("trivy", "secret"):    {"TATAR-SEC-001", "TATAR-SEC-002", "TATAR-SEC-004"},
    ("kubescape", "C-0260"):{"TATAR-NET-001", "TATAR-NET-002"},
}

def main():
    d = yaml.safe_load(open(REG))
    errs, warns = [], []
    ids = set()
    idx = {}
    for c in d["controls"]:
        cid = c["id"]
        if cid in ids: errs.append(f"давхардсан ID: {cid}")
        ids.add(cid)
        if not IDRE.match(cid): errs.append(f"буруу ID формат: {cid}")
        if cid.split("-")[1] not in CATS: errs.append(f"буруу category prefix: {cid}")
        if c["default_severity"] not in SEV: errs.append(f"{cid}: буруу severity {c['default_severity']}")
        if c["type"] not in TYPES: errs.append(f"{cid}: буруу type {c['type']}")
        if c["status"] not in STATUS: errs.append(f"{cid}: буруу status {c['status']}")
        cov = 0
        for sc, rules in c["mappings"].items():
            if sc not in ALLOWED_SCANNERS: errs.append(f"{cid}: зөвшөөрөгдөөгүй scanner {sc}")
            cov += len(rules)
            for r in rules:
                idx.setdefault((sc, r), []).append(cid)
        if cov == 0 and c["status"] == "active":
            warns.append(f"{cid}: идэвхтэй ч ямар ч scanner rule-д зурагдаагүй (coverage=0)")

    # reverse-index collisions
    for k, v in idx.items():
        if len(v) > 1:
            if k in EXPECTED_MULTI:
                if set(v) != EXPECTED_MULTI[k]:
                    errs.append(f"expected-multi {k} -> {v}, хүлээсэн {EXPECTED_MULTI[k]}")
            else:
                errs.append(f"САНАМСАРГҮЙ collision {k} -> {v} (нэг rule нэгээс олон canonical руу)")

    print(f"controls: {len(d['controls'])}, unique IDs: {len(ids)}")
    print(f"expected multi-candidate rules: {len(EXPECTED_MULTI)}")
    if warns:
        print("\nWARN:"); [print("  -", w) for w in warns]
    if errs:
        print("\nERROR:"); [print("  -", e) for e in errs]
        print("\nVALIDATION FAILED"); return 1
    print("\nVALIDATION PASSED ✓")
    return 0

sys.exit(main())
