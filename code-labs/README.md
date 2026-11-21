# OrderFlow AI-Powered DevSecOps — Companion Code Labs

Zero-Cloud-Bill (`$0.00`) and Zero-API-Bill (`$0.00`) closed-loop
DevSecOps labs covering `FIRST EPSS v4`, `CISA KEV`, `OpenVEX v0.2.0`,
`Aqua Security Trivy v0.76.2`, `Anchore Syft v1.57.2` & `Grype v0.122.0`,
`Semgrep v1.170+`, `SLSA v1.2` (`in-toto v1` / `DSSE`), `Sigstore Cosign`
`v3.1.4` (`.bundle`), `OWASP CycloneDX v1.7 AI-BOM`, `SPDX v3.0.1`,
`Kyverno v1.19` CEL (`policies.kyverno.io/v1`), `OPA v1.21.1` /
`Conftest v0.71.1`, `Checkov v3.2.532+`, `cfn-guard v3.2.1`,
`Prowler v5.34+` (`CIS v8.1` + MCP), `Falco v0.45.2` (modern CO-RE
eBPF), `Cilium Tetragon v1.8.0` (`TracingPolicy` + `Sigkill`), and
`OCSF` (`1007`, `2002`, `2003`, `2004`):

> **AI-Powered DevSecOps: Autonomous Supply Chain, Runtime eBPF,**
> **and Cloud Security**
> *Practical Engineering Series — Volume 09 (Arc II AI for DevSecOps)*
> **Author & Publisher:** Kien Nguyen
> **Repository:** `https://github.com/kiennt308/ai-devsecops-labs`

Copyright (c) 2026 Kien Nguyen. Companion Python triage scorers, SLSA
v1.2 DSSE/bundle verifiers, CycloneDX 1.7/SPDX 3.0.1 AI-BOM linters,
Kyverno CEL/Conftest gates, Terraform/Prowler MCP servers, Falco/Tetragon
rule harnesses, and OCSF SQLite correlators are licensed under
**Apache-2.0**.

---

## Zero-Cloud-Bill & Zero-API-Bill Toolchain

Every chapter lab executes locally with Docker and Python `3.11+` using
`ch01/01-devsecops-replay-gateway.py` (`LLM_BASE_URL` can point to local
`Ollama` or any OpenAI-compatible gateway) at `$0.00` spend:

- `Python 3.11+`, `cryptography`, `jsonschema`, `pydantic`, `mcp v2.2+`,
  `pytest`, `PyYAML`, `SQLite`
- `aquasec/trivy:latest` (`v0.76.2` container/Dockerfile/Terraform scan)
- `openpolicyagent/conftest:latest` (`v0.71.1` / `OPA v1.21.1 rego.v1`)
- `localstack/localstack:4` + `public.ecr.aws/aws-cli/aws-cli:latest`
- Spec-accurate `Kyverno v1.19` CEL, `Falco v0.45.2` CO-RE eBPF, and
  `Cilium Tetragon v1.8.0` `TracingPolicyNamespaced` test harnesses

---

## Directory Index (48 Clean Files)

```text
code-labs/
├── README.md      Zero-Cloud-Bill & Zero-API-Bill lab guide
├── policies/      OPA rego.v1 DevSecOps & retirement policy gates
├── ch01/          Mock DevSecOps replay gateway & plane router
├── ch02/          EPSS v4 + CISA KEV + Reachability + OpenVEX v0.2.0
├── ch03/          Sandboxed multi-agent remediation & regression gate
├── ch04/          SLSA v1.2, in-toto DSSE & Cosign v3.1.4 bundle
├── ch05/          CycloneDX 1.7 AI-BOM, SPDX 3.0.1 & Kyverno v1.19
├── ch06/          Checkov/Trivy/cfn-guard IaC & Prowler CIS v8.1 MCP
├── ch07/          Falco v0.45.2 modern CO-RE eBPF rules & linter
├── ch08/          Cilium Tetragon v1.8.0 TracingPolicy & Sigkill sim
└── ch09/          OCSF 1007/2002/2003/2004 correlator & Purple-Team
```

---

## Quick Verification Commands

```bash
docker run --rm -v "${PWD}:/work" -w /work \
  openpolicyagent/conftest:latest test \
  -p policies/devsecops_gates.rego \
  ch01/03-orderflow-devsecops-baseline-valid.yaml \
  ch02/04-triage-policy-valid.yaml \
  ch03/03-remediation-pipeline-valid.yaml \
  ch04/04-slsa-cosign-policy-valid.yaml \
  ch05/03-kyverno-v119-cel-policies-valid.yaml \
  ch06/04-iac-posture-remediation-valid.yaml \
  ch07/02-falco-engine-config-valid.yaml \
  ch08/01-tetragon-v18-tracingpolicy-valid.yaml \
  ch09/03-devsecops-prr-ready.json

PYTHONDONTWRITEBYTECODE=1 pytest -v -p no:cacheprovider \
  ch02/06-test-epss-reachability.py \
  ch03/05-test-remediation-pipeline.py \
  ch04/06-test-slsa-dsse-bundle.py \
  ch05/06-test-aibom-admission.py \
  ch06/06-test-iac-posture-mcp.py \
  ch08/04-test-ebpf-falco-tetragon.py \
  ch09/05-test-ocsf-purple-team-prr.py
```
