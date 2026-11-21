package main

import rego.v1

# --------------------------------------------------------------------
# 1. Ch01: Closed-Loop DevSecOps Baseline & Anti-Pattern Retirements
# --------------------------------------------------------------------
deny contains msg if {
	input.kind == "OrderFlowDevSecOpsBaseline"
	input.spec.triage.cvss_only_blocking == true
	msg := "TRIAGE_CVSS_ONLY_RETIRED: combine EPSS v4, KEV & reachability"
}

deny contains msg if {
	input.kind == "OrderFlowDevSecOpsBaseline"
	not input.spec.triage.use_epss_v4
	msg := "TRIAGE_EPSS_V4_REQUIRED: enable FIRST EPSS v4 scoring"
}

deny contains msg if {
	input.kind == "OrderFlowDevSecOpsBaseline"
	input.spec.remediation.direct_automerge == true
	msg := "REMEDIATION_AUTOMERGE_DENIED: require sandbox & HITL PR gate"
}

deny contains msg if {
	input.kind == "OrderFlowDevSecOpsBaseline"
	input.spec.supply_chain.slsa_version != "1.2"
	msg := "SLSA_V02_RETIRED: require SLSA v1.2 Build & Source Tracks"
}

deny contains msg if {
	input.kind == "OrderFlowDevSecOpsBaseline"
	input.spec.supply_chain.slsa_level < 2
	msg := "SLSA_UNSIGNED_L1_DENIED: require SLSA v1.2 L2+ provenance"
}

deny contains msg if {
	input.kind == "OrderFlowDevSecOpsBaseline"
	not input.spec.supply_chain.cosign_bundle_default
	msg := "COSIGN_V2_OCI_RETIRED: require Cosign v3.1+ unified .bundle"
}

deny contains msg if {
	input.kind == "OrderFlowDevSecOpsBaseline"
	not input.spec.supply_chain.hardened_minimal_base
	msg := "BASE_IMAGE_UNHARDENED: require minimal/distroless base"
}

deny contains msg if {
	input.kind == "OrderFlowDevSecOpsBaseline"
	not input.spec.supply_chain.aibom_enabled
	msg := "AIBOM_BLIND_SPOT: enable CycloneDX 1.7 / SPDX 3.0.1 AI-BOM"
}

deny contains msg if {
	input.kind == "OrderFlowDevSecOpsBaseline"
	input.spec.admission.legacy_cluster_policy_enabled == true
	msg := "KYVERNO_LEGACY_CRD_RETIRED: migrate to policies.kyverno.io"
}

deny contains msg if {
	input.kind == "OrderFlowDevSecOpsBaseline"
	input.spec.runtime_ebpf.falco_driver != "modern_ebpf"
	msg := "FALCO_LEGACY_PROBE_REMOVED: use modern CO-RE eBPF libbpf"
}

deny contains msg if {
	input.kind == "OrderFlowDevSecOpsBaseline"
	startswith(input.spec.runtime_ebpf.tetragon_grpc_socket, "tcp://")
	msg := "TETRAGON_TCP_GRPC_DENIED: require Unix-domain socket default"
}

deny contains msg if {
	input.kind == "OrderFlowDevSecOpsBaseline"
	count(input.spec.secops.enabled_classes) < 4
	msg := "OCSF_SILO_DENIED: require OCSF 1007, 2002, 2003, and 2004"
}

# --------------------------------------------------------------------
# 2. Ch02: EPSS v4 + CISA KEV + Reachability + OpenVEX Triage Policy
# --------------------------------------------------------------------
deny contains msg if {
	input.kind == "VulnerabilityTriagePolicy"
	input.spec.cvss_only_blocking == true
	msg := "TRIAGE_CVSS_ONLY_RETIRED: enable EPSS v4 and reachability"
}

deny contains msg if {
	input.kind == "VulnerabilityTriagePolicy"
	not input.spec.cisa_kev_mandatory_floor
	msg := "KEV_FLOOR_MISSING: CISA KEV findings must trigger triage"
}

deny contains msg if {
	input.kind == "VulnerabilityTriagePolicy"
	input.spec.epss_version != "v4"
	msg := "EPSS_VERSION_STALE: require FIRST EPSS v4 probability score"
}

deny contains msg if {
	input.kind == "VulnerabilityTriagePolicy"
	input.spec.vex_spec != "openvex-0.2.0"
	msg := "OPENVEX_SPEC_REQUIRED: require signed OpenVEX v0.2.0"
}

# --------------------------------------------------------------------
# 3. Ch03: Multi-Agent Vulnerability Remediation & Sandbox PR Gate
# --------------------------------------------------------------------
deny contains msg if {
	input.kind == "RemediationPipelineSpec"
	not input.spec.sandbox_regression_required
	msg := "SANDBOX_PROOF_MISSING: patch PR must run regression suite"
}

deny contains msg if {
	input.kind == "RemediationPipelineSpec"
	input.spec.allow_major_version_jump == true
	msg := "BREAKING_MAJOR_JUMP_DENIED: constrain to minimal security diff"
}

deny contains msg if {
	input.kind == "RemediationPipelineSpec"
	input.spec.direct_merge_without_hitl == true
	msg := "HITL_GITOPS_BYPASS: block unreviewed agent self-merge"
}

# --------------------------------------------------------------------
# 4. Ch04: SLSA v1.2 + in-toto DSSE + Cosign v3.1.4 + Base Hardening
# --------------------------------------------------------------------
deny contains msg if {
	input.kind == "SupplyChainProvenancePolicy"
	input.spec.slsa.spec_version != "1.2"
	msg := "SLSA_VERSION_INVALID: require SLSA v1.2 specification"
}

deny contains msg if {
	input.kind == "SupplyChainProvenancePolicy"
	input.spec.slsa.build_level < 2
	msg := "SLSA_LEVEL_TOO_LOW: Build Track L2+ with DSSE required"
}

deny contains msg if {
	input.kind == "SupplyChainProvenancePolicy"
	not input.spec.cosign.use_bundle_format
	msg := "COSIGN_BUNDLE_REQUIRED: Cosign v3.1.4 uses unified .bundle"
}

deny contains msg if {
	input.kind == "SupplyChainProvenancePolicy"
	not input.spec.base_image.minimal_hardened
	msg := "HARDENED_BASE_REQUIRED: disallow bloated shell/pkg base"
}

# --------------------------------------------------------------------
# 5. Ch05: Kyverno v1.19 Native CEL Admission vs. Deprecated ClusterPolicy
# --------------------------------------------------------------------
deny contains msg if {
	input.kind in {"ClusterPolicy", "Policy"}
	input.apiVersion == "kyverno.io/v1"
	msg := "KYVERNO_CLUSTERPOLICY_DEPRECATED: use policies.kyverno.io/v1"
}

deny contains msg if {
	input.kind in {"ValidatingPolicy", "ImageValidatingPolicy"}
	input.apiVersion != "policies.kyverno.io/v1"
	msg := "KYVERNO_CEL_GROUP_INVALID: require policies.kyverno.io/v1"
}

deny contains msg if {
	input.kind == "ImageValidatingPolicy"
	not input.spec.verifyImages
	msg := "KYVERNO_IMAGE_ATTEST_MISSING: verify Cosign v3 & AI-BOM"
}

# --------------------------------------------------------------------
# 6. Ch06: Autonomous IaC & Cloud Posture Remediation (Prowler / OIDC)
# --------------------------------------------------------------------
deny contains msg if {
	input.kind == "CloudPostureRemediationPolicy"
	input.spec.patch_live_aws_clickops == true
	msg := "CLICKOPS_DRIFT_DENIED: remediate back in root IaC module"
}

deny contains msg if {
	input.kind == "CloudPostureRemediationPolicy"
	input.spec.oidc_trust_scope == "*"
	msg := "IAM_OIDC_WILDCARD_CKV393: pin GitHub repo & branch sub"
}

deny contains msg if {
	input.kind == "CloudPostureRemediationPolicy"
	input.spec.key_rotation_days > 90
	msg := "KEY_ROTATION_CKV304: enforce <= 90-day rotation cadence"
}

# --------------------------------------------------------------------
# 7. Ch07: Falco v0.45.2 Modern CO-RE eBPF Capture Policy
# --------------------------------------------------------------------
deny contains msg if {
	input.kind == "FalcoRuntimeConfig"
	input.spec.engine.kind != "modern_ebpf"
	msg := "FALCO_ENGINE_LEGACY: v0.44+ removes legacy probe and gVisor"
}

deny contains msg if {
	input.kind == "FalcoRuntimeConfig"
	input.spec.legacy_grpc_server_enabled == true
	msg := "FALCO_LEGACY_GRPC_REMOVED: removed in Falco v0.44+"
}

# --------------------------------------------------------------------
# 8. Ch08: Cilium Tetragon v1.8.0 TracingPolicyNamespaced Guards
# --------------------------------------------------------------------
deny contains msg if {
	input.kind in {"TracingPolicy", "TracingPolicyNamespaced"}
	not startswith(input.apiVersion, "cilium.io/")
	msg := "TETRAGON_APIVERSION_INVALID: require cilium.io/v1alpha1"
}

deny contains msg if {
	input.kind == "TracingPolicyNamespaced"
	contains(json.marshal(input.spec), "Sigkill")
	not input.metadata.namespace
	msg := "TETRAGON_UNSCOPED_SIGKILL: bind Sigkill inside namespace"
}

deny contains msg if {
	input.kind == "TracingPolicyNamespaced"
	input.metadata.grpc_endpoint
	startswith(input.metadata.grpc_endpoint, "tcp://")
	msg := "TETRAGON_UNSAFE_GRPC: require Unix-domain socket endpoint"
}

# --------------------------------------------------------------------
# 9. Ch09: 20-Point AI-Powered DevSecOps PRR Gate
# --------------------------------------------------------------------
deny contains msg if {
	input.kind == "DevSecOpsPRRAssessment"
	input.spec.score_passed < 20
	msg := sprintf(
		"DEVSECOPS_PRR_INCOMPLETE: %d/20 passed (20/20 required)",
		[input.spec.score_passed],
	)
}

deny contains msg if {
	input.kind == "DevSecOpsPRRAssessment"
	count(input.spec.ocsf_classes) < 4
	msg := "PRR_OCSF_MISSING: require 1007, 2002, 2003, and 2004"
}

deny contains msg if {
	input.kind == "DevSecOpsPRRAssessment"
	not input.spec.purple_team_validated
	msg := "PRR_PURPLE_TEAM_MISSING: validate runtime eBPF & OCSF loop"
}
