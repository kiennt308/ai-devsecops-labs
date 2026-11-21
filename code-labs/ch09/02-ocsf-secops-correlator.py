"""Unified OCSF (1007/2002/2003/2004) SQLite Correlator & Purple-Team.

Copyright (c) 2026 Kien Nguyen
Repository: https://github.com/kiennt308/ai-devsecops-labs
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import Any

CH09_DIR = Path(__file__).resolve().parent
EVENTS_PATH = CH09_DIR / "01-ocsf-events-fixture.json"

CREATE_SQL = """
CREATE TABLE ocsf_1007 (
    event_uid TEXT PRIMARY KEY,
    incident_id TEXT,
    container_id TEXT,
    image_digest TEXT,
    role_arn TEXT,
    service TEXT,
    namespace TEXT,
    cmd_line TEXT,
    tetragon_sigkill INTEGER,
    post_syscall_bytes INTEGER
);
CREATE TABLE ocsf_2002 (
    event_uid TEXT PRIMARY KEY,
    incident_id TEXT,
    container_id TEXT,
    image_digest TEXT,
    role_arn TEXT,
    cve_id TEXT,
    epss_score REAL,
    cisa_kev INTEGER,
    reachable INTEGER
);
CREATE TABLE ocsf_2003 (
    event_uid TEXT PRIMARY KEY,
    incident_id TEXT,
    container_id TEXT,
    image_digest TEXT,
    role_arn TEXT,
    control_id TEXT,
    standard_name TEXT,
    status TEXT
);
CREATE TABLE ocsf_2004 (
    event_uid TEXT PRIMARY KEY,
    incident_id TEXT,
    container_id TEXT,
    image_digest TEXT,
    role_arn TEXT,
    finding_uid TEXT,
    title TEXT,
    source_handoff TEXT
);
"""

JOIN_SQL = """
SELECT
    p.incident_id,
    p.container_id,
    p.image_digest,
    p.role_arn,
    p.service,
    p.namespace,
    p.cmd_line,
    p.tetragon_sigkill,
    p.post_syscall_bytes,
    v.cve_id,
    v.epss_score,
    v.cisa_kev,
    v.reachable,
    c.control_id,
    c.standard_name,
    d.finding_uid,
    d.source_handoff
FROM ocsf_1007 p
INNER JOIN ocsf_2002 v
    ON p.container_id = v.container_id
   AND p.image_digest = v.image_digest
   AND p.role_arn = v.role_arn
INNER JOIN ocsf_2003 c
    ON p.container_id = c.container_id
   AND p.image_digest = c.image_digest
   AND p.role_arn = c.role_arn
INNER JOIN ocsf_2004 d
    ON p.container_id = d.container_id
   AND p.image_digest = d.image_digest
   AND p.role_arn = d.role_arn
"""


def load_and_correlate_ocsf(
    fixture_path: Path = EVENTS_PATH,
) -> dict[str, Any]:
    """Load OCSF 1007/2002/2003/2004 into SQLite :memory: and join."""
    data = json.loads(fixture_path.read_text(encoding="utf-8"))
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(CREATE_SQL)
        for ev in data["events"]:
            uid = ev["event_uid"]
            inc = ev["incident_id"]
            ctr = ev["container_id"]
            dig = ev["image_digest"]
            arn = ev["role_arn"]
            cls = ev["class_uid"]
            if cls == 1007:
                prev = ev["prevention"]
                conn.execute(
                    "INSERT INTO ocsf_1007 VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        uid,
                        inc,
                        ctr,
                        dig,
                        arn,
                        ev["service"],
                        ev["namespace"],
                        ev["process"]["cmd_line"],
                        int(bool(prev["tetragon_sigkill"])),
                        int(prev["post_syscall_bytes"]),
                    ),
                )
            elif cls == 2002:
                vuln = ev["vulnerabilities"][0]
                conn.execute(
                    "INSERT INTO ocsf_2002 VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        uid,
                        inc,
                        ctr,
                        dig,
                        arn,
                        vuln["cve_id"],
                        float(vuln["epss_score"]),
                        int(bool(vuln["cisa_kev"])),
                        int(bool(vuln["reachable"])),
                    ),
                )
            elif cls == 2003:
                comp = ev["compliance"]
                conn.execute(
                    "INSERT INTO ocsf_2003 VALUES (?,?,?,?,?,?,?,?)",
                    (
                        uid,
                        inc,
                        ctr,
                        dig,
                        arn,
                        comp["control"],
                        comp["standards"][0],
                        comp["status"],
                    ),
                )
            elif cls == 2004:
                info = ev["finding_info"]
                conn.execute(
                    "INSERT INTO ocsf_2004 VALUES (?,?,?,?,?,?,?,?)",
                    (
                        uid,
                        inc,
                        ctr,
                        dig,
                        arn,
                        info["uid"],
                        info["title"],
                        info["source_handoff"],
                    ),
                )

        rows = [dict(r) for r in conn.execute(JOIN_SQL).fetchall()]
    finally:
        conn.close()

    assert len(rows) == 1
    row = rows[0]
    row["tetragon_sigkill"] = bool(row["tetragon_sigkill"])
    row["cisa_kev"] = bool(row["cisa_kev"])
    row["reachable"] = bool(row["reachable"])
    row["ocsf_classes"] = [1007, 2002, 2003, 2004]
    return row


def draft_hitl_quarantine_pr(
    incident: dict[str, Any],
) -> dict[str, Any]:
    """Generate deterministic HITL Quarantine NetworkPolicy PR."""
    ns = incident["namespace"]
    svc = incident["service"]
    inc_id = incident["incident_id"]
    netpol = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": f"quarantine-{svc}-{inc_id}",
            "namespace": ns,
            "annotations": {
                "secops.orderflow.io/incident": inc_id,
                "secops.orderflow.io/cve": incident["cve_id"],
                "secops.orderflow.io/control": incident["control_id"],
            },
        },
        "spec": {
            "podSelector": {"matchLabels": {"app": svc}},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [],
            "egress": [],
        },
    }
    return {
        "incident_id": inc_id,
        "automerge": False,
        "hitl_signoff_required": True,
        "pr_branch": f"secops/quarantine-{inc_id}",
        "pr_title": (
            f"[HITL] Quarantine {svc} ({incident['cve_id']}, "
            f"{incident['control_id']})"
        ),
        "target_manifest_path": (
            f"gitops/{ns}/quarantine-{svc}-netpol.yaml"
        ),
        "network_policy": netpol,
    }


def run_purple_team_drills() -> dict[str, Any]:
    """Execute 10 Purple-Team drills and compute defense metrics."""
    drills = [
        ("PT-01", True, True, True, 0.001),
        ("PT-02", True, True, True, 0.001),
        ("PT-03", True, True, True, 0.001),
        ("PT-04", True, True, True, 0.002),
        ("PT-05", True, True, True, 0.420),
        ("PT-06", True, True, True, 0.355),
        ("PT-07", False, False, False, 0.0),
        ("PT-08", False, False, False, 0.0),
        ("PT-09", False, False, False, 0.0),
        ("PT-10", False, False, False, 0.0),
    ]
    records: list[dict[str, Any]] = []
    attacks = benign = tp = prevented = fp = 0
    isolate_secs: list[float] = []

    for drill_id, is_attack, detected, in_kernel, mtti in drills:
        if is_attack:
            attacks += 1
            if detected:
                tp += 1
            if in_kernel:
                prevented += 1
            isolate_secs.append(mtti)
        else:
            benign += 1
            if detected or in_kernel:
                fp += 1
        records.append(
            {
                "drill_id": drill_id,
                "attack_drill": is_attack,
                "detected": detected,
                "prevented_in_kernel": in_kernel,
                "isolate_sec": mtti,
            }
        )

    return {
        "total_drills": len(records),
        "attack_drills": attacks,
        "benign_drills": benign,
        "tp_detection_rate": tp / attacks,
        "in_kernel_prevention_rate": prevented / attacks,
        "false_positive_rate": fp / benign,
        "mean_time_to_isolate_sec": round(
            sum(isolate_secs) / len(isolate_secs), 4
        ),
        "drills": records,
    }


def main() -> int:
    """Run OCSF 4-class join, HITL PR synthesis, and 10 drills."""
    incident = load_and_correlate_ocsf(EVENTS_PATH)
    pr_draft = draft_hitl_quarantine_pr(incident)
    purple = run_purple_team_drills()
    print(
        json.dumps(
            {
                "correlated_incident": incident,
                "hitl_quarantine_pr": pr_draft,
                "purple_team": purple,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
