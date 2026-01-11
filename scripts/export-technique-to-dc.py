#!/usr/bin/env python3
import csv
import json
from pathlib import Path
from collections import defaultdict


def get_external_id(obj: dict, prefix: str) -> str:
    for ref in obj.get("external_references", []) or []:
        ext_id = ref.get("external_id", "")
        if isinstance(ext_id, str) and ext_id.startswith(prefix):
            return ext_id
    return ""


def extract_dc_refs_from_analytic(analytic: dict) -> list[str]:
    refs = []
    for item in analytic.get("x_mitre_log_source_references", []) or []:
        if not isinstance(item, dict):
            continue
        dc_ref = item.get("x_mitre_data_component_ref")
        if isinstance(dc_ref, str) and dc_ref.startswith("x-mitre-data-component--"):
            refs.append(dc_ref)
    return list(dict.fromkeys(refs))  # unique, keep order


def main() -> int:
    input_path = Path("data/input/enterprise-attack.json")
    if not input_path.exists():
        raise FileNotFoundError(f"Not found: {input_path}")

    out_dir = Path("data/output")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "enterprise_technique_to_dc.csv"

    with input_path.open("r", encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", []) or []

    # ---- index objects ----
    dcs = {o["id"]: o for o in objects if o.get("type") == "x-mitre-data-component"}
    analytics = {o["id"]: o for o in objects if o.get("type") == "x-mitre-analytic"}
    dets = {o["id"]: o for o in objects if o.get("type") == "x-mitre-detection-strategy"}
    techniques = {o["id"]: o for o in objects if o.get("type") == "attack-pattern"}

    # Analytic -> DC
    analytic_to_dc = {}
    for an_id, an in analytics.items():
        analytic_to_dc[an_id] = extract_dc_refs_from_analytic(an)

    # Detection Strategy -> Analytic
    det_to_analytic = {}
    for det_id, det in dets.items():
        refs = det.get("x_mitre_analytic_refs") or []
        det_to_analytic[det_id] = [
            r for r in refs if isinstance(r, str) and r.startswith("x-mitre-analytic--")
        ]

    # Technique -> {DCs, DETs}
    technique_map = defaultdict(lambda: {"dc": set(), "det": set()})

    detects_rels = [
        o for o in objects
        if o.get("type") == "relationship" and o.get("relationship_type") == "detects"
    ]

    for rel in detects_rels:
        det_id = rel.get("source_ref")
        tech_id = rel.get("target_ref")

        if det_id not in dets or tech_id not in techniques:
            continue

        technique_map[tech_id]["det"].add(det_id)

        for an_ref in det_to_analytic.get(det_id, []):
            for dc_ref in analytic_to_dc.get(an_ref, []):
                if dc_ref in dcs:
                    technique_map[tech_id]["dc"].add(dc_ref)

    # ---- build CSV rows ----
    rows = []
    for tech_id, tech in techniques.items():
        if tech_id not in technique_map:
            continue

        dc_refs = sorted(technique_map[tech_id]["dc"])
        det_refs = sorted(technique_map[tech_id]["det"])

        rows.append({
            "technique_id": get_external_id(tech, "T"),
            "technique_name": tech.get("name", ""),
            "technique_stix_id": tech.get("id", ""),
            "is_subtechnique": bool(tech.get("x_mitre_is_subtechnique", False)),
            "dc_ids": ";".join(get_external_id(dcs[dc], "DC") for dc in dc_refs),
            "dc_names": ";".join(dcs[dc].get("name", "") for dc in dc_refs),
            "det_ids": ";".join(get_external_id(dets[det], "DET") for det in det_refs),
            "dc_count": len(dc_refs),
        })

    rows.sort(key=lambda r: (r["technique_id"] or "ZZZZZZ"))

    fieldnames = [
        "technique_id",
        "technique_name",
        "technique_stix_id",
        "is_subtechnique",
        "dc_ids",
        "dc_names",
        "det_ids",
        "dc_count",
    ]

    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    print(f"Input : {input_path}")
    print(f"Output: {out_path} ({len(rows)} techniques)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
