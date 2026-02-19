#!/usr/bin/env python3
import csv
import json
from collections import defaultdict
from pathlib import Path


def get_external_id(obj: dict, prefix: str) -> str:
    for ref in obj.get("external_references", []) or []:
        ext_id = ref.get("external_id", "")
        if isinstance(ext_id, str) and ext_id.startswith(prefix):
            return ext_id
    return ""


def main() -> int:
    input_path = Path("data/input/enterprise-attack.json")
    if not input_path.exists():
        raise FileNotFoundError(f"Not found: {input_path}")

    out_dir = Path("data/output")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "enterprise_technique_to_mitigation.csv"

    with input_path.open("r", encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", []) or []

    techniques = {o["id"]: o for o in objects if o.get("type") == "attack-pattern"}
    mitigations = {o["id"]: o for o in objects if o.get("type") == "course-of-action"}

    technique_map: dict[str, set[str]] = defaultdict(set)

    mitigates_rels = [
        o for o in objects
        if o.get("type") == "relationship" and o.get("relationship_type") == "mitigates"
    ]

    for rel in mitigates_rels:
        mitigation_id = rel.get("source_ref")
        technique_id = rel.get("target_ref")
        if mitigation_id in mitigations and technique_id in techniques:
            technique_map[technique_id].add(mitigation_id)

    rows = []
    for tech_id, tech in techniques.items():
        mitigation_refs = sorted(
            technique_map.get(tech_id, []),
            key=lambda mid: get_external_id(mitigations[mid], "M") or mitigations[mid].get("name", ""),
        )
        if not mitigation_refs:
            continue

        rows.append({
            "technique_id": get_external_id(tech, "T"),
            "technique_name": tech.get("name", ""),
            "technique_stix_id": tech_id,
            "is_subtechnique": bool(tech.get("x_mitre_is_subtechnique", False)),
            "mitigation_ids": ";".join(get_external_id(mitigations[mid], "M") for mid in mitigation_refs),
            "mitigation_names": ";".join(mitigations[mid].get("name", "") for mid in mitigation_refs),
            "mitigation_count": len(mitigation_refs),
        })

    rows.sort(key=lambda r: (r["technique_id"] or "ZZZZZZ"))

    fieldnames = [
        "technique_id",
        "technique_name",
        "technique_stix_id",
        "is_subtechnique",
        "mitigation_ids",
        "mitigation_names",
        "mitigation_count",
    ]

    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Input : {input_path}")
    print(f"Output: {out_path} ({len(rows)} techniques)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
