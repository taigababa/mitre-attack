#!/usr/bin/env python3
import csv
import json
from pathlib import Path
from collections import Counter


def get_external_id(obj: dict, prefix: str) -> str:
    for ref in obj.get("external_references", []) or []:
        ext_id = ref.get("external_id", "")
        if isinstance(ext_id, str) and ext_id.startswith(prefix):
            return ext_id
    return ""


def extract_dc_refs_from_analytic(analytic: dict) -> list[str]:
    """
    analytic['x_mitre_log_source_references'] の中から
    x_mitre_data_component_ref を拾う（重複排除、順序維持）
    """
    refs = []
    for item in analytic.get("x_mitre_log_source_references", []) or []:
        if not isinstance(item, dict):
            continue
        dc_ref = item.get("x_mitre_data_component_ref")
        if isinstance(dc_ref, str) and dc_ref.startswith("x-mitre-data-component--"):
            refs.append(dc_ref)

    # unique preserve order
    uniq, seen = [], set()
    for r in refs:
        if r not in seen:
            seen.add(r)
            uniq.append(r)
    return uniq


def main() -> int:
    input_path = Path("data/input/enterprise-attack.json")
    if not input_path.exists():
        raise FileNotFoundError(f"Not found: {input_path}")

    out_dir = Path("data/output")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "enterprise_dc_detects_techniques.csv"

    with input_path.open("r", encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", []) or []
    type_counts = Counter(o.get("type", "") for o in objects)

    # Index objects
    dcs = {o["id"]: o for o in objects if o.get("type") == "x-mitre-data-component" and "id" in o}
    analytics = {o["id"]: o for o in objects if o.get("type") == "x-mitre-analytic" and "id" in o}
    det_strats = {o["id"]: o for o in objects if o.get("type") == "x-mitre-detection-strategy" and "id" in o}
    techniques = {o["id"]: o for o in objects if o.get("type") == "attack-pattern" and "id" in o}

    # Build analytic -> dc_refs map
    analytic_to_dc = {}
    analytics_without_dc = 0
    for an_id, an in analytics.items():
        dc_refs = extract_dc_refs_from_analytic(an)
        if not dc_refs:
            analytics_without_dc += 1
        analytic_to_dc[an_id] = dc_refs

    # Build detection strategy -> analytic refs map
    det_to_analytics = {}
    det_without_analytics = 0
    for det_id, det in det_strats.items():
        refs = det.get("x_mitre_analytic_refs") or []
        refs = [r for r in refs if isinstance(r, str) and r.startswith("x-mitre-analytic--")]
        if not refs:
            det_without_analytics += 1
        det_to_analytics[det_id] = refs

    # Detects relationships: detection-strategy -> technique
    detects_rels = [
        o for o in objects
        if o.get("type") == "relationship" and o.get("relationship_type") == "detects"
    ]
    src_prefix = Counter(r.get("source_ref", "").split("--")[0] for r in detects_rels if r.get("source_ref"))
    tgt_prefix = Counter(r.get("target_ref", "").split("--")[0] for r in detects_rels if r.get("target_ref"))

    rows = []
    rels_no_dc_path = 0

    for rel in detects_rels:
        det_stix = rel.get("source_ref", "")
        tech_stix = rel.get("target_ref", "")

        if not (isinstance(det_stix, str) and det_stix.startswith("x-mitre-detection-strategy--")):
            continue
        if not (isinstance(tech_stix, str) and tech_stix.startswith("attack-pattern--")):
            continue

        det = det_strats.get(det_stix)
        tech = techniques.get(tech_stix)
        if det is None or tech is None:
            continue

        det_ext = get_external_id(det, "DET")
        tech_ext = get_external_id(tech, "T")

        analytic_refs = det_to_analytics.get(det_stix, [])
        # expand to DC refs via analytics
        dc_refs = []
        for an_ref in analytic_refs:
            dc_refs.extend(analytic_to_dc.get(an_ref, []))

        # unique preserve order
        uniq, seen = [], set()
        for r in dc_refs:
            if r not in seen:
                seen.add(r)
                uniq.append(r)
        dc_refs = uniq

        if not dc_refs:
            rels_no_dc_path += 1
            continue

        for dc_ref in dc_refs:
            dc = dcs.get(dc_ref)
            if dc is None:
                continue

            rows.append({
                "dc_id": get_external_id(dc, "DC"),
                "dc_name": dc.get("name", ""),
                "dc_stix_id": dc.get("id", ""),
                "technique_id": tech_ext,
                "technique_name": tech.get("name", ""),
                "technique_stix_id": tech.get("id", ""),
                "is_subtechnique": bool(tech.get("x_mitre_is_subtechnique", False)),
                "det_id": det_ext,
                "det_name": det.get("name", ""),
                "det_stix_id": det.get("id", ""),
                "relationship_id": rel.get("id", ""),
                "relationship_description": (rel.get("description") or "").replace("\n", " ").strip(),
            })

    rows.sort(key=lambda r: (r["dc_id"] or "ZZZZZZ", r["technique_id"] or "ZZZZZZ", r["det_id"] or "ZZZZZZ"))

    fieldnames = [
        "dc_id", "dc_name", "dc_stix_id",
        "technique_id", "technique_name", "technique_stix_id",
        "is_subtechnique",
        "det_id", "det_name", "det_stix_id",
        "relationship_id", "relationship_description",
    ]

    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    print(f"Input : {input_path}")
    print(f"Output: {out_path} ({len(rows)} rows)")
    print("Top STIX types:", type_counts.most_common(10))
    print("detects source prefixes:", src_prefix.most_common(10))
    print("detects target prefixes:", tgt_prefix.most_common(10))
    print(f"analytics without DC refs: {analytics_without_dc} / {len(analytics)}")
    print(f"detection-strategy without analytics: {det_without_analytics} / {len(det_strats)}")
    print(f"detects rels with no DC path: {rels_no_dc_path} / {len(detects_rels)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
