#!/usr/bin/env python3
import csv
import json
from pathlib import Path
from collections import Counter


def get_dc_id(obj: dict) -> str:
    """Return DCxxxx from external_references, or '' if not found."""
    for ref in obj.get("external_references", []) or []:
        ext_id = ref.get("external_id", "")
        if isinstance(ext_id, str) and ext_id.startswith("DC"):
            return ext_id
    return ""


def main() -> int:
    # input path: absolute then relative
    candidates = [
        Path("/data/input/enterprise-attack.json"),
        Path("data/input/enterprise-attack.json"),
    ]
    input_path = next((p for p in candidates if p.exists()), None)
    if input_path is None:
        raise FileNotFoundError(
            "enterprise-attack.json not found. Tried: " + ", ".join(map(str, candidates))
        )

    out_dir = Path("/data/output") if Path("/data").exists() else Path("data/output")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "enterprise_data_components.csv"

    with input_path.open("r", encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", []) or []
    type_counts = Counter([o.get("type", "") for o in objects])

    data_components = [o for o in objects if o.get("type") == "x-mitre-data-component"]

    rows = []
    for dc in data_components:
        rows.append(
            {
                "dc_id": get_dc_id(dc),  # DCxxxx (may be empty)
                "dc_name": dc.get("name", ""),
                "dc_stix_id": dc.get("id", ""),
                "description": (dc.get("description") or "").replace("\n", " ").strip(),
                "created": dc.get("created", ""),
                "modified": dc.get("modified", ""),
                "deprecated": bool(dc.get("x_mitre_deprecated", False)),
                "revoked": bool(dc.get("revoked", False)),
            }
        )

    # stable order: DC id first; fall back to name
    rows.sort(key=lambda r: (r["dc_id"] or "ZZZZZZ", r["dc_name"]))

    fieldnames = [
        "dc_id",
        "dc_name",
        "dc_stix_id",
        "description",
        "created",
        "modified",
        "deprecated",
        "revoked",
    ]

    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    # helpful summary
    dc_with_id = sum(1 for r in rows if r["dc_id"])
    print(f"Input : {input_path}")
    print(f"Output: {out_path} ({len(rows)} DC rows, {dc_with_id} with DC ID)")
    print("Top STIX types:", type_counts.most_common(10))
    print("x-mitre-data-component:", type_counts.get("x-mitre-data-component", 0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
