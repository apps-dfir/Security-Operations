from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

@dataclass
class MitreTechnique:
    id: str
    name: str

@dataclass
class MitreSection:
    enabled: bool
    source: str
    techniques: list[MitreTechnique]

def _load_tech_lookup(mitre_json_path: Path) -> dict[str, str]:
    data = json.loads(mitre_json_path.read_text(encoding="utf-8"))
    out: dict[str, str] = {}

    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        tid = None
        for r in (obj.get("external_references") or []):
            if r.get("source_name") == "mitre-attack" and r.get("external_id"):
                tid = r["external_id"]
                break

        if tid:
            out[tid] = (obj.get("name", "") or "").strip()

    return out

def extract_mitre_techniques(
    article_text: str,
    ocr_results: list[dict],
    mitre_json_path: Optional[Path],
    max_techniques: int = 30,
) -> MitreSection:
    combined_text = (article_text or "") + "\n\n" + "\n".join([(r.get("text") or "") for r in (ocr_results or [])])

    if not mitre_json_path:
        return MitreSection(enabled=False, source="(missing enterprise-attack.json)", techniques=[])

    lookup = _load_tech_lookup(mitre_json_path)
    found: list[MitreTechnique] = []

    # Explicit technique IDs
    ids: list[str] = []
    for tid in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", combined_text, flags=re.I):
        tid = tid.upper()
        if tid not in ids:
            ids.append(tid)

    for tid in ids:
        base = tid.split(".")[0]
        found.append(MitreTechnique(id=tid, name=lookup.get(base, "")))

    # Conservative name matching: full-phrase boundary match + ignore short names
    lower = combined_text.lower()
    for base_id, name in lookup.items():
        nm = (name or "").strip()
        if len(nm) < 14:
            continue
        phrase = re.escape(nm.lower())
        if re.search(rf"(?<![a-z0-9]){phrase}(?![a-z0-9])", lower):
            found.append(MitreTechnique(id=base_id, name=nm))

    # De-dupe + cap
    seen = set()
    uniq: list[MitreTechnique] = []
    for t in found:
        if t.id in seen:
            continue
        seen.add(t.id)
        uniq.append(t)
    uniq = uniq[:max_techniques]

    return MitreSection(enabled=True, source=str(mitre_json_path), techniques=uniq)
