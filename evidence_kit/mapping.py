"""Load and validate ``mappings/controls.yaml``."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from evidence_kit.checks import EVALUATORS

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only without PyYAML
    yaml = None

LANGS = ("en", "pl")


class MappingError(ValueError):
    pass


def load(path: Path) -> dict[str, Any]:
    if yaml is None:
        raise MappingError("PyYAML is required: pip install -r requirements.txt")
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    problems = validate(doc)
    if problems:
        raise MappingError("invalid mapping:\n  - " + "\n  - ".join(problems))
    return doc


def validate(doc: Any) -> list[str]:
    """Return a list of human-readable problems (empty = valid)."""
    p: list[str] = []
    if not isinstance(doc, dict):
        return ["mapping root must be a mapping"]
    if doc.get("schema") != "evidence-kit/mapping/v1":
        p.append("schema must be 'evidence-kit/mapping/v1'")
    for lang in LANGS:
        if not (doc.get("disclaimer") or {}).get(lang):
            p.append(f"disclaimer.{lang} is required")
    refs = doc.get("references") or {}
    for rid, ref in refs.items():
        if not isinstance(ref, dict) or not ref.get("cite"):
            p.append(f"reference {rid}: 'cite' is required")
            continue
        for lang in LANGS:
            if not ref.get(lang):
                p.append(f"reference {rid}: '{lang}' label is required")
        if not (rid.startswith("KSC-") or rid.startswith("CRA-")):
            p.append(f"reference {rid}: id must start with KSC- or CRA-")
    ids: set[str] = set()
    controls = doc.get("controls") or []
    if not controls:
        p.append("no controls defined")
    for c in controls:
        cid = c.get("id", "?")
        if cid in ids:
            p.append(f"control {cid}: duplicate id")
        ids.add(cid)
        status = c.get("status")
        if status not in ("auto", "manual"):
            p.append(f"control {cid}: status must be auto or manual")
        for lang in LANGS:
            if not (c.get("title") or {}).get(lang):
                p.append(f"control {cid}: title.{lang} is required")
        if status == "auto":
            if c.get("check") not in EVALUATORS:
                p.append(f"control {cid}: unknown check '{c.get('check')}'")
            if not isinstance(c.get("evidence"), list) or not c.get("evidence"):
                p.append(f"control {cid}: evidence must list evidence files")
        elif status == "manual":
            ev = c.get("evidence") or {}
            if not all(isinstance(ev, dict) and ev.get(lang) for lang in LANGS):
                p.append(f"control {cid}: manual evidence needs en and pl descriptions")
        if not (c.get("ksc") or c.get("cra")):
            p.append(f"control {cid}: maps to neither KSC nor CRA")
        for key, prefix in (("ksc", "KSC-"), ("cra", "CRA-")):
            for rid in c.get(key) or []:
                if rid not in refs:
                    p.append(f"control {cid}: unknown reference {rid}")
                elif not rid.startswith(prefix):
                    p.append(f"control {cid}: {rid} listed under {key}")
    return p
