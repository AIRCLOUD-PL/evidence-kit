"""Command line: ``python -m evidence_kit {collect,report,gate,validate}``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from evidence_kit import __version__
from evidence_kit.checks import SEVERITIES
from evidence_kit.collect import collect
from evidence_kit.mapping import MappingError, load, validate
from evidence_kit.report import write

DEFAULT_MAPPING = Path(__file__).resolve().parent.parent / "mappings" / "controls.yaml"
THRESHOLDS = ("none", "critical", "high", "medium", "low")


def _cmd_collect(a: argparse.Namespace) -> int:
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    data = collect(Path(a.repo))
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"repo checks written to {out}")
    return 0


def _cmd_report(a: argparse.Namespace) -> int:
    try:
        mapping = load(Path(a.mapping))
    except (MappingError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    langs = [x.strip() for x in a.lang.split(",") if x.strip()]
    bad = [x for x in langs if x not in ("en", "pl")]
    if bad:
        print(f"error: unsupported language(s): {', '.join(bad)}", file=sys.stderr)
        return 2
    doc = write(Path(a.evidence_dir), mapping, langs)
    s = doc["summary"]
    print("evidence: " + ", ".join(f"{k}={v}" for k, v in s.items()))
    return 0


def gate(doc: dict, fail_on: str, fail_on_secrets: bool) -> list[str]:
    """Return reasons to fail (empty list = gate passes)."""
    reasons: list[str] = []
    by_id = {c["id"]: c for c in doc.get("controls", [])}
    if fail_on != "none":
        vuln = by_id.get("EK-VULN") or {}
        if vuln.get("outcome") == "not-run":
            reasons.append("vulnerability scan did not run")
        sev = (vuln.get("data") or {}).get("by_severity") or {}
        cutoff = SEVERITIES.index(fail_on.upper())
        hits = {s: sev.get(s, 0) for s in SEVERITIES[: cutoff + 1] if sev.get(s, 0)}
        if hits:
            reasons.append("vulnerabilities at or above " + fail_on + ": " + json.dumps(hits))
    if fail_on_secrets:
        sec = by_id.get("EK-SECRETS") or {}
        if sec.get("outcome") == "not-run":
            reasons.append("secret scan did not run")
        elif (sec.get("data") or {}).get("findings", 0):
            reasons.append(f"{sec['data']['findings']} potential secret(s) in git history")
    return reasons


def _cmd_gate(a: argparse.Namespace) -> int:
    doc = json.loads(Path(a.evidence).read_text(encoding="utf-8"))
    reasons = gate(doc, a.fail_on, a.fail_on_secrets)
    for r in reasons:
        print(f"gate: {r}", file=sys.stderr)
    if reasons:
        return 1
    print("gate: ok")
    return 0


def _cmd_validate(a: argparse.Namespace) -> int:
    import yaml

    doc = yaml.safe_load(Path(a.mapping).read_text(encoding="utf-8"))
    problems = validate(doc)
    for p in problems:
        print(f"mapping: {p}", file=sys.stderr)
    if problems:
        return 1
    auto = sum(1 for c in doc["controls"] if c["status"] == "auto")
    print(f"mapping ok: {len(doc['controls'])} controls ({auto} auto), {len(doc['references'])} references")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="evidence_kit", description=__doc__)
    ap.add_argument("--version", action="version", version=f"evidence-kit {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect", help="check repository files and GitHub settings")
    c.add_argument("--repo", default=".")
    c.add_argument("--out", default="evidence/repo-checks.json")
    c.set_defaults(func=_cmd_collect)

    r = sub.add_parser("report", help="build evidence.json and Markdown reports")
    r.add_argument("--evidence-dir", default="evidence")
    r.add_argument("--mapping", default=str(DEFAULT_MAPPING))
    r.add_argument("--lang", default="en,pl")
    r.set_defaults(func=_cmd_report)

    g = sub.add_parser("gate", help="exit 1 when findings exceed the threshold")
    g.add_argument("--evidence", default="evidence/evidence.json")
    g.add_argument("--fail-on", choices=THRESHOLDS, default="none")
    g.add_argument("--fail-on-secrets", action="store_true")
    g.set_defaults(func=_cmd_gate)

    v = sub.add_parser("validate", help="validate a mapping file")
    v.add_argument("mapping", nargs="?", default=str(DEFAULT_MAPPING))
    v.set_defaults(func=_cmd_validate)

    a = ap.parse_args(argv)
    return a.func(a)
