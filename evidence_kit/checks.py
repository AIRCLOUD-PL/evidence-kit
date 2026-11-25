"""Control evaluators.

Each evaluator reads already-loaded tool outputs from an ``Evidence`` object and
returns an outcome with a bilingual one-line result. Missing or malformed input
never yields ``pass`` (FR-010).
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

OUTCOMES = ("pass", "warn", "fail", "unknown", "not-run", "manual")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")

# File names inside the evidence directory.
FILES = {
    "sbom": "sbom.cdx.json",
    "vulns": "vulnerabilities.trivy.json",
    "secrets": "secrets.gitleaks.json",
    "secrets_baseline": "secrets.gitleaks.baseline.json",
    "scorecard": "scorecard.json",
    "repo": "repo-checks.json",
}


@dataclass
class Evidence:
    directory: Path
    data: dict[str, Any] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, directory: Path) -> Evidence:
        ev = cls(Path(directory))
        for key, name in FILES.items():
            path = ev.directory / name
            if not path.is_file():
                ev.errors[key] = f"{name} not found"
                continue
            try:
                ev.data[key] = json.loads(path.read_text(encoding="utf-8") or "null")
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                ev.errors[key] = f"{name}: invalid JSON ({e.__class__.__name__})"
        return ev

    def get(self, key: str) -> Any:
        return self.data.get(key)


def result(outcome: str, en: str, pl: str, **data: Any) -> dict[str, Any]:
    assert outcome in OUTCOMES, outcome
    return {"outcome": outcome, "result": {"en": en, "pl": pl}, "data": data}


def _missing(ev: Evidence, key: str) -> dict[str, Any] | None:
    if key in ev.errors:
        msg = ev.errors[key]
        notes = ((ev.get("repo") or {}).get("meta") or {}).get("notes") or {}
        if notes:  # reason recorded by a workflow step, e.g. unsupported runner architecture
            msg += "; " + "; ".join(f"{k}: {v}" for k, v in sorted(notes.items()))
        return result("not-run", f"No input: {msg}.", f"Brak danych wejściowych: {msg}.", error=msg)
    return None


def _repo_files(ev: Evidence) -> dict[str, Any]:
    return (ev.get("repo") or {}).get("files") or {}


# --------------------------------------------------------------------------- SBOM


def check_sbom(ev: Evidence, control: dict[str, Any]) -> dict[str, Any]:
    if m := _missing(ev, "sbom"):
        return m
    bom = ev.get("sbom")
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX":
        return result(
            "fail",
            "File is not a CycloneDX SBOM.",
            "Plik nie jest SBOM w formacie CycloneDX.",
        )
    comps = [c for c in bom.get("components") or [] if isinstance(c, dict)]
    # Trivy also lists lock files as "application" components; count packages only.
    libs = [c for c in comps if c.get("type") in ("library", "framework")]
    with_purl = sum(1 for c in libs if c.get("purl"))
    with_lic = sum(1 for c in libs if c.get("licenses"))
    data = {
        "spec_version": bom.get("specVersion"),
        "serial_number": bom.get("serialNumber"),
        "components": len(comps),
        "packages": len(libs),
        "with_purl": with_purl,
        "with_license": with_lic,
        "generator": _sbom_tool(bom),
    }
    if not libs:
        return result(
            "warn",
            f"CycloneDX {data['spec_version']} SBOM is valid but lists no packages (no supported lock file?).",
            f"SBOM CycloneDX {data['spec_version']} jest poprawny, ale nie zawiera pakietów "
            "(brak obsługiwanego pliku lock?).",
            **data,
        )
    return result(
        "pass",
        f"CycloneDX {data['spec_version']} SBOM: {len(libs)} package(s), {with_purl} with purl.",
        f"SBOM CycloneDX {data['spec_version']}: pakiety: {len(libs)} (z purl: {with_purl}).",
        **data,
    )


def _sbom_tool(bom: dict[str, Any]) -> str:
    tools = (bom.get("metadata") or {}).get("tools")
    if isinstance(tools, dict):  # CycloneDX 1.5+
        tools = tools.get("components") or []
    if isinstance(tools, list) and tools and isinstance(tools[0], dict):
        t = tools[0]
        return f"{t.get('name', '?')} {t.get('version', '')}".strip()
    return ""


# --------------------------------------------------------------------------- vulnerabilities

VEX_STATUSES = {"not_affected", "fixed", "under_investigation", "affected"}


def _suppression_kind(m: dict[str, Any]) -> str:
    """Classify a Trivy suppressed finding by source (FR-018)."""
    source = Path(str(m.get("Source") or "")).name.lower()
    status = str(m.get("Status") or "").lower()
    if source.startswith(".trivyignore") or status == "ignored":
        return "ignore-file"
    if status in VEX_STATUSES:
        return "vex"
    return "other"


def vuln_counts(report: Any) -> dict[str, Any]:
    """Count unique vulnerabilities and suppressed findings in a Trivy JSON report."""
    seen: set[tuple[str, str, str]] = set()
    sev: Counter[str] = Counter()
    fixable: Counter[str] = Counter()
    by_kind: Counter[str] = Counter()
    suppressed: list[dict[str, str]] = []
    top: list[dict[str, str]] = []
    results = (report.get("Results") or []) if isinstance(report, dict) else []
    for r in results:
        if not isinstance(r, dict):
            continue
        # Trivy >= 0.50 names it ExperimentalModifiedFindings (requires --show-suppressed).
        for m in r.get("ExperimentalModifiedFindings") or r.get("ModifiedFindings") or []:
            if not isinstance(m, dict):
                continue
            kind = _suppression_kind(m)
            by_kind[kind] += 1
            f = m.get("Finding") or {}
            suppressed.append(
                {
                    "id": f.get("VulnerabilityID", ""),
                    "package": f.get("PkgName", ""),
                    "severity": (f.get("Severity") or "UNKNOWN").upper(),
                    "kind": kind,
                    "status": m.get("Status", ""),
                    "statement": m.get("Statement", ""),
                    "source": Path(str(m.get("Source") or "")).name,
                }
            )
        for v in r.get("Vulnerabilities") or []:
            key = (v.get("VulnerabilityID", ""), v.get("PkgName", ""), v.get("InstalledVersion", ""))
            if key in seen:
                continue
            seen.add(key)
            s = (v.get("Severity") or "UNKNOWN").upper()
            s = s if s in SEVERITIES else "UNKNOWN"
            sev[s] += 1
            if v.get("FixedVersion"):
                fixable[s] += 1
            top.append(
                {
                    "id": key[0],
                    "package": key[1],
                    "version": key[2],
                    "fixed": v.get("FixedVersion") or "",
                    "severity": s,
                }
            )
    order = {s: i for i, s in enumerate(SEVERITIES)}
    top.sort(key=lambda x: (order[x["severity"]], x["id"]))
    return {
        "by_severity": {s: sev.get(s, 0) for s in SEVERITIES},
        "fixable": {s: fixable.get(s, 0) for s in SEVERITIES},
        "total": sum(sev.values()),
        "suppressed": {k: by_kind.get(k, 0) for k in ("vex", "ignore-file", "other")},
        "suppressed_findings": suppressed[:50],
        "top": top[:25],
    }


def _scan_config(ev: Evidence) -> dict[str, list[str]]:
    return (ev.get("repo") or {}).get("scan_config") or {}


def _at_least_warn(outcome: str) -> str:
    return "warn" if outcome == "pass" else outcome


def check_vulnerabilities(ev: Evidence, control: dict[str, Any]) -> dict[str, Any]:
    if m := _missing(ev, "vulns"):
        return m
    rep = ev.get("vulns")
    if not isinstance(rep, dict) or "SchemaVersion" not in rep:
        return result("not-run", "Not a Trivy JSON report.", "To nie jest raport JSON Trivy.")
    params = control.get("params") or {}
    fail_s = [s.upper() for s in params.get("fail_severities", ["CRITICAL", "HIGH"])]
    warn_s = [s.upper() for s in params.get("warn_severities", ["MEDIUM", "LOW", "UNKNOWN"])]
    c = vuln_counts(rep)
    meta = (ev.get("repo") or {}).get("meta") or {}
    cfg = _scan_config(ev)
    c["vex_file"] = meta.get("vex_file") or ""
    c["trivy_ignore_files"] = cfg.get("trivy_ignore") or []
    c["trivy_config_files_not_applied"] = cfg.get("trivy_config") or []
    bs = c["by_severity"]
    sup = c["suppressed"]
    summary_en = ", ".join(f"{bs[s]} {s.lower()}" for s in SEVERITIES if bs[s]) or "none"
    summary_pl = ", ".join(f"{s.lower()}: {bs[s]}" for s in SEVERITIES if bs[s]) or "brak"
    if any(bs.get(s, 0) for s in fail_s):
        outcome = "fail"
    elif any(bs.get(s, 0) for s in warn_s):
        outcome = "warn"
    else:
        outcome = "pass"
    en: list[str] = [f"Known vulnerabilities: {summary_en}."]
    pl: list[str] = [f"Znane podatności: {summary_pl}."]
    if sup["vex"]:
        en.append(f"Suppressed by VEX: {sup['vex']}.")
        pl.append(f"Wyłączone przez VEX: {sup['vex']}.")
    if sup["ignore-file"] or sup["other"]:
        # Ignore files carry no justification: never a silent pass.
        outcome = _at_least_warn(outcome)
        n = sup["ignore-file"] + sup["other"]
        src = ", ".join(c["trivy_ignore_files"]) or "ignore file"
        en.append(f"Suppressed by {src}: {n} (review the list).")
        pl.append(f"Wyłączone przez {src}: {n} (sprawdź listę).")
    if c["trivy_config_files_not_applied"]:
        files = ", ".join(c["trivy_config_files_not_applied"])
        en.append(f"{files} in the repository was not applied.")
        pl.append(f"{files} z repozytorium nie został zastosowany.")
    return result(outcome, " ".join(en), " ".join(pl), **c)


# --------------------------------------------------------------------------- secrets


def _locations(findings: list[Any], limit: int = 20) -> list[dict[str, Any]]:
    return [
        {
            "rule": f.get("RuleID", "?"),
            "file": f.get("File", ""),
            "line": f.get("StartLine", 0),
            "commit": (f.get("Commit") or "")[:12],
        }
        for f in findings[:limit]
        if isinstance(f, dict)
    ]


def _fingerprint(f: dict[str, Any]) -> str:
    if f.get("Fingerprint"):
        return str(f["Fingerprint"])
    return ":".join(str(f.get(k, "")) for k in ("Commit", "File", "RuleID", "StartLine"))


def check_secrets(ev: Evidence, control: dict[str, Any]) -> dict[str, Any]:
    if m := _missing(ev, "secrets"):
        return m
    findings = ev.get("secrets")
    if findings is None:
        findings = []
    if not isinstance(findings, list):
        return result("not-run", "Not a gitleaks JSON report.", "To nie jest raport JSON gitleaks.")
    findings = [f for f in findings if isinstance(f, dict)]
    rules = Counter(f.get("RuleID", "?") for f in findings)
    cfg = _scan_config(ev)
    repo_cfg = (cfg.get("gitleaks_config") or []) + (cfg.get("gitleaks_ignore") or [])

    # Baseline: default rules, no repository allowlists (FR-018).
    baseline = ev.get("secrets_baseline")
    if isinstance(baseline, list):
        seen = {_fingerprint(f) for f in findings}
        hidden = [f for f in baseline if isinstance(f, dict) and _fingerprint(f) not in seen]
        baseline_state = "ok"
    else:
        hidden = []
        baseline_state = "not-available"
    data: dict[str, Any] = {
        "findings": len(findings),
        "by_rule": dict(rules),
        "locations": _locations(findings),
        "repo_config_files": repo_cfg,
        "baseline": baseline_state,
        "suppressed_by_repo_config": len(hidden),
        "suppressed_locations": _locations(hidden),
    }
    n = len(findings)
    if n:
        outcome = "fail"
        en = f"{n} potential secret(s) in git history (rule types: {len(rules)}). Rotate and remove them."
        pl = f"Potencjalne sekrety w historii git: {n} (typy reguł: {len(rules)}). Unieważnij je i usuń."
    else:
        outcome = "pass"
        en = "No secrets found in the git history."
        pl = "Nie znaleziono sekretów w historii git."
    if hidden:
        outcome = _at_least_warn(outcome)
        src = ", ".join(repo_cfg) or "repository configuration"
        en += f" {len(hidden)} finding(s) of the default rules are suppressed by {src} (review the list)."
        pl += f" Wyłączone przez {src}: {len(hidden)} wynik(ów) reguł domyślnych (sprawdź listę)."
    elif repo_cfg:
        en += f" Repository config {', '.join(repo_cfg)} applied" + (
            "; nothing suppressed." if baseline_state == "ok" else "; baseline scan not available."
        )
        pl += f" Zastosowano konfigurację {', '.join(repo_cfg)}" + (
            "; nic nie wyłączono." if baseline_state == "ok" else "; brak skanu bazowego."
        )
    return result(outcome, en, pl, **data)


# --------------------------------------------------------------------------- scorecard


def check_scorecard(ev: Evidence, control: dict[str, Any]) -> dict[str, Any]:
    if m := _missing(ev, "scorecard"):
        return m
    sc = ev.get("scorecard")
    if not isinstance(sc, dict) or "checks" not in sc:
        return result("not-run", "Not a Scorecard JSON result.", "To nie jest wynik JSON Scorecard.")
    params = control.get("params") or {}
    pass_min = float(params.get("pass_min", 7.0))
    warn_min = float(params.get("warn_min", 4.0))
    score = sc.get("score")
    checks = [
        {"name": c.get("name", "?"), "score": c.get("score", -1), "reason": c.get("reason", "")}
        for c in sc.get("checks") or []
        if isinstance(c, dict)
    ]
    data = {
        "score": score,
        "version": (sc.get("scorecard") or {}).get("version", ""),
        "checks": checks,
        "pass_min": pass_min,
        "warn_min": warn_min,
    }
    if not isinstance(score, (int, float)) or score < 0:
        return result(
            "unknown",
            "Scorecard ran but returned no aggregate score.",
            "Scorecard nie zwrócił łącznej oceny.",
            **data,
        )
    outcome = "pass" if score >= pass_min else "warn" if score >= warn_min else "fail"
    low = [c["name"] for c in sorted(checks, key=lambda x: x["score"]) if 0 <= c["score"] < 5]
    low_en = f" Lowest: {', '.join(low[:5])}." if low else ""
    low_pl = f" Najsłabsze: {', '.join(low[:5])}." if low else ""
    return result(
        outcome,
        f"Scorecard {score}/10 (pass >= {pass_min}).{low_en}",
        f"Scorecard {score}/10 (próg zaliczenia {pass_min}).{low_pl}",
        **data,
    )


# --------------------------------------------------------------------------- repo hygiene


def _repo_required(ev: Evidence) -> dict[str, Any] | None:
    return _missing(ev, "repo")


def check_security_policy(ev: Evidence, control: dict[str, Any]) -> dict[str, Any]:
    if m := _repo_required(ev):
        return m
    f = _repo_files(ev).get("security_policy") or {}
    gh = (ev.get("repo") or {}).get("github") or {}
    pvr = gh.get("private_vulnerability_reporting")
    paths = f.get("paths") or []
    data = {"paths": paths, "contact_found": f.get("contact_found"), "private_vulnerability_reporting": pvr}
    if not paths:
        return result(
            "fail",
            "No SECURITY.md (root, .github/ or docs/).",
            "Brak SECURITY.md (w katalogu głównym, .github/ lub docs/).",
            **data,
        )
    if not f.get("contact_found"):
        return result(
            "warn",
            f"{paths[0]} found, but no reporting contact (e-mail, security.txt or advisory link) detected.",
            f"Jest {paths[0]}, ale nie wykryto kontaktu do zgłoszeń (e-mail, security.txt lub link do advisories).",
            **data,
        )
    pvr_en = " Private vulnerability reporting is enabled." if pvr else ""
    pvr_pl = " Prywatne zgłaszanie podatności jest włączone." if pvr else ""
    return result(
        "pass",
        f"{paths[0]} with a reporting contact.{pvr_en}",
        f"{paths[0]} z kontaktem do zgłoszeń.{pvr_pl}",
        **data,
    )


def check_cvd_policy(ev: Evidence, control: dict[str, Any]) -> dict[str, Any]:
    if m := _repo_required(ev):
        return m
    f = _repo_files(ev).get("cvd_policy") or {}
    paths = f.get("paths") or []
    in_sec = bool(f.get("section_in_security_md"))
    data = {"paths": paths, "section_in_security_md": in_sec}
    if paths:
        return result("pass", f"CVD policy: {paths[0]}.", f"Polityka CVD: {paths[0]}.", **data)
    if in_sec:
        return result(
            "pass",
            "CVD section found in SECURITY.md.",
            "Sekcja CVD w SECURITY.md.",
            **data,
        )
    return result(
        "fail",
        "No coordinated vulnerability disclosure policy found (see templates/).",
        "Nie znaleziono polityki skoordynowanego ujawniania podatności (zob. templates/).",
        **data,
    )


def check_security_txt(ev: Evidence, control: dict[str, Any]) -> dict[str, Any]:
    if m := _repo_required(ev):
        return m
    items = _repo_files(ev).get("security_txt") or []
    if not items:
        return result(
            "warn",
            "No security.txt in the repository. If you publish it on your website, attach that URL manually.",
            "Brak security.txt w repozytorium. Jeśli publikujesz go na stronie, dołącz ten adres ręcznie.",
            paths=[],
        )
    best = items[0]
    data = {"paths": [i.get("path") for i in items], "expires": best.get("expires"), "contact": best.get("contact")}
    if not best.get("contact"):
        return result("fail", f"{best['path']} has no Contact field.", f"{best['path']} nie ma pola Contact.", **data)
    if best.get("expires_valid") is not True:
        return result(
            "fail",
            f"{best['path']}: Expires missing, invalid or in the past ({best.get('expires')}).",
            f"{best['path']}: pole Expires brakuje, jest błędne lub minęło ({best.get('expires')}).",
            **data,
        )
    return result(
        "pass",
        f"{best['path']} valid until {best['expires']}.",
        f"{best['path']} ważny do {best['expires']}.",
        **data,
    )


def check_codeowners(ev: Evidence, control: dict[str, Any]) -> dict[str, Any]:
    if m := _repo_required(ev):
        return m
    f = _repo_files(ev).get("codeowners") or {}
    paths = f.get("paths") or []
    rules = int(f.get("rules") or 0)
    if not paths:
        return result("fail", "No CODEOWNERS file.", "Brak pliku CODEOWNERS.", paths=[], rules=0)
    if rules == 0:
        return result(
            "warn",
            f"{paths[0]} has no ownership rules.",
            f"{paths[0]} nie zawiera reguł.",
            paths=paths,
            rules=0,
        )
    return result(
        "pass",
        f"{paths[0]} with {rules} rule(s).",
        f"{paths[0]}: reguł {rules}.",
        paths=paths,
        rules=rules,
    )


def check_branch_protection(ev: Evidence, control: dict[str, Any]) -> dict[str, Any]:
    if m := _repo_required(ev):
        return m
    gh = (ev.get("repo") or {}).get("github") or {}
    if not gh.get("available"):
        err = gh.get("error", "GitHub API not reachable")
        return result(
            "unknown",
            f"Not verifiable: {err}. Attach a screenshot or export of the branch rules.",
            f"Nie do sprawdzenia: {err}. Dołącz zrzut lub eksport reguł gałęzi.",
            error=err,
        )
    branch = gh.get("default_branch", "?")
    rules = gh.get("rules") or []
    classic = gh.get("classic") or {}
    protected = gh.get("protected")
    pr_required = "pull_request" in rules or classic.get("required_pull_request_reviews", False)
    data = {
        "default_branch": branch,
        "protected": protected,
        "rules": rules,
        "classic": classic or None,
    }
    if pr_required:
        extra = [r for r in ("non_fast_forward", "deletion", "required_status_checks") if r in rules]
        tail = f" (+ {', '.join(extra)})" if extra else ""
        return result(
            "pass",
            f"`{branch}` requires pull requests{tail}.",
            f"Gałąź `{branch}` wymaga pull requestów{tail}.",
            **data,
        )
    if protected or rules:
        return result(
            "warn",
            f"`{branch}` is protected, but a pull-request review requirement could not be confirmed.",
            f"Gałąź `{branch}` jest chroniona, ale nie potwierdzono wymogu przeglądu pull requestów.",
            **data,
        )
    if protected is None and gh.get("rules") is None:
        return result(
            "unknown",
            "Branch API not readable with this token.",
            "API gałęzi niedostępne dla tego tokenu.",
            **data,
        )
    return result(
        "fail",
        f"`{branch}` has no branch protection or ruleset.",
        f"Gałąź `{branch}` nie ma ochrony ani rulesetu.",
        **data,
    )


def _presence(key: str, en_name: str, pl_name: str, missing_outcome: str = "fail"):
    def _check(ev: Evidence, control: dict[str, Any]) -> dict[str, Any]:
        if m := _repo_required(ev):
            return m
        paths = (_repo_files(ev).get(key) or {}).get("paths") or []
        if paths:
            more = f" (+{len(paths) - 1})" if len(paths) > 1 else ""
            return result(
                "pass",
                f"{en_name}: {paths[0]}{more}.",
                f"{pl_name}: {paths[0]}{more}.",
                paths=paths,
            )
        return result(
            missing_outcome,
            f"{en_name}: not found (see templates/).",
            f"{pl_name}: nie znaleziono (zob. templates/).",
            paths=[],
        )

    return _check


EVALUATORS: dict[str, Callable[[Evidence, dict[str, Any]], dict[str, Any]]] = {
    "sbom": check_sbom,
    "vulnerabilities": check_vulnerabilities,
    "secrets": check_secrets,
    "scorecard": check_scorecard,
    "security_policy": check_security_policy,
    "cvd_policy": check_cvd_policy,
    "security_txt": check_security_txt,
    "codeowners": check_codeowners,
    "branch_protection": check_branch_protection,
    "dependency_updates": _presence(
        "dependency_updates", "Dependency update config", "Konfiguracja aktualizacji zależności", "warn"
    ),
    "supplier_register": _presence("supplier_register", "Supplier register", "Rejestr dostawców", "warn"),
    "incident_runbook": _presence(
        "incident_runbook", "Incident reporting runbook", "Procedura zgłaszania incydentów", "warn"
    ),
}
