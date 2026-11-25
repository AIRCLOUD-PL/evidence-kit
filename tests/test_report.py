import hashlib
import json

import pytest

from evidence_kit.checks import OUTCOMES
from evidence_kit.report import REPORT_NAMES, build, write

EXPECTED = {
    "EK-SBOM": "pass",
    "EK-VULN": "fail",
    "EK-SECRETS": "fail",
    "EK-SCORECARD": "warn",
    "EK-SECURITY-POLICY": "pass",
    "EK-CVD": "pass",
    "EK-SECURITY-TXT": "pass",
    "EK-CODEOWNERS": "pass",
    "EK-BRANCH-PROTECTION": "pass",
    "EK-DEP-UPDATES": "pass",
    "EK-SUPPLIERS": "warn",
    "EK-INCIDENT-RUNBOOK": "warn",
}


def by_id(doc):
    return {c["id"]: c for c in doc["controls"]}


def test_sample_outcomes(sample_dir, mapping):  # V008, V010
    doc = build(sample_dir, mapping)
    got = {cid: c["outcome"] for cid, c in by_id(doc).items() if c["mode"] == "auto"}
    assert got == EXPECTED
    manual = [c for c in doc["controls"] if c["mode"] == "manual"]
    assert manual and all(c["outcome"] == "manual" for c in manual)
    assert sum(doc["summary"].values()) == len(doc["controls"])
    assert set(doc["summary"]) == set(OUTCOMES)


def test_sbom_details(sample_dir, mapping):  # V002
    sbom = by_id(build(sample_dir, mapping))["EK-SBOM"]["data"]
    assert sbom["spec_version"] == "1.6"
    assert sbom["packages"] == 4 and sbom["with_purl"] == 4
    assert sbom["generator"].startswith("trivy")


def test_vulnerability_counts_and_vex(sample_dir, mapping):  # V003
    v = by_id(build(sample_dir, mapping))["EK-VULN"]["data"]
    assert v["by_severity"]["HIGH"] == 7
    assert v["by_severity"]["MEDIUM"] == 12
    assert v["by_severity"]["CRITICAL"] == 0
    assert v["total"] == 19
    assert v["suppressed"] == {"vex": 1, "ignore-file": 0, "other": 0}
    assert v["suppressed_findings"][0]["id"] == "CVE-2021-33503"
    assert v["suppressed_findings"][0]["kind"] == "vex"
    assert v["fixable"]["HIGH"] == 7
    assert v["vex_file"] == ".vex/openvex.json"
    assert v["top"][0]["severity"] == "HIGH"


def test_vulnerability_threshold_from_mapping(sample_dir, mapping):  # V003
    import copy

    m = copy.deepcopy(mapping)
    ctl = next(c for c in m["controls"] if c["id"] == "EK-VULN")
    ctl["params"] = {"fail_severities": ["CRITICAL"], "warn_severities": ["HIGH", "MEDIUM"]}
    assert by_id(build(sample_dir, m))["EK-VULN"]["outcome"] == "warn"


def test_secret_values_never_in_report(sample_dir, mapping):  # V004
    write(sample_dir, mapping, ["en", "pl"])
    for name in REPORT_NAMES.values():
        text = (sample_dir / name).read_text(encoding="utf-8")
        assert "REDACTED" not in text
        assert "config/settings.example.py" in text  # location is shown, value is not
    doc = json.loads((sample_dir / "evidence.json").read_text())
    assert "Secret" not in json.dumps(by_id(doc)["EK-SECRETS"]["data"])


def test_scorecard_details(sample_dir, mapping):  # V005
    sc = by_id(build(sample_dir, mapping))["EK-SCORECARD"]
    assert sc["data"]["score"] == 6.2
    assert len(sc["data"]["checks"]) == 18
    assert "Branch-Protection" in sc["result"]["en"]


@pytest.mark.parametrize(("score", "outcome"), [(8.1, "pass"), (5.0, "warn"), (2.0, "fail"), (-1, "unknown")])
def test_scorecard_thresholds(sample_dir, mapping, score, outcome):  # V005
    path = sample_dir / "scorecard.json"
    sc = json.loads(path.read_text())
    sc["score"] = score
    path.write_text(json.dumps(sc))
    assert by_id(build(sample_dir, mapping))["EK-SCORECARD"]["outcome"] == outcome


def test_both_languages_and_disclaimer(sample_dir, mapping):  # V008, V012
    write(sample_dir, mapping, ["en", "pl"])
    en = (sample_dir / "evidence-report.md").read_text(encoding="utf-8")
    pl = (sample_dir / "evidence-report.pl.md").read_text(encoding="utf-8")
    assert "not legal advice" in en and "authorised auditor" in en
    assert "nie jest porada prawna" in pl and "uprawniony audytor" in pl
    assert "Annex I, Part II(1)" in en and "zał. I część II pkt 1" in pl
    assert "art. 8 ust. 1 pkt 2 lit. e" in en and "art. 8 ust. 1 pkt 2 lit. e" in pl
    for text in (en, pl):
        assert "https://aircloud.com.pl/consulting/?from=evidence-kit" in text
        assert "M-AUDIT" in text and "EK-SBOM" in text
        assert "https://eli.gov.pl/eli/DU/2026/252/ogl" in text
        assert "https://eur-lex.europa.eu/eli/reg/2024/2847/oj" in text


def test_evidence_json_schema_and_hashes(sample_dir, mapping):  # V009
    write(sample_dir, mapping, ["en"])
    doc = json.loads((sample_dir / "evidence.json").read_text())
    assert doc["schema"] == "evidence-kit/v1"
    assert doc["repository"] == "example/demo-app"
    assert doc["generated_at"] == "2026-11-25T00:00:00+00:00"
    assert doc["disclaimer"]["en"] and doc["disclaimer"]["pl"]
    names = {f["path"] for f in doc["evidence_files"]}
    assert names == {
        "repo-checks.json",
        "sbom.cdx.json",
        "scorecard.json",
        "secrets.gitleaks.json",
        "secrets.gitleaks.baseline.json",
        "vulnerabilities.trivy.json",
    }
    for f in doc["evidence_files"]:
        data = (sample_dir / f["path"]).read_bytes()
        assert f["sha256"] == hashlib.sha256(data).hexdigest()
        assert f["bytes"] == len(data)


def test_missing_inputs_never_pass(tmp_path, mapping):  # V010
    empty = tmp_path / "evidence"
    empty.mkdir()
    doc = build(empty, mapping)
    auto = [c for c in doc["controls"] if c["mode"] == "auto"]
    assert {c["outcome"] for c in auto} == {"not-run"}
    assert doc["inputs_missing"]


def test_malformed_input_is_not_run(sample_dir, mapping):  # V010
    (sample_dir / "sbom.cdx.json").write_text("{not json")
    (sample_dir / "vulnerabilities.trivy.json").write_text('{"unexpected": true}')
    (sample_dir / "secrets.gitleaks.json").write_text('{"not": "a list"}')
    c = by_id(build(sample_dir, mapping))
    assert c["EK-SBOM"]["outcome"] == "not-run"
    assert c["EK-VULN"]["outcome"] == "not-run"
    assert c["EK-SECRETS"]["outcome"] == "not-run"


def test_non_cyclonedx_sbom_fails(sample_dir, mapping):  # V002
    (sample_dir / "sbom.cdx.json").write_text('{"spdxVersion": "SPDX-2.3"}')
    assert by_id(build(sample_dir, mapping))["EK-SBOM"]["outcome"] == "fail"


def test_empty_sbom_warns(sample_dir, mapping):  # V002
    (sample_dir / "sbom.cdx.json").write_text('{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}')
    assert by_id(build(sample_dir, mapping))["EK-SBOM"]["outcome"] == "warn"


def test_clean_scan_passes(sample_dir, mapping):  # V003, V004
    (sample_dir / "vulnerabilities.trivy.json").write_text('{"SchemaVersion": 2, "Results": []}')
    (sample_dir / "secrets.gitleaks.json").write_text("[]")
    (sample_dir / "secrets.gitleaks.baseline.json").write_text("[]")
    c = by_id(build(sample_dir, mapping))
    assert c["EK-VULN"]["outcome"] == "pass"
    assert c["EK-SECRETS"]["outcome"] == "pass"


def _set_scan_config(sample_dir, **files):
    path = sample_dir / "repo-checks.json"
    rc = json.loads(path.read_text())
    rc["scan_config"].update(files)
    path.write_text(json.dumps(rc))


IGNORED = {
    "Type": "vulnerability",
    "Status": "ignored",
    "Statement": "",
    "Source": "/home/runner/work/app/app/.trivyignore",
    "Finding": {"VulnerabilityID": "CVE-2099-0001", "PkgName": "demo", "Severity": "CRITICAL"},
}


def test_trivyignore_suppression_is_never_a_silent_pass(sample_dir, mapping):  # V018
    rep = {
        "SchemaVersion": 2,
        "Results": [{"Target": "x", "Vulnerabilities": [], "ExperimentalModifiedFindings": [IGNORED]}],
    }
    (sample_dir / "vulnerabilities.trivy.json").write_text(json.dumps(rep))
    _set_scan_config(sample_dir, trivy_ignore=[".trivyignore"])
    v = by_id(build(sample_dir, mapping))["EK-VULN"]
    assert v["outcome"] == "warn"
    assert v["data"]["suppressed"]["ignore-file"] == 1
    assert v["data"]["suppressed_findings"][0]["source"] == ".trivyignore"
    assert ".trivyignore" in v["result"]["en"] and ".trivyignore" in v["result"]["pl"]
    write(sample_dir, mapping, ["en", "pl"])
    en = (sample_dir / "evidence-report.md").read_text(encoding="utf-8")
    assert "CVE-2099-0001" in en and "ignore-file (`.trivyignore`)" in en
    assert "/home/runner" not in en  # runner paths are not leaked


def test_vex_only_suppression_keeps_outcome(sample_dir, mapping):  # V018
    vex = dict(IGNORED, Status="not_affected", Statement="vulnerable_code_not_in_execute_path", Source="vex.json")
    rep = {
        "SchemaVersion": 2,
        "Results": [{"Target": "x", "Vulnerabilities": [], "ExperimentalModifiedFindings": [vex]}],
    }
    (sample_dir / "vulnerabilities.trivy.json").write_text(json.dumps(rep))
    v = by_id(build(sample_dir, mapping))["EK-VULN"]
    assert v["outcome"] == "pass"
    assert v["data"]["suppressed"]["vex"] == 1
    assert "VEX: 1" in v["result"]["en"]


def test_trivy_config_in_repo_is_reported(sample_dir, mapping):  # V018
    _set_scan_config(sample_dir, trivy_config=["trivy.yaml"])
    v = by_id(build(sample_dir, mapping))["EK-VULN"]
    assert v["data"]["trivy_config_files_not_applied"] == ["trivy.yaml"]
    assert "trivy.yaml in the repository was not applied" in v["result"]["en"]


def test_gitleaks_allowlist_suppression_is_reported(sample_dir, mapping):  # V018
    (sample_dir / "secrets.gitleaks.json").write_text("[]")  # repo config hid the finding
    _set_scan_config(sample_dir, gitleaks_ignore=[".gitleaksignore"])
    s = by_id(build(sample_dir, mapping))["EK-SECRETS"]
    assert s["outcome"] == "warn"
    assert s["data"]["suppressed_by_repo_config"] == 1
    assert s["data"]["suppressed_locations"][0]["file"] == "config/settings.example.py"
    assert ".gitleaksignore" in s["result"]["en"]


def test_gitleaks_without_baseline_is_noted(sample_dir, mapping):  # V018
    (sample_dir / "secrets.gitleaks.json").write_text("[]")
    (sample_dir / "secrets.gitleaks.baseline.json").unlink()
    _set_scan_config(sample_dir, gitleaks_config=[".gitleaks.toml"])
    s = by_id(build(sample_dir, mapping))["EK-SECRETS"]
    assert s["outcome"] == "pass"
    assert s["data"]["baseline"] == "not-available"
    assert "baseline scan not available" in s["result"]["en"]


def test_step_notes_explain_not_run(sample_dir, mapping):  # V010
    (sample_dir / "sbom.cdx.json").unlink()
    path = sample_dir / "repo-checks.json"
    rc = json.loads(path.read_text())
    rc["meta"]["notes"] = {"tools": "unsupported runner architecture riscv64"}
    path.write_text(json.dumps(rc))
    sbom = by_id(build(sample_dir, mapping))["EK-SBOM"]
    assert sbom["outcome"] == "not-run"
    assert "riscv64" in sbom["result"]["en"]


def test_relation_is_shown(sample_dir, mapping):  # V007
    doc = build(sample_dir, mapping)
    secrets = by_id(doc)["EK-SECRETS"]
    assert {"id": "CRA-13.1", "relation": "supporting"} in secrets["cra"]
    assert {"id": "CRA-I.1.2a", "relation": "supporting"} in by_id(doc)["EK-VULN"]["cra"]
    assert {"id": "CRA-I.2.1", "relation": "direct"} in by_id(doc)["EK-SBOM"]["cra"]
    write(sample_dir, mapping, ["en", "pl"])
    en = (sample_dir / "evidence-report.md").read_text(encoding="utf-8")
    pl = (sample_dir / "evidence-report.pl.md").read_text(encoding="utf-8")
    assert "Annex I, Part I(2)(d) (supporting)" in en
    assert "zał. I część I pkt 2 lit. d (pośrednio)" in pl
    assert "Annex I, Part II(1)<br>" in en  # direct: no mark


def _set_github(sample_dir, github):
    path = sample_dir / "repo-checks.json"
    rc = json.loads(path.read_text())
    rc["github"] = github
    path.write_text(json.dumps(rc))


@pytest.mark.parametrize(
    ("github", "outcome"),
    [
        ({"available": False, "error": "no GITHUB_TOKEN"}, "unknown"),
        ({"available": True, "default_branch": "main", "protected": False, "rules": []}, "fail"),
        ({"available": True, "default_branch": "main", "protected": True, "rules": []}, "warn"),
        ({"available": True, "default_branch": "main", "protected": None, "rules": None}, "unknown"),
        (
            {
                "available": True,
                "default_branch": "main",
                "protected": True,
                "rules": None,
                "classic": {"required_pull_request_reviews": True},
            },
            "pass",
        ),
    ],
)
def test_branch_protection_outcomes(sample_dir, mapping, github, outcome):  # V006
    _set_github(sample_dir, github)
    assert by_id(build(sample_dir, mapping))["EK-BRANCH-PROTECTION"]["outcome"] == outcome


def test_security_txt_expired_fails(sample_dir, mapping):  # V006
    path = sample_dir / "repo-checks.json"
    rc = json.loads(path.read_text())
    rc["files"]["security_txt"][0]["expires_valid"] = False
    path.write_text(json.dumps(rc))
    assert by_id(build(sample_dir, mapping))["EK-SECURITY-TXT"]["outcome"] == "fail"
