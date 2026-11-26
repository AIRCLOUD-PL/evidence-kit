import datetime as dt
from pathlib import Path

from evidence_kit import collect as col


def _write(root: Path, rel: str, text: str = "x\n") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_collect_finds_policy_files(tmp_path):  # V006
    _write(
        tmp_path, "SECURITY.md", "# Security\nReport to security@example.com\n## Coordinated vulnerability disclosure\n"
    )
    _write(tmp_path, ".well-known/security.txt", "Contact: mailto:a@example.com\nExpires: 2099-01-01T00:00:00Z\n")
    _write(tmp_path, ".github/CODEOWNERS", "# owners\n* @example/team\n")
    _write(tmp_path, ".github/dependabot.yml", "version: 2\n")
    _write(tmp_path, "docs/suppliers.yaml")
    _write(tmp_path, "docs/security/incident-and-vulnerability-reporting.md")
    _write(tmp_path, "docs/cvd-policy.md")
    data = col.collect(tmp_path, env={})
    f = data["files"]
    assert f["security_policy"] == {"paths": ["SECURITY.md"], "contact_found": True}
    assert f["cvd_policy"]["paths"] == ["docs/cvd-policy.md"]
    assert f["cvd_policy"]["section_in_security_md"] is True
    assert f["security_txt"][0]["path"] == ".well-known/security.txt"
    assert f["security_txt"][0]["expires_valid"] is True
    assert f["codeowners"] == {"paths": [".github/CODEOWNERS"], "rules": 1}
    assert f["dependency_updates"]["paths"] == [".github/dependabot.yml"]
    assert f["supplier_register"]["paths"] == ["docs/suppliers.yaml"]
    assert f["incident_runbook"]["paths"] == ["docs/security/incident-and-vulnerability-reporting.md"]
    assert data["github"]["available"] is False


def test_collect_polish_file_names(tmp_path):  # V006
    _write(tmp_path, "docs/polityka-cvd.md")
    _write(tmp_path, "docs/dostawcy.csv")
    _write(tmp_path, "docs/incydenty-i-podatnosci-zglaszanie.md")
    f = col.collect(tmp_path, env={})["files"]
    assert f["cvd_policy"]["paths"] == ["docs/polityka-cvd.md"]
    assert f["supplier_register"]["paths"] == ["docs/dostawcy.csv"]
    assert f["incident_runbook"]["paths"] == ["docs/incydenty-i-podatnosci-zglaszanie.md"]


def test_templates_and_tests_are_not_evidence(tmp_path):  # V006
    _write(tmp_path, "templates/en/security.txt", "Contact: x\nExpires: 2099-01-01T00:00:00Z\n")
    _write(tmp_path, "templates/en/suppliers.yaml")
    _write(tmp_path, "tests/fixtures/.well-known/security.txt", "Contact: x\n")
    _write(tmp_path, "node_modules/pkg/docs/incident.md")
    f = col.collect(tmp_path, env={})["files"]
    assert f["security_txt"] == []
    assert f["supplier_register"]["paths"] == []
    assert f["incident_runbook"]["paths"] == []


def test_empty_repo(tmp_path):  # V006
    f = col.collect(tmp_path, env={})["files"]
    assert f["security_policy"]["paths"] == []
    assert f["codeowners"] == {"paths": [], "rules": 0}


def test_parse_security_txt():  # V006
    now = dt.datetime(2026, 11, 25, tzinfo=dt.UTC)
    ok = col.parse_security_txt("# c\nContact: mailto:a@b.pl\nExpires: 2027-01-01T00:00:00Z\n", now)
    assert ok["contact"] == ["mailto:a@b.pl"] and ok["expires_valid"] is True
    old = col.parse_security_txt("Contact: x\nExpires: 2026-01-01T00:00:00Z\n", now)
    assert old["expires_valid"] is False
    bad = col.parse_security_txt("Contact: x\nExpires: next year\n", now)
    assert bad["expires_valid"] is False
    none = col.parse_security_txt("Contact: x\n", now)
    assert none["expires_valid"] is None


def test_meta_from_env(tmp_path):  # V009
    env = {
        "GITHUB_REPOSITORY": "o/r",
        "GITHUB_SHA": "abc",
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_RUN_ID": "42",
        "EK_TRIVY_VERSION": "v0.70.0",
    }
    meta = col.collect(tmp_path, env=env)["meta"]
    assert meta["run_url"] == "https://github.com/o/r/actions/runs/42"
    assert meta["tools"]["trivy"] == "v0.70.0"


def test_collect_github_with_fake_api(monkeypatch):  # V006
    responses = {
        "/repos/o/r": (200, {"default_branch": "main", "visibility": "public"}),
        "/repos/o/r/branches/main": (200, {"protected": True}),
        "/repos/o/r/rules/branches/main": (200, [{"type": "pull_request"}, {"type": "deletion"}]),
        "/repos/o/r/branches/main/protection": (403, None),
        "/repos/o/r/private-vulnerability-reporting": (200, {"enabled": True}),
    }

    def fake(url, token, timeout=20):
        return responses[url.removeprefix("https://api.github.com")]

    monkeypatch.setattr(col, "_api_get", fake)
    gh = col.collect_github("o/r", "t")
    assert gh["available"] is True
    assert gh["protected"] is True
    assert gh["rules"] == ["deletion", "pull_request"]
    assert "classic" not in gh
    assert gh["private_vulnerability_reporting"] is True


def test_collect_github_unreachable(monkeypatch):  # V006
    monkeypatch.setattr(col, "_api_get", lambda url, token, timeout=20: (0, None))
    gh = col.collect_github("o/r", "t")
    assert gh["available"] is False and "error" in gh


def test_collect_github_rejects_plain_http():  # V006
    assert col.collect_github("o/r", "t", api="http://example.com")["available"] is False
