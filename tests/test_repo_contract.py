"""Checks on the repository itself: workflows, templates, README (FR-001, 012-016)."""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
SHA_PIN = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)@([0-9a-f]{40})\s+#\s*v\d", re.M)
ANY_USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.M)


def test_reusable_workflow_contract():  # V001
    wf = yaml.safe_load((ROOT / ".github/workflows/evidence.yml").read_text())
    on = wf.get("on") or wf.get(True)  # PyYAML parses bare `on` as True
    inputs = on["workflow_call"]["inputs"]
    for name in ("kit-ref", "vex-file", "run-scorecard", "fail-on", "fail-on-secrets", "lang", "scan-path"):
        assert name in inputs, name
    # kit-ref: required full SHA, no mutable default (GHSA-69fq-xp46-6x23 lesson)
    assert inputs["kit-ref"]["required"] is True and "default" not in inputs["kit-ref"]
    assert inputs["kit-repository"]["default"] == "AIRCLOUD-PL/evidence-kit"
    # harden-runner is opt-in (telemetry to StepSecurity, paid for private repos)
    assert inputs["harden-runner"]["default"] is False
    assert wf["permissions"] == {"contents": "read"}
    job = wf["jobs"]["evidence"]
    assert job["permissions"] == {"contents": "read", "actions": "read"}
    names = [s.get("name", "") for s in job["steps"]]
    harden = next(s for s in job["steps"] if "harden-runner" in s.get("uses", ""))
    assert harden["if"] == "inputs.harden-runner"
    validate = next(s for s in job["steps"] if s.get("name") == "Validate inputs")
    assert "^[0-9a-f]{40}$" in validate["run"]
    assert names.index("Validate inputs") < names.index("Checkout evidence-kit")
    assert "GITHUB_ENV" not in validate["run"]  # user input never reaches GITHUB_ENV
    upload = names.index("Upload evidence bundle")
    gate = names.index("Gate")
    assert upload < gate, "gate must run after the artifact upload"
    assert job["steps"][upload]["if"] == "always()"
    text = (ROOT / ".github/workflows/evidence.yml").read_text()
    assert "sha256sum --check --strict" in text  # V016 gitleaks binary verified
    assert "--require-hashes" in text
    assert "publish_results: false" in text


def test_all_actions_pinned_to_sha():  # V016
    for wf in WORKFLOWS:
        text = wf.read_text()
        for m in ANY_USES.finditer(text):
            target = m.group(1)
            if target.startswith("./"):
                continue
            assert SHA_PIN.search(text[m.start() : m.end() + 80]), f"{wf.name}: {target} not pinned to SHA"


def test_no_workflow_requests_write_by_default():  # V001, V016
    for wf in WORKFLOWS:
        doc = yaml.safe_load(wf.read_text())
        assert doc["permissions"] == {"contents": "read"}, wf.name


def test_owner_is_aircloud_pl():  # V014
    skip = {".git", ".venv", "venv", "node_modules", ".ruff_cache", ".pytest_cache", "__pycache__"}
    old_owner = "lkolo-prez" + "/evidence-kit"
    hits = []
    for p in ROOT.rglob("*"):
        if skip & set(p.relative_to(ROOT).parts) or not p.is_file():
            continue
        if p.suffix in {".md", ".yml", ".yaml", ".py", ".txt", ".toml", ".json"}:
            if old_owner in p.read_text(encoding="utf-8", errors="ignore"):
                hits.append(str(p.relative_to(ROOT)))
    assert hits == [], hits


def test_examples_use_sha_placeholder():  # V001, V016
    ex = (ROOT / "examples/evidence-caller.yml").read_text()
    assert "evidence.yml@<FULL_COMMIT_SHA_OF_v0.1.0>" in ex
    assert "kit-ref: <FULL_COMMIT_SHA_OF_v0.1.0>" in ex
    assert "gh api repos/AIRCLOUD-PL/evidence-kit/commits/v0.1.0 --jq .sha" in ex
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "evidence.yml@v0.1.0" not in readme and "kit-ref: v0.1.0" not in readme


def test_self_check_uses_local_workflow():  # V015
    wf = yaml.safe_load((ROOT / ".github/workflows/self-check.yml").read_text())
    job = wf["jobs"]["evidence"]
    assert job["uses"] == "./.github/workflows/evidence.yml"
    assert job["with"]["kit-ref"] == "${{ github.sha }}"


def test_templates_exist_in_both_languages():  # V013
    t = ROOT / "templates"
    for en, pl in [
        ("SECURITY.md", "SECURITY.md"),
        ("cvd-policy.md", "polityka-cvd.md"),
        ("security.txt", "security.txt"),
        ("incident-and-vulnerability-reporting.md", "incydenty-i-podatnosci-zglaszanie.md"),
        ("suppliers.yaml", "dostawcy.yaml"),
        ("suppliers.csv", "dostawcy.csv"),
    ]:
        assert (t / "en" / en).is_file(), en
        assert (t / "pl" / pl).is_file(), pl
    for f in ("en/suppliers.yaml", "pl/dostawcy.yaml"):
        assert yaml.safe_load((t / f).read_text(encoding="utf-8"))["suppliers"]
    own = yaml.safe_load((ROOT / "docs/suppliers.yaml").read_text(encoding="utf-8"))["suppliers"]
    assert any("StepSecurity" in s["name"] for s in own)  # optional data recipient is declared


def test_runbook_deadlines_match_sources():  # V013
    pl = (ROOT / "templates/pl/incydenty-i-podatnosci-zglaszanie.md").read_text(encoding="utf-8")
    en = (ROOT / "templates/en/incident-and-vulnerability-reporting.md").read_text(encoding="utf-8")
    for needle in (
        "24 h od wykrycia",
        "72 h od wykrycia",
        "w ciągu miesiąca od dnia zgłoszenia",
        "art. 11 ust. 1 pkt 4c",
    ):
        assert needle in pl, needle
    for needle in (
        "14 dni od udostępnienia środka",
        "art. 14 ust. 2 lit. c",
        "w ciągu miesiąca od zgłoszenia incydentu",
    ):
        assert needle in pl, needle
    for needle in ("24 h after detection", "72 h after detection", "14 days after a corrective", "Art. 14(4)(c)"):
        assert needle in en, needle


def test_readme_sections_and_disclaimer():  # V012, V014
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    for needle in (
        "## Quick start",
        "## What it proves",
        "## What it does not prove",
        "## Controls",
        "## Example report",
        "## Built on",
        "## Need help? AIRCLOUD",
        "## Po polsku",
        "not legal advice",
        "nie jest porada prawna",
        "https://aircloud.com.pl/consulting/?from=evidence-kit",
        "`kit-repository`",
        "`harden-runner`",
        "`summary`",
        "## Updating pinned tools",
    ):
        assert needle in text, needle
    assert text.index("## Quick start") < text.index("## Po polsku")


def test_no_secrets_or_real_contacts_in_fixtures():  # V004 (constitution VII)
    for p in (ROOT / "tests/fixtures").rglob("*"):
        if p.is_file():
            text = p.read_text(encoding="utf-8")
            emails = set(re.findall(r"[\w.+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}", text))
            assert emails <= {"dev@example.com", "security@example.com"}, (p, emails)
