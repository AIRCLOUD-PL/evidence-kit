import copy
import json
from pathlib import Path

import yaml

from evidence_kit import cli
from evidence_kit.checks import EVALUATORS
from evidence_kit.mapping import validate

ROOT = Path(__file__).resolve().parent.parent


def test_mapping_is_valid(mapping):  # V007
    assert validate(mapping) == []


def test_every_control_maps_to_law(mapping):  # V007
    for c in mapping["controls"]:
        assert c["status"] in ("auto", "manual")
        assert c.get("ksc") or c.get("cra"), c["id"]
        if c["status"] == "auto":
            assert c["check"] in EVALUATORS
            assert c["evidence"]


def test_all_evaluators_are_used(mapping):  # V007
    used = {c.get("check") for c in mapping["controls"] if c["status"] == "auto"}
    assert used == set(EVALUATORS)


def test_references_cover_ksc_art8_and_cra_annex1(mapping):  # V007
    refs = mapping["references"]
    letters = "abcdefghijklmn"
    for letter in letters:  # KSC art. 8 ust. 1 pkt 2 lit. a-n
        assert f"KSC-8.1.2{letter}" in refs
    for n in range(1, 9):  # CRA Annex I Part II(1)-(8)
        assert f"CRA-I.2.{n}" in refs
    assert refs["KSC-11.1.4"]["cite"] == "art. 11 ust. 1 pkt 4-4c"
    assert refs["CRA-14"]["cite"] == "Art. 14(1)-(4)"


def test_validate_catches_errors(mapping):  # V007
    bad = copy.deepcopy(mapping)
    bad["controls"][0]["ksc"] = ["KSC-99"]
    bad["controls"][1]["status"] = "maybe"
    bad["controls"].append(copy.deepcopy(bad["controls"][2]))
    del bad["disclaimer"]["pl"]
    problems = "\n".join(validate(bad))
    assert "unknown reference KSC-99" in problems
    assert "status must be auto or manual" in problems
    assert "duplicate id" in problems
    assert "disclaimer.pl" in problems


def test_cli_validate_and_report(tmp_path, capsys):  # V007, V008
    assert cli.main(["validate", str(ROOT / "mappings" / "controls.yaml")]) == 0
    ev = tmp_path / "ev"
    ev.mkdir()
    for p in (ROOT / "tests" / "fixtures" / "sample").iterdir():
        (ev / p.name).write_bytes(p.read_bytes())
    assert cli.main(["report", "--evidence-dir", str(ev), "--lang", "pl"]) == 0
    assert (ev / "evidence-report.pl.md").is_file()
    assert not (ev / "evidence-report.md").exists()
    assert cli.main(["report", "--evidence-dir", str(ev), "--lang", "de"]) == 2


def test_cli_validate_rejects_bad_file(tmp_path):  # V007
    m = yaml.safe_load((ROOT / "mappings" / "controls.yaml").read_text(encoding="utf-8"))
    m["controls"][0]["check"] = "nope"
    p = tmp_path / "m.yaml"
    p.write_text(yaml.safe_dump(m, allow_unicode=True), encoding="utf-8")
    assert cli.main(["validate", str(p)]) == 1


def _doc(sample_dir, mapping):
    from evidence_kit.report import build

    return build(sample_dir, mapping)


def test_gate(sample_dir, mapping):  # V011
    doc = _doc(sample_dir, mapping)
    assert cli.gate(doc, "none", False) == []
    assert cli.gate(doc, "critical", False) == []
    assert cli.gate(doc, "high", False) and "HIGH" in cli.gate(doc, "high", False)[0]
    assert cli.gate(doc, "none", True) == ["1 potential secret(s) in git history"]


def test_gate_fails_when_scan_missing(tmp_path, mapping):  # V011
    empty = tmp_path / "e"
    empty.mkdir()
    from evidence_kit.report import build

    doc = build(empty, mapping)
    reasons = cli.gate(doc, "high", True)
    assert "vulnerability scan did not run" in reasons
    assert "secret scan did not run" in reasons


def test_cli_gate_exit_codes(sample_dir, mapping):  # V011
    from evidence_kit.report import write

    write(sample_dir, mapping, ["en"])
    ev = str(sample_dir / "evidence.json")
    assert cli.main(["gate", "--evidence", ev]) == 0
    assert cli.main(["gate", "--evidence", ev, "--fail-on", "critical"]) == 0
    assert cli.main(["gate", "--evidence", ev, "--fail-on", "high"]) == 1
    assert cli.main(["gate", "--evidence", ev, "--fail-on-secrets"]) == 1
    json.loads(Path(ev).read_text())  # still valid JSON after gate
