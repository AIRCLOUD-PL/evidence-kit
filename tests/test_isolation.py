"""FR-017: the scanned repository is data, never code.

A scanned repository can contain its own ``evidence_kit/`` package. If the kit were run
with plain ``python -m`` from the repository directory, Python would import that package
first (the current directory goes to the front of ``sys.path``) and the attacker could
replace the gate. The workflow runs ``python3 -P`` from ``$RUNNER_TEMP``; this test
reproduces the attack and checks that the invocation used in the workflow resists it.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from evidence_kit.report import write

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "evidence.yml"

needs_safe_path = pytest.mark.skipif(sys.version_info < (3, 11), reason="python -P needs 3.11+")


def _malicious_repo(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "scanned-repo"
    pkg = repo / "evidence_kit"
    pkg.mkdir(parents=True)
    marker = tmp_path / "pwned"
    (pkg / "__init__.py").write_text("")
    (pkg / "__main__.py").write_text(f"open({str(marker)!r}, 'w').write('x')\nraise SystemExit(0)\n")
    return repo, marker


def _gate(cwd: Path, evidence: Path, safe: bool) -> subprocess.CompletedProcess:
    cmd = [sys.executable, *(["-P"] if safe else []), "-m", "evidence_kit", "gate"]
    cmd += ["--evidence", str(evidence), "--fail-on", "high"]
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONSAFEPATH", "PYTHONPATH")}
    env["PYTHONPATH"] = str(ROOT)  # absolute path to the kit, as in the workflow
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=60)


@needs_safe_path
def test_malicious_evidence_kit_in_scanned_repo_cannot_replace_gate(tmp_path, sample_dir, mapping):  # V017
    write(sample_dir, mapping, ["en"])  # sample has 7 HIGH vulnerabilities -> gate must fail
    evidence = sample_dir / "evidence.json"
    repo, marker = _malicious_repo(tmp_path)

    # The attack works against a naive invocation (proves the test is meaningful).
    naive = _gate(repo, evidence, safe=False)
    assert naive.returncode == 0 and marker.exists()
    marker.unlink()

    # The workflow invocation: python -P, even with the repository as working directory.
    safe = _gate(repo, evidence, safe=True)
    assert safe.returncode == 1, safe.stderr
    assert "HIGH" in safe.stderr
    assert not marker.exists()


def test_workflow_never_runs_kit_code_from_the_scanned_repo():  # V017
    wf = yaml.safe_load(WORKFLOW.read_text())
    steps = wf["jobs"]["evidence"]["steps"]
    python_steps = [s for s in steps if re.search(r"\bpython3?\b|/bin/python", s.get("run", ""))]
    assert python_steps, "expected python steps"
    for s in python_steps:
        assert s.get("working-directory") == "${{ runner.temp }}", s["name"]
        for line in s["run"].splitlines():
            if "-m evidence_kit" in line or "-m pip" in line or " -c " in line:
                assert re.search(r"python3? -P |python\" -P ", line), f"{s['name']}: {line.strip()}"
            assert ".evidence-kit" not in line, "kit must run from $RUNNER_TEMP, not the workspace"
    prepare = next(s for s in steps if s.get("name") == "Prepare")
    assert 'mv .evidence-kit "${RUNNER_TEMP}/evidence-kit"' in prepare["run"]


def test_trivy_never_uses_repository_config():  # V017, V018
    text = WORKFLOW.read_text()
    trivy_calls = re.findall(r'"\$\{EK_BIN\}/trivy" "\$\{args\[@\]\}"', text)
    assert len(trivy_calls) == 2
    assert text.count('--config "${RUNNER_TEMP}/ek-trivy.yaml"') == 2
    assert "--show-suppressed" in text
    assert "--gitleaks-ignore-path" in text and "--mirror" in text
