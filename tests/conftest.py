import shutil
from pathlib import Path

import pytest

from evidence_kit.mapping import load

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
MAPPING = ROOT / "mappings" / "controls.yaml"


@pytest.fixture(scope="session")
def mapping():
    return load(MAPPING)


@pytest.fixture
def sample_dir(tmp_path: Path) -> Path:
    """A writable copy of the sample evidence bundle."""
    dst = tmp_path / "evidence"
    shutil.copytree(FIXTURES / "sample", dst)
    return dst


@pytest.fixture(autouse=True)
def _fixed_clock(monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1795564800")  # 2026-11-25T00:00:00Z
