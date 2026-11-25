"""Repository hygiene collector.

Looks for security policy files in a checked-out repository and, when a token is
available, reads branch protection / rulesets from the GitHub REST API. Writes a
single JSON document (``repo-checks.json``) that the report generator evaluates.
Standard library only.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from evidence_kit import __version__

# Directories where policy documents are conventionally kept.
DOC_DIRS = (".", ".github", "docs", "doc", "compliance", "security", "policies")
DOC_DEPTH = 3
SKIP_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    ".terraform",
    ".evidence-kit",
    "evidence",
    "dist",
    "build",
}

# security.txt is searched in the whole tree, minus sample/template locations.
SKIP_DIRS_SECURITY_TXT = SKIP_DIRS | {"templates", "tests", "test", "fixtures", "examples"}

SECURITY_MD = ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")
CODEOWNERS = ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS")
DEP_UPDATE_FILES = (
    ".github/dependabot.yml",
    ".github/dependabot.yaml",
    "renovate.json",
    "renovate.json5",
    ".renovaterc",
    ".renovaterc.json",
    ".github/renovate.json",
    ".github/renovate.json5",
    ".gitlab/renovate.json",
)
CVD_NAME = re.compile(r"(cvd|disclosure|ujawnian)", re.I)
CVD_TEXT = re.compile(
    r"(coordinated (vulnerability )?disclosure|disclosure policy|skoordynowan\w* ujawnian)",
    re.I,
)
SUPPLIER_NAME = re.compile(
    r"^(suppliers?|supplier[-_]register|vendors?|dostawcy|rejestr[-_]dostawcow)\.(ya?ml|csv|json|md)$",
    re.I,
)
RUNBOOK_NAME = re.compile(r"(incident|incydent)[\w.-]*\.md$", re.I)


def _walk(root: Path, start: str, depth: int) -> list[Path]:
    base = (root / start).resolve()
    if not base.is_dir():
        return []
    out: list[Path] = []
    stack = [(base, 0)]
    while stack:
        cur, d = stack.pop()
        try:
            entries = sorted(cur.iterdir())
        except OSError:
            continue
        for e in entries:
            if e.is_dir():
                if e.name in SKIP_DIRS or d + 1 > depth:
                    continue
                stack.append((e, d + 1))
            elif e.is_file():
                out.append(e)
    return out


def _doc_files(root: Path) -> list[str]:
    seen: set[str] = set()
    for start in DOC_DIRS:
        depth = 0 if start == "." else DOC_DEPTH  # root: top-level files only
        for p in _walk(root, start, depth):
            seen.add(p.relative_to(root.resolve()).as_posix())
    return sorted(seen)


def _existing(root: Path, candidates: tuple[str, ...]) -> list[str]:
    return [c for c in candidates if (root / c).is_file()]


def _read(root: Path, rel: str, limit: int = 200_000) -> str:
    try:
        return (root / rel).read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def find_security_txt(root: Path) -> list[str]:
    found: list[str] = []
    rroot = root.resolve()
    for dirpath, dirnames, filenames in os.walk(rroot):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS_SECURITY_TXT]
        if "security.txt" in filenames:
            rel = (Path(dirpath) / "security.txt").relative_to(rroot).as_posix()
            if rel == "security.txt" or rel.endswith(".well-known/security.txt"):
                found.append(rel)
    return sorted(found)


def parse_security_txt(text: str, now: dt.datetime | None = None) -> dict[str, Any]:
    """Parse RFC 9116 fields that matter for evidence (Contact, Expires, Policy)."""
    now = now or dt.datetime.now(dt.timezone.utc)
    fields: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        fields.setdefault(key.strip().lower(), []).append(value.strip())
    expires_raw = (fields.get("expires") or [None])[0]
    expires_ok = None
    if expires_raw:
        try:
            exp = dt.datetime.fromisoformat(expires_raw.replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=dt.timezone.utc)
            expires_ok = exp > now
        except ValueError:
            expires_ok = False
    return {
        "contact": fields.get("contact", []),
        "expires": expires_raw,
        "expires_valid": expires_ok,
        "policy": fields.get("policy", []),
        "preferred_languages": (fields.get("preferred-languages") or [None])[0],
    }


def _codeowners_rules(text: str) -> int:
    return sum(1 for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#"))


# --------------------------------------------------------------------------- API


def _api_get(url: str, token: str, timeout: int = 20) -> tuple[int, Any]:
    if not url.startswith("https://"):
        return 0, None
    req = urllib.request.Request(  # noqa: S310 (scheme checked above)
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": f"evidence-kit/{__version__}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https only)
            return resp.status, json.loads(resp.read().decode("utf-8") or "null")
    except urllib.error.HTTPError as e:
        return e.code, None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return 0, None


def collect_github(repo: str, token: str, api: str = "https://api.github.com") -> dict[str, Any]:
    """Read default-branch protection signals. Every failure is recorded, never raised."""
    if not api.startswith("https://"):
        return {"available": False, "error": "API URL must use https"}
    out: dict[str, Any] = {"available": False, "repository": repo}
    code, meta = _api_get(f"{api}/repos/{repo}", token)
    out["repo_status"] = code
    if code != 200 or not isinstance(meta, dict):
        out["error"] = f"GET /repos/{repo} returned {code}"
        return out
    out["available"] = True
    branch = meta.get("default_branch") or "main"
    out["default_branch"] = branch
    out["visibility"] = meta.get("visibility")

    code, br = _api_get(f"{api}/repos/{repo}/branches/{branch}", token)
    out["branch_status"] = code
    out["protected"] = bool(br.get("protected")) if code == 200 and isinstance(br, dict) else None

    code, rules = _api_get(f"{api}/repos/{repo}/rules/branches/{branch}", token)
    out["rules_status"] = code
    if code == 200 and isinstance(rules, list):
        out["rules"] = sorted({r.get("type", "?") for r in rules if isinstance(r, dict)})
    else:
        out["rules"] = None

    # Classic protection details need admin rights; GITHUB_TOKEN usually gets 403/404.
    code, prot = _api_get(f"{api}/repos/{repo}/branches/{branch}/protection", token)
    out["protection_status"] = code
    if code == 200 and isinstance(prot, dict):
        out["classic"] = {
            "required_pull_request_reviews": bool(prot.get("required_pull_request_reviews")),
            "required_status_checks": bool(prot.get("required_status_checks")),
            "enforce_admins": bool((prot.get("enforce_admins") or {}).get("enabled")),
            "allow_force_pushes": bool((prot.get("allow_force_pushes") or {}).get("enabled")),
            "allow_deletions": bool((prot.get("allow_deletions") or {}).get("enabled")),
        }

    code, pvr = _api_get(f"{api}/repos/{repo}/private-vulnerability-reporting", token)
    out["private_vulnerability_reporting"] = bool(pvr.get("enabled")) if code == 200 and isinstance(pvr, dict) else None
    return out


# --------------------------------------------------------------------------- main


def collect(root: Path, env: dict[str, str] | None = None) -> dict[str, Any]:
    env = dict(os.environ if env is None else env)
    root = Path(root)
    docs = _doc_files(root)

    security_md = _existing(root, SECURITY_MD)
    sec_text = _read(root, security_md[0]) if security_md else ""
    contact_in_policy = bool(re.search(r"[\w.+-]+@[\w-]+\.[\w.]+|security\.txt|/security/advisories", sec_text))

    cvd_files = [d for d in docs if d.lower().endswith(".md") and CVD_NAME.search(Path(d).name)]
    cvd_in_security_md = bool(CVD_TEXT.search(sec_text))

    sec_txt_paths = find_security_txt(root)
    sec_txt = [{"path": p, **parse_security_txt(_read(root, p))} for p in sec_txt_paths]

    codeowners = _existing(root, CODEOWNERS)
    co_rules = _codeowners_rules(_read(root, codeowners[0])) if codeowners else 0

    suppliers = [d for d in docs if SUPPLIER_NAME.match(Path(d).name)]
    runbooks = [d for d in docs if RUNBOOK_NAME.search(Path(d).name)]

    result: dict[str, Any] = {
        "schema": "evidence-kit/repo-checks/v1",
        "collected_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "files": {
            "security_policy": {"paths": security_md, "contact_found": contact_in_policy},
            "cvd_policy": {"paths": cvd_files, "section_in_security_md": cvd_in_security_md},
            "security_txt": sec_txt,
            "codeowners": {"paths": codeowners, "rules": co_rules},
            "dependency_updates": {"paths": _existing(root, DEP_UPDATE_FILES)},
            "supplier_register": {"paths": suppliers},
            "incident_runbook": {"paths": runbooks},
        },
        "meta": {
            "kit_version": __version__,
            "repository": env.get("GITHUB_REPOSITORY", ""),
            "commit": env.get("GITHUB_SHA", ""),
            "ref": env.get("GITHUB_REF", ""),
            "run_url": (
                f"{env['GITHUB_SERVER_URL']}/{env['GITHUB_REPOSITORY']}/actions/runs/{env['GITHUB_RUN_ID']}"
                if env.get("GITHUB_SERVER_URL") and env.get("GITHUB_RUN_ID") and env.get("GITHUB_REPOSITORY")
                else ""
            ),
            "tools": {
                "trivy": env.get("EK_TRIVY_VERSION", ""),
                "gitleaks": env.get("EK_GITLEAKS_VERSION", ""),
                "scorecard_action": env.get("EK_SCORECARD_VERSION", ""),
            },
            "vex_file": env.get("EK_VEX_FILE", ""),
            "scorecard_enabled": env.get("EK_SCORECARD_ENABLED", ""),
        },
    }

    token = env.get("GITHUB_TOKEN") or env.get("GH_TOKEN") or ""
    repo = env.get("GITHUB_REPOSITORY", "")
    if token and repo:
        result["github"] = collect_github(repo, token, env.get("GITHUB_API_URL", "https://api.github.com"))
    else:
        result["github"] = {"available": False, "error": "no GITHUB_TOKEN or GITHUB_REPOSITORY"}
    return result
