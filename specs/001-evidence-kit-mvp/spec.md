# Feature Specification: evidence-kit MVP (v0.1)

**Feature Branch**: `001-evidence-kit-mvp`
**Created**: 2026-11-25
**Status**: Implemented (v0.1.0)
**Input**: "A free, open-source GitHub workflow that produces technical evidence of secure
software supply-chain practices, mapped (informatively) to the Polish KSC act (NIS2
transposition, Dz.U. 2026 poz. 252) and the EU Cyber Resilience Act (Regulation (EU)
2024/2847)."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - One-line evidence bundle (Priority: P1)
A maintainer of a GitHub repository adds a 10-line caller workflow. Each run produces an
`evidence` artifact with an SBOM, vulnerability scan, secret scan, OpenSSF Scorecard result,
repository hygiene checks, and a bilingual report that maps every result to KSC art. 8 / 11
and CRA Annex I / Art. 13-14.

**Why this priority**: this is the product; without it nothing else matters.

**Independent Test**: run the reusable workflow on this repository (self-check) and download
the artifact.

**Acceptance Scenarios**:
1. **Given** a repository with a lock file, **When** the workflow runs, **Then** the artifact
   contains `sbom.cdx.json`, `vulnerabilities.trivy.json`, `secrets.gitleaks.json`,
   `repo-checks.json`, `evidence.json`, `evidence-report.md`, `evidence-report.pl.md`.
2. **Given** no secrets or API access, **When** the workflow runs, **Then** it still succeeds
   and marks API-dependent controls as `unknown`, not `pass`.

### User Story 2 - Honest report for a compliance conversation (Priority: P1)
A security officer opens `evidence-report.md` (or `.pl.md`) and sees, per control: outcome,
short result, the KSC and CRA provisions it supports, and which controls need manual
evidence (risk assessment, BCP, training, audit).

**Independent Test**: generate the report from `tests/fixtures/` and read it.

### User Story 3 - Policy templates (Priority: P2)
The maintainer copies SECURITY.md, a CVD policy, security.txt, an incident and
vulnerability reporting runbook and a supplier register (PL and EN) and the next run turns
the related controls from `fail`/`manual` to `pass`.

### Edge Cases
- Tool output missing (step failed or disabled) -> control `not-run`, report still produced.
- Malformed JSON from a tool -> control `not-run` with the parse error in details.
- Scorecard disabled or the repository is private -> `not-run` / partial result.
- Branch protection not readable with `GITHUB_TOKEN` -> `unknown`.
- `security.txt` present but `Expires` in the past -> `fail`.

## Requirements *(mandatory)*

### Functional Requirements
- **FR-001**: The repository MUST provide a reusable workflow `.github/workflows/evidence.yml`
  (`on: workflow_call`) with documented inputs and least-privilege permissions, plus an
  example caller in `examples/`. `kit-ref` MUST be required and validated as a full 40-hex
  commit SHA; optional third-party telemetry (harden-runner) MUST be opt-in.
- **FR-002**: The workflow MUST generate a CycloneDX JSON SBOM of the caller repository
  (Trivy, filesystem mode).
- **FR-003**: The workflow MUST scan the SBOM for known vulnerabilities (Trivy) and MUST
  accept an optional VEX document that is applied to the scan.
- **FR-004**: The workflow MUST scan the full git history for secrets with the gitleaks CLI,
  downloaded with a pinned version and verified SHA-256, with redacted output.
- **FR-005**: The workflow MUST run OpenSSF Scorecard (JSON, `publish_results: false`) unless
  disabled by input; a Scorecard failure MUST NOT block the report.
- **FR-006**: A collector MUST check the repository for: SECURITY.md, a CVD policy,
  `security.txt` (with `Contact` and a future `Expires`, RFC 9116), CODEOWNERS, a dependency
  update tool config, a supplier register, an incident/vulnerability reporting runbook,
  and - via the GitHub API when reachable - default-branch protection or rulesets.
- **FR-007**: `mappings/controls.yaml` MUST map every control to KSC and CRA references with
  fields `evidence` and `status` (`auto`|`manual`), and MUST carry the disclaimer and source
  URLs. References MUST be resolvable to a label (no free-text citations in controls). Each
  reference has a `relation` (`direct`|`supporting`) shown in the report.
- **FR-008**: The generator MUST produce `evidence-report.md` (EN) and `evidence-report.pl.md`
  (PL) from tool outputs + mapping, including a summary, per-control results, manual controls,
  evidence file hashes and sources.
- **FR-009**: The generator MUST produce `evidence.json` (schema `evidence-kit/v1`) with
  per-control outcome, data and the SHA-256 of every evidence file.
- **FR-010**: Outcomes MUST be one of `pass`, `warn`, `fail`, `unknown`, `not-run`, `manual`;
  missing or malformed inputs MUST never produce `pass`.
- **FR-011**: A gate command MUST fail the job (exit 1) on a configurable vulnerability
  severity threshold and optionally on secrets, *after* the evidence artifact is uploaded.
  Default: report-only.
- **FR-012**: Every report, `evidence.json` and the README MUST include the disclaimer:
  informative mapping, not legal advice or certification, the statutory KSC audit is performed
  by an authorised auditor.
- **FR-013**: `templates/` MUST contain PL and EN versions of SECURITY.md, CVD policy,
  security.txt, incident and vulnerability reporting runbook (KSC art. 11 and CRA art. 14
  deadlines as published), and a supplier register (CSV and YAML).
- **FR-014**: README MUST have EN first and a PL section: purpose, 5-minute quick start, what it
  proves / does not prove, control list, example report, "Built on", "Need help? AIRCLOUD".
- **FR-015**: The kit's own CI MUST lint (ruff, actionlint), run pytest, and run the evidence
  workflow on this repository (self-check).
- **FR-016**: All third-party actions MUST be pinned to a full commit SHA with a version
  comment, without known advisories at the pinned version; downloaded binaries (Trivy, gitleaks,
  actionlint) MUST be verified against SHA-256 values pinned in the repository; CI MUST run zizmor.
- **FR-017**: Code from the scanned repository MUST NOT be executed by kit steps: the kit runs
  from `$RUNNER_TEMP` with `python3 -P`, and user inputs are validated and never written to
  `GITHUB_ENV`. A test MUST show that a malicious `evidence_kit/` in the scanned repository cannot
  replace the gate.
- **FR-018**: Suppressions MUST be visible: Trivy always runs with `--show-suppressed`; findings
  suppressed by VEX, ignore files or other sources are listed per source; a repository
  `trivy.yaml` is not applied and is reported; gitleaks findings hidden by `.gitleaks.toml` /
  `.gitleaksignore` are revealed by a baseline scan. Suppression without a justification
  (ignore file, gitleaks allowlist) MUST make the control at least `warn`.

### Key Entities
- **Control**: id, title (en/pl), `status` auto|manual, `check` (evaluator name), `evidence`
  files, `ksc`/`cra`/`osps` reference ids, manual evidence hint.
- **Reference**: id, citation (e.g. "art. 8 ust. 1 pkt 2 lit. e"), short label en/pl, source.
- **Evidence bundle**: directory `evidence/` with tool outputs, `evidence.json`, reports.

## Success Criteria *(mandatory)*
- **SC-001**: A new user gets the first evidence artifact in under 5 minutes of setup.
- **SC-002**: Self-check run on this repository is green and the report has 0 `fail` for
  repository hygiene controls.
- **SC-003**: 100% of FR have a passing V### in `verify.md`.

## Assumptions
- Target is GitHub-hosted runners (`ubuntu-24.04`); other CI systems can run the CLI locally.
- The kit does not decide whether an organisation is a KSC "podmiot kluczowy/ważny" or a CRA
  "manufacturer"; it only collects evidence.
- KSC references follow the act of 5 July 2018 (t.j. Dz.U. 2026 poz. 20) as amended by the act
  of 23 January 2026 (Dz.U. 2026 poz. 252, in force 3 April 2026; chapter 3 duties within 12
  months, art. 33 ust. 1 of the amending act). Later amendments Dz.U. 2026 poz. 815, 1003, 1206
  do not change the cited provisions. CRA dates: art. 14 from 11 September 2026, the rest from
  11 December 2027 (art. 71(2)).
