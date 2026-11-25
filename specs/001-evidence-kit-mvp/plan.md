# Implementation Plan: evidence-kit MVP (v0.1)

**Spec**: [spec.md](spec.md) · **Date**: 2026-11-25

## Summary
A GitHub reusable workflow composes Trivy, gitleaks and OpenSSF Scorecard, a small Python
collector checks repository hygiene, and a report generator joins tool outputs with a YAML
mapping to produce `evidence.json` and EN/PL Markdown reports.

## Technical context
- **Runtime**: GitHub-hosted `ubuntu-24.04`, system `python3` (3.12). Locally Python >= 3.10.
- **Dependencies**: PyYAML only (hash-pinned `requirements.txt`); dev: pytest, ruff (hash-pinned).
- **Tools composed**: aquasecurity/trivy-action v0.36.0 (SHA) with Trivy v0.70.0, gitleaks CLI
  8.30.1 (SHA-256), ossf/scorecard-action v2.6.0 (SHA), harden-runner, checkout, upload-artifact.
- **Testing**: pytest on fixtures generated with real Trivy output (`tests/fixtures/sample`).

## Decisions (ADR-style)
1. **Trivy for SBOM and vulnerabilities** instead of Syft + Grype/OSV: one pinned tool, native
   CycloneDX and VEX (OpenVEX / CycloneDX / CSAF). Syft and OSV-Scanner stay as alternatives.
2. **gitleaks CLI instead of gitleaks-action**: the action needs a paid licence for organisation
   accounts; the CLI is MIT. Pattern reused from AIRCLOUD `00-engineering-standards`.
3. **Reusable workflow + kit checkout at `kit-ref`**: a called workflow cannot see its own ref,
   so the caller passes the same SHA. The kit is checked out to `.evidence-kit/` and excluded
   from scans. Self-check passes `github.sha`.
4. **Scorecard with `publish_results: false`** inside the evidence job (works on PRs and in
   reusable workflows); a separate `scorecard.yml` publishes the badge for this repo only.
5. **Report-only by default**; gate is a separate step after the artifact upload so evidence is
   never lost on failure.
6. **Mapping in YAML with a reference table**: controls refer to reference ids, never free text,
   so every citation is defined once and checked by `validate`.
7. **OSPS Baseline as cross-reference** (not as the engine): `pvtr-github-repo-scanner` is a
   candidate for v0.2.

## Structure
```
.github/workflows/evidence.yml   reusable workflow (FR-001..005, 011, 016)
.github/workflows/ci.yml         ruff, mapping validation, pytest, actionlint (FR-015)
.github/workflows/self-check.yml evidence on this repository (FR-015)
evidence_kit/                    collect.py, checks.py, mapping.py, report.py, cli.py
mappings/controls.yaml           controls -> KSC / CRA / OSPS references (FR-007)
templates/{en,pl}/               policy templates (FR-013)
examples/                        caller workflow, VEX example, generated sample report
tests/                           pytest + fixtures
```
