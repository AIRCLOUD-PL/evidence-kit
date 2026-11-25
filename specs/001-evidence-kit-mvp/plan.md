# Implementation Plan: evidence-kit MVP (v0.1)

**Spec**: [spec.md](spec.md) · **Date**: 2026-11-25

## Summary
A GitHub reusable workflow composes Trivy, gitleaks and OpenSSF Scorecard, a small Python
collector checks repository hygiene, and a report generator joins tool outputs with a YAML
mapping to produce `evidence.json` and EN/PL Markdown reports.

## Technical context
- **Runtime**: GitHub-hosted `ubuntu-24.04`, system `python3` (3.12). Locally Python >= 3.10.
- **Dependencies**: PyYAML only (hash-pinned `requirements.txt`); dev: pytest, ruff (hash-pinned).
- **Tools composed**: Trivy CLI 0.76.2 and gitleaks CLI 8.30.1 (release binaries, SHA-256 pinned,
  x64 and arm64), ossf/scorecard-action v2.6.0, actions/checkout v7.0.1, actions/upload-artifact
  v7.0.2 (all SHA-pinned); optional step-security/harden-runner v2.23.0.
- **Testing**: pytest on fixtures generated with real Trivy output (`tests/fixtures/sample`).

## Decisions (ADR-style)
1. **Trivy for SBOM and vulnerabilities** instead of Syft + Grype/OSV: one pinned tool, native
   CycloneDX and VEX (OpenVEX / CycloneDX / CSAF). Syft and OSV-Scanner stay as alternatives.
   The release binary is downloaded and SHA-256 verified instead of using trivy-action or
   setup-trivy (fewer third-party actions; both had tags hijacked in March 2026).
2. **gitleaks CLI instead of gitleaks-action**: the action needs a paid licence for organisation
   accounts; the CLI is MIT. Pattern reused from the AIRCLOUD golden-path templates.
3. **Reusable workflow + kit checkout at `kit-ref`**: a called workflow cannot see its own ref,
   so the caller passes the same full SHA (required, validated). The kit is checked out and moved
   to `$RUNNER_TEMP`; all kit steps run from there with `python3 -P` (FR-017). Self-check passes
   `github.sha`.
4. **Scorecard with `publish_results: false`** inside the evidence job (works on PRs and in
   reusable workflows); a separate `scorecard.yml` publishes the badge for this repo only.
5. **Report-only by default**; gate is a separate step after the artifact upload so evidence is
   never lost on failure.
6. **Mapping in YAML with a reference table**: controls refer to reference ids, never free text,
   so every citation is defined once and checked by `validate`.
7. **OSPS Baseline as cross-reference** (not as the engine): `pvtr-github-repo-scanner` is a
   candidate for v0.2.
8. **Suppressions are honoured but exposed** (FR-018): `.trivyignore` and VEX are applied with
   `--show-suppressed`; repository `trivy.yaml` is not applied; gitleaks runs twice (repository
   config, then default rules on a bare mirror) to reveal allowlisted findings.
9. **harden-runner opt-in**: it sends telemetry to StepSecurity and needs a plan for private
   repositories, so callers enable it explicitly; this repository uses it in its own CI.

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
