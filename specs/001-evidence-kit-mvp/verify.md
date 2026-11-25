# Verification: evidence-kit MVP (v0.1)

Each `FR-###` from [spec.md](spec.md) has a check `V###`. Automated checks are pytest tests
tagged with `# V###` in `tests/`. Local run: 2026-11-25, macOS, Python 3.14.6, Trivy 0.69.3,
gitleaks 8.30.1. GitHub Actions runs are pending publication (T014-T015).

| V | FR | Check | How | Result |
|---|---|---|---|---|
| V001 | FR-001 | Reusable workflow has `workflow_call` inputs, top-level `contents: read`, job `contents/actions: read`, upload before gate, example caller exists | `test_reusable_workflow_contract`, `test_no_workflow_requests_write_by_default` | PASS (local) |
| V002 | FR-002 | CycloneDX SBOM parsed (spec version, packages, purl, generator); non-CycloneDX = fail; empty = warn | `test_sbom_details`, `test_non_cyclonedx_sbom_fails`, `test_empty_sbom_warns`; local Trivy run on this repo | PASS (local) |
| V003 | FR-003 | Vulnerability counts per severity, fixable, VEX-suppressed count (real Trivy output with OpenVEX), thresholds from mapping | `test_vulnerability_counts_and_vex`, `test_vulnerability_threshold_from_mapping`, `test_clean_scan_passes` | PASS (local) |
| V004 | FR-004 | gitleaks report parsed; secret values never in reports; fixtures hold no real contacts; full-history scan of this repo | `test_secret_values_never_in_report`, `test_clean_scan_passes`, `test_no_secrets_or_real_contacts_in_fixtures`; `gitleaks git .` | PASS (local), 0 leaks |
| V005 | FR-005 | Scorecard JSON parsed; pass/warn/fail/unknown thresholds | `test_scorecard_details`, `test_scorecard_thresholds` (4 cases) | PASS (local); real Scorecard run pending in CI |
| V006 | FR-006 | Collector finds EN and PL file names, ignores templates/tests/node_modules, parses security.txt Expires, GitHub API paths (fake API + live read-only call) | `tests/test_collect.py` (10 tests), `test_branch_protection_outcomes` (5 cases), `test_security_txt_expired_fails`; live `collect_github` on two own public repos | PASS (local) |
| V007 | FR-007 | Mapping valid, every control maps to KSC or CRA, every evaluator used, KSC art. 8 ust. 1 pkt 2 lit. a-n and CRA Annex I Part II(1)-(8) defined, validator catches errors | `tests/test_mapping_cli.py`; `python -m evidence_kit validate` | PASS: 22 controls (12 auto), 48 references |
| V008 | FR-008 | EN and PL reports with summary, controls, manual controls, hashes, sources; Polish CRA citations | `test_sample_outcomes`, `test_both_languages_and_disclaimer`, `test_cli_validate_and_report` | PASS (local) |
| V009 | FR-009 | `evidence.json` schema `evidence-kit/v1`, SHA-256 of each evidence file matches, run metadata | `test_evidence_json_schema_and_hashes`, `test_meta_from_env` | PASS (local) |
| V010 | FR-010 | Missing or malformed inputs give `not-run`, never `pass` | `test_missing_inputs_never_pass`, `test_malformed_input_is_not_run`, `test_sample_outcomes` | PASS (local) |
| V011 | FR-011 | Gate: thresholds, secrets, missing scans fail the gate; exit codes | `test_gate`, `test_gate_fails_when_scan_missing`, `test_cli_gate_exit_codes` | PASS (local) |
| V012 | FR-012 | Disclaimer in both reports, `evidence.json` and README | `test_both_languages_and_disclaimer`, `test_readme_sections_and_disclaimer` | PASS (local) |
| V013 | FR-013 | Templates in EN and PL; supplier YAML parses; runbook deadlines match the cited provisions | `test_templates_exist_in_both_languages`, `test_runbook_deadlines_match_sources`; manual comparison with Dz.U. 2026 poz. 252 (art. 11, 12a-12c) and CRA Art. 14 | PASS (local) |
| V014 | FR-014 | README sections, EN before PL, consulting link | `test_readme_sections_and_disclaimer` | PASS (local) |
| V015 | FR-015 | CI (ruff, validate, pytest, actionlint) and self-check calling the local reusable workflow with `kit-ref: github.sha` | `test_self_check_uses_local_workflow`; ruff locally; local end-to-end run below | PASS (local); actionlint and GitHub runs pending |
| V016 | FR-016 | Every `uses:` pinned to a 40-hex SHA with a version comment; gitleaks and actionlint binaries SHA-256 verified; pip `--require-hashes` | `test_all_actions_pinned_to_sha`, `test_reusable_workflow_contract`; SHAs resolved via GitHub API on 2026-11-25 | PASS (local) |

## Results (local)

```
$ pytest
..................................................                       [100%]
50 passed in 0.46s

$ ruff check . && ruff format --check .
All checks passed!
12 files already formatted

$ python -m evidence_kit validate
mapping ok: 22 controls (12 auto), 48 references
```

### Sample report from fixtures (`examples/report/`)
```
evidence: pass=7, warn=3, fail=2, unknown=0, not-run=0, manual=10
```
Fixtures `sbom.cdx.json` and `vulnerabilities.trivy.json` are real Trivy 0.69.3 output for a demo
`requirements.txt` (requests 2.25.0, urllib3 1.26.4, pyyaml 6.0.1, jinja2 3.1.2) with one OpenVEX
statement; gitleaks and Scorecard fixtures are hand-written in the tools' JSON format.

### End-to-end on this repository (same steps as `evidence.yml`, run locally)
```
trivy fs --format cyclonedx --skip-dirs tests/fixtures,examples -> sbom.cdx.json
trivy sbom --format json                                       -> vulnerabilities.trivy.json
gitleaks git . --redact                                        -> no leaks found
python -m evidence_kit collect / report
evidence: pass=10, warn=0, fail=0, unknown=1, not-run=1, manual=10
python -m evidence_kit gate --fail-on critical --fail-on-secrets
gate: ok (exit 0)
```
`unknown` = EK-BRANCH-PROTECTION (no token locally), `not-run` = EK-SCORECARD (needs GitHub).
Repository hygiene controls: 0 `fail` (SC-002 locally met).

### Live GitHub API check (read-only)
`collect_github` against two existing public repositories of the owner returned
`available: true`, `rules: []`, `protected: false`, classic protection `404` (expected for
non-admin reads) and the private vulnerability reporting flag.

## Not verified yet
- actionlint was not run locally (binary download not permitted in this session); it runs in `ci.yml`.
- No GitHub Actions run yet: Trivy v0.70.0 via trivy-action, Scorecard in a reusable workflow,
  artifact upload and job summary are verified only by design review until the first run.
- Legal mapping is checked against primary texts, but the interpretation (which control
  "supports" which provision) needs review by a human expert (see README disclaimer).
