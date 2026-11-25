# Verification: evidence-kit MVP (v0.1)

Each `FR-###` from [spec.md](spec.md) has a check `V###`. Automated checks are pytest tests
tagged with `# V###` in `tests/`. Local run: 2026-11-25, macOS, Python 3.14.6, Trivy 0.69.3 and
gitleaks 8.30.1 from Homebrew (the workflow pins Trivy 0.76.2). Revision 2 after the independent
review (Checker verdict "ready after fixes"). GitHub Actions runs are pending publication (T014-T015).

| V | FR | Check | How | Result |
|---|---|---|---|---|
| V001 | FR-001 | `workflow_call` inputs; `kit-ref` required, no default, validated `^[0-9a-f]{40}$` before checkout; `harden-runner` opt-in; top-level `contents: read`; upload before gate; example uses SHA placeholder | `test_reusable_workflow_contract`, `test_examples_use_sha_placeholder`, `test_no_workflow_requests_write_by_default` | PASS (local) |
| V002 | FR-002 | CycloneDX SBOM parsed; non-CycloneDX = fail; empty = warn | `test_sbom_details`, `test_non_cyclonedx_sbom_fails`, `test_empty_sbom_warns`; local Trivy run | PASS (local) |
| V003 | FR-003 | Severity and fixable counts; VEX applied (real Trivy output with OpenVEX); thresholds from mapping | `test_vulnerability_counts_and_vex`, `test_vulnerability_threshold_from_mapping`, `test_clean_scan_passes` | PASS (local) |
| V004 | FR-004 | gitleaks report parsed; secret values never in reports; fixtures hold no real contacts | `test_secret_values_never_in_report`, `test_clean_scan_passes`, `test_no_secrets_or_real_contacts_in_fixtures`; `gitleaks git .` on this repo | PASS (local), 0 leaks |
| V005 | FR-005 | Scorecard JSON parsed; pass/warn/fail/unknown thresholds | `test_scorecard_details`, `test_scorecard_thresholds` | PASS (local); real run pending |
| V006 | FR-006 | Collector: EN/PL file names, skips templates/tests/node_modules, security.txt Expires, GitHub API (fake + live read-only), https only | `tests/test_collect.py`, `test_branch_protection_outcomes`, `test_security_txt_expired_fails` | PASS (local) |
| V007 | FR-007 | Mapping valid; every control maps to law; `relation` direct/supporting validated and rendered ("(supporting)" / "(pośrednio)"); CRA Art. 13(1) present | `tests/test_mapping_cli.py`, `test_relation_is_shown`; `validate` | PASS: 22 controls (12 auto), 49 references |
| V008 | FR-008 | EN and PL reports, Polish CRA citations | `test_sample_outcomes`, `test_both_languages_and_disclaimer`, `test_cli_validate_and_report` | PASS (local) |
| V009 | FR-009 | `evidence.json` schema, SHA-256 of each file incl. gitleaks baseline | `test_evidence_json_schema_and_hashes`, `test_meta_from_env` | PASS (local) |
| V010 | FR-010 | Missing/malformed input = `not-run`, with the reason from workflow notes (e.g. unsupported architecture) | `test_missing_inputs_never_pass`, `test_malformed_input_is_not_run`, `test_step_notes_explain_not_run` | PASS (local) |
| V011 | FR-011 | Gate thresholds, secrets, missing scans; exit codes | `test_gate`, `test_gate_fails_when_scan_missing`, `test_cli_gate_exit_codes` | PASS (local) |
| V012 | FR-012 | Disclaimer in reports, `evidence.json`, README | `test_both_languages_and_disclaimer`, `test_readme_sections_and_disclaimer` | PASS (local) |
| V013 | FR-013 | Templates EN/PL; runbook deadlines match the cited provisions | `test_templates_exist_in_both_languages`, `test_runbook_deadlines_match_sources` | PASS (local) |
| V014 | FR-014 | README sections (incl. `kit-repository`, `harden-runner`, `summary`, updating pinned tools); owner `AIRCLOUD-PL/evidence-kit` everywhere | `test_readme_sections_and_disclaimer`, `test_owner_is_aircloud_pl` | PASS (local) |
| V015 | FR-015 | CI (ruff, validate, pytest, zizmor, actionlint) and self-check with `kit-ref: github.sha` | `test_self_check_uses_local_workflow`; ruff + zizmor locally | PASS (local); actionlint and GitHub runs pending |
| V016 | FR-016 | Every `uses:` pinned to a SHA with version comment, SHAs resolved from tags via GitHub API; versions without the cited advisories; Trivy/gitleaks/actionlint SHA-256 pinned; `--require-hashes` | `test_all_actions_pinned_to_sha`, `test_reusable_workflow_contract`; `zizmor --offline` = no findings | PASS (local) |
| V017 | FR-017 | A malicious `evidence_kit/` in the scanned repo: naive `python -m` is hijacked (exit 0, marker written), the workflow form `python3 -P` with absolute `PYTHONPATH` fails the gate (exit 1, no marker); every python step runs in `${{ runner.temp }}`, kit moved out of the workspace | `test_malicious_evidence_kit_in_scanned_repo_cannot_replace_gate`, `test_workflow_never_runs_kit_code_from_the_scanned_repo`, `test_trivy_never_uses_repository_config`; hostile-repo e2e below | PASS (local) |
| V018 | FR-018 | Suppressions by source: `.trivyignore` gives WARN with a list (no runner paths), VEX-only keeps the outcome, repository `trivy.yaml` not applied and reported, gitleaks allowlist revealed by baseline gives WARN, missing baseline noted | `test_trivyignore_suppression_is_never_a_silent_pass`, `test_vex_only_suppression_keeps_outcome`, `test_trivy_config_in_repo_is_reported`, `test_gitleaks_allowlist_suppression_is_reported`, `test_gitleaks_without_baseline_is_noted`; hostile-repo e2e below | PASS (local) |

## Results (local)

```
$ pytest
62 passed in 0.82s
$ ruff check . && ruff format --check .
All checks passed! / 13 files already formatted
$ python -P -m evidence_kit validate
mapping ok: 22 controls (12 auto), 49 references
$ zizmor --offline .github/workflows
No findings to report. Good job! (1 ignored, 3 suppressed)
```
The one ignored finding is `self-repository` (zizmor suggests the `$/` syntax for the local reusable
workflow call; `./` is kept for actionlint compatibility, with an inline `zizmor: ignore`).

### End-to-end replica of `evidence.yml` (scratch dir as cwd, `-P`, empty Trivy config, gitleaks baseline on a bare mirror)

On this repository (`skip-dirs: tests/fixtures,examples`):
```
evidence: pass=10, warn=0, fail=0, unknown=1, not-run=1, manual=10
gate --fail-on critical --fail-on-secrets: ok (exit 0)
```
`unknown` = branch protection (no token locally), `not-run` = Scorecard (needs GitHub).

On a hostile demo repository (old `requests`/`urllib3`, `.trivyignore` hiding one CVE, `trivy.yaml`
with `severity: [LOW]`, a fake GitHub token hidden by `.gitleaksignore`, and a malicious
`evidence_kit/__main__.py` that exits 0):
```
EK-VULN    fail | Known vulnerabilities: 7 high, 7 medium. Suppressed by .trivyignore: 1 (review the list). trivy.yaml in the repository was not applied.
EK-SECRETS warn | No secrets found in the git history. 1 finding(s) of the default rules are suppressed by .gitleaksignore (review the list).
gate --fail-on high: exit 1 ("HIGH": 7); malicious module not executed (no marker file)
```

### Sample report from fixtures (`examples/report/`)
```
evidence: pass=7, warn=3, fail=2, unknown=0, not-run=0, manual=10
```

### Pins resolved on 2026-11-25 (tag to commit via GitHub API)
harden-runner v2.23.0 `aebdcf61…`, checkout v7.0.1 `3d3c42e5…`, upload-artifact v7.0.2 `cf430e03…`,
codeql-action v4.39.5 `915412ff…`, scorecard-action v2.6.0 `23f22cd4…`. Advisories GHSA-46g3-37rh-v698,
GHSA-g699-3x6g-wm3g, GHSA-cpmj-h4f6-r6pq, GHSA-mxr3-8whj-j74r (harden-runner <= 2.15.1) and
GHSA-vqf5-2xx6-9wfm (codeql-action <= 3.28.2) do not affect the pinned versions. Trivy 0.76.2,
gitleaks 8.30.1 (x64, arm64) and actionlint 1.7.12 SHA-256 values come from the release checksum files.

### Legal sources re-checked
KSC: the amending act Dz.U. 2026 poz. 252 cites t.j. Dz.U. 2026 poz. 20; the later acts Dz.U. 2026
poz. 815 (art. 15 ust. 7), 1003 (art. 26 ust. 3) and 1206 (annex) do not change art. 8, 11, 12a-12c
or 15 ust. 1.

## Not verified yet
- actionlint was not run locally (binary download not permitted in this session); it runs in `ci.yml`.
- No GitHub Actions run yet: the Trivy 0.76.2 download, Scorecard in a reusable workflow, checkout v7 /
  upload-artifact v7 and the job summary are verified by design review only until the first run.
- The arm64 path of the workflow is untested (no arm64 runner used).
- `fail-on-secrets` gates on findings after the repository's own allowlists; findings revealed only
  by the baseline make EK-SECRETS WARN but do not fail the gate (deliberate, see report).
- The interpretation of the mapping (direct vs supporting) needs review by a human expert.
