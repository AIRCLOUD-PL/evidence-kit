# Tasks: evidence-kit MVP (v0.1)

- [x] T001 Research existing tools (Trivy, Syft, OSV-Scanner, Scorecard, gitleaks, OSPS Baseline, OSCAL tools, NIS2/CRA repos)
- [x] T002 Verify legal texts: KSC art. 8, 11, 12a-12c, 15, 33 (Dz.U. 2026 poz. 252); CRA art. 13, 14, 71, Annex I (EN, PL); CERT Polska guide
- [x] T003 Constitution and spec 001 with FR-001..FR-016
- [x] T004 Mapping `mappings/controls.yaml` + validator (FR-007)
- [x] T005 Collector: files, security.txt parser, GitHub API (FR-006)
- [x] T006 Evaluators for 12 automated controls (FR-002..006, FR-010)
- [x] T007 Report generator EN/PL + evidence.json with SHA-256 (FR-008, FR-009, FR-012)
- [x] T008 Gate command (FR-011)
- [x] T009 Reusable workflow, example caller, VEX example (FR-001..005, FR-016)
- [x] T010 Templates EN/PL (FR-013)
- [x] T011 README EN + PL (FR-014)
- [x] T012 Tests on fixtures, CI and self-check workflows (FR-015)
- [x] T013 Local end-to-end run on this repository, results in verify.md
- [x] T016 Independent review fixes: FR-017 isolation (`python3 -P` from `$RUNNER_TEMP`, malicious-module test), FR-018 suppression transparency, pin bumps + zizmor, opt-in harden-runner, required SHA `kit-ref`, `relation` in mapping, owner AIRCLOUD-PL
- [ ] T014 Publish to AIRCLOUD-PL/evidence-kit: gitleaks scan, push, tag v0.1.0, enable private vulnerability reporting and branch ruleset (main session)
- [ ] T015 First green CI + self-check run on GitHub; record run URL in verify.md
