<!-- Sync Impact Report: template -> 1.0.0; principles I-VII added; no TODOs -->
# evidence-kit Constitution

## Core Principles

### I. Evidence, not paper
Every automated control produces a machine-readable artifact (SBOM, scan result, API
response) that is stored in the `evidence/` bundle with its SHA-256. A control that cannot
be proven from the repository is marked `manual` and says which document a human must attach.
The kit never reports "compliant"; it reports what was observed.

### II. Compose, don't rebuild
Scanning is done by established open-source tools (Trivy, gitleaks, OpenSSF Scorecard).
Our own code is limited to repository hygiene checks, the requirement mapping and the
report. Before adding a new capability we check whether an existing tool already does it.

### III. Honest, sourced mapping
The mapping to the Polish KSC act (NIS2 transposition) and the EU Cyber Resilience Act is
informative. Each reference cites the provision as published in the primary source
(eli.gov.pl / Dziennik Ustaw, EUR-Lex). If we are unsure of a point number we cite the
article, not a guess. Every report carries the disclaimer: not legal advice, not a
certification; the statutory KSC audit is performed by an authorised auditor.

### IV. The kit is itself a secure supply chain
Third-party actions are pinned to a full commit SHA, downloaded binaries are verified with
SHA-256, Python dependencies are hash-pinned, workflow permissions are least-privilege
(`contents: read` by default) and no secret is required to run. The kit runs on itself
in CI (self-check).

### V. Small, tested, dependency-light
The generator is plain Python (standard library + PyYAML). Every functional requirement
`FR-###` has a verification `V###` in `specs/*/verify.md`, preferably an automated pytest
on fixtures in `tests/fixtures/`.

### VI. Bilingual by default
User-facing outputs and templates exist in English and Polish. English is the source
language of code, commits and the spec.

### VII. No third-party data
No customer data, no names of companies the author worked for, no real secrets in
fixtures. Contact: office@aircloud.com.pl, https://aircloud.com.pl.

## Governance
This constitution overrides other practices in this repository. Changes are made by PR
with a version bump (semantic: MAJOR for removed principles, MINOR for new ones, PATCH for
wording). Mapping changes must reference the primary source they were checked against.

**Version**: 1.0.0 | **Ratified**: 2026-11-25 | **Last Amended**: 2026-11-25
