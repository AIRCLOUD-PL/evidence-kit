# evidence-kit

[![ci](https://github.com/AIRCLOUD-PL/evidence-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/AIRCLOUD-PL/evidence-kit/actions/workflows/ci.yml)
[![self-check](https://github.com/AIRCLOUD-PL/evidence-kit/actions/workflows/self-check.yml/badge.svg)](https://github.com/AIRCLOUD-PL/evidence-kit/actions/workflows/self-check.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/AIRCLOUD-PL/evidence-kit/badge)](https://scorecard.dev/viewer/?uri=github.com/AIRCLOUD-PL/evidence-kit)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Evidence, not paper.** A free GitHub reusable workflow that turns your repository into
machine-readable evidence of secure software supply-chain practice: a CycloneDX SBOM, a
vulnerability scan (with optional VEX), a full-history secret scan, an OpenSSF Scorecard and
repository hygiene checks. Every result is mapped to the Polish **KSC act** (NIS2
transposition, Dz.U. 2026 poz. 252) and the EU **Cyber Resilience Act** (Regulation (EU)
2024/2847), and delivered as one artifact with a report in English and Polish.

> **Informative mapping only. This is not legal advice and not a certification.** The
> statutory KSC audit (art. 15) is performed by an authorised auditor. The kit shows what was
> observed in a repository at one commit; it does not prove that an information security
> management system exists.

Polska wersja: [Po polsku](#po-polsku).

## Why now

| Date | What happens | Source |
|---|---|---|
| 3 Apr 2026 | Amended KSC act in force | Dz.U. 2026 poz. 252 |
| 11 Sep 2026 | CRA reporting of actively exploited vulnerabilities and severe incidents (Art. 14) applies | CRA Art. 71(2) |
| 3 Apr 2027 | Entities that met the criteria on 3 Apr 2026 must implement the chapter 3 duties (incl. art. 8 and 11) | art. 33 ust. 1 of the amending act |
| 11 Dec 2027 | CRA applies in full, incl. Annex I essential requirements | CRA Art. 71(2) |

Auditors and customers will ask for evidence. A PDF policy says what you intend to do; an SBOM,
a scan result and a protected branch show what you actually do, on every commit.

## Quick start

1. Get the full commit SHA of the release (tags are mutable and are rejected):

   ```sh
   gh api repos/AIRCLOUD-PL/evidence-kit/commits/v0.1.0 --jq .sha
   # or: git ls-remote https://github.com/AIRCLOUD-PL/evidence-kit 'refs/tags/v0.1.0^{}'
   ```

2. Add `.github/workflows/evidence.yml` to your repository and put that SHA in both places
   ([full example](examples/evidence-caller.yml)):

   ```yaml
   name: evidence
   on:
     push:
       branches: [main]
     schedule:
       - cron: "0 5 * * 1"
     workflow_dispatch: {}
   permissions:
     contents: read
   jobs:
     evidence:
       uses: AIRCLOUD-PL/evidence-kit/.github/workflows/evidence.yml@<FULL_COMMIT_SHA_OF_v0.1.0> # v0.1.0
       permissions:
         contents: read
         actions: read
       with:
         kit-ref: <FULL_COMMIT_SHA_OF_v0.1.0> # the same SHA as in `uses:`
   ```

3. Push. Open the run: the job summary shows the report; the **evidence** artifact holds all files.
4. Copy the [templates](templates/) you are missing (SECURITY.md, CVD policy, security.txt,
   incident runbook, supplier register) and run again.

No secrets, no app installation, no paid licence: by default nothing is sent to third-party
services except downloads from GitHub and the vulnerability database. The optional
`harden-runner: true` adds StepSecurity egress auditing; it sends telemetry to StepSecurity and
needs a StepSecurity plan for private repositories. The default is **report-only**; set
`fail-on: high` and `fail-on-secrets: true` when you want a gate. Runner: Linux x64 or arm64
with Python 3.11+ (`ubuntu-24.04` by default).

### Inputs

| Input | Default | Description |
|---|---|---|
| `kit-ref` | **required** | Full 40-hex commit SHA of evidence-kit, the same as in `uses:`. The workflow checks out its scripts and mapping at this SHA; tags are rejected. |
| `kit-repository` | `AIRCLOUD-PL/evidence-kit` | Where to check the kit out from. Change it only when you run your own fork. |
| `scan-path` | `.` | Path for the SBOM, relative to the repository root. |
| `skip-dirs` | `""` | Directories excluded from the SBOM (comma-separated, relative to `scan-path`; letters, digits, `. _ - / *`). |
| `vex-file` | `""` | OpenVEX / CycloneDX VEX / CSAF file applied to the scan ([example](examples/vex.openvex.json)). |
| `run-scorecard` | `true` | Run OpenSSF Scorecard (results are not published). |
| `harden-runner` | `false` | Run `step-security/harden-runner` in audit mode (third-party telemetry, see above). |
| `fail-on` | `none` | `none`, `critical`, `high`, `medium`, `low`. The gate runs after the artifact upload. |
| `fail-on-secrets` | `false` | Fail when gitleaks reports potential secrets. |
| `lang` | `en,pl` | Report languages; the first one goes to the job summary. |
| `artifact-name`, `retention-days`, `runs-on` | `evidence`, `90`, `ubuntu-24.04` | Artifact and runner settings. |

Output: `summary`, a JSON object with the number of controls per outcome, e.g.
`{"pass": 10, "warn": 1, "fail": 0, "unknown": 0, "not-run": 1, "manual": 10}`. Use it in a later
job as `needs.evidence.outputs.summary`.

### Output: the `evidence` artifact

| File | Content |
|---|---|
| `sbom.cdx.json` | CycloneDX SBOM (Trivy) |
| `vulnerabilities.trivy.json` | Vulnerability scan of the SBOM; VEX and `.trivyignore` applied, suppressed findings listed |
| `secrets.gitleaks.json` | gitleaks findings with the repository's own config, full history, values redacted |
| `secrets.gitleaks.baseline.json` | Same scan with default rules and no repository allowlists (reveals suppressions) |
| `scorecard.json` | OpenSSF Scorecard result |
| `repo-checks.json` | Policy files, scanner config files found, branch protection / rulesets, run metadata |
| `evidence.json` | Machine-readable result per control, SHA-256 of every file (`evidence-kit/v1`) |
| `evidence-report.md`, `evidence-report.pl.md` | Human-readable report (EN, PL) |

### Suppressions are always visible

A scan can be made green by configuration. The kit therefore:

- never applies a `trivy.yaml` from the scanned repository (it is reported as "not applied");
- applies `.trivyignore` / `.trivyignore.yaml` and VEX, always runs Trivy with `--show-suppressed`
  and lists every suppressed finding with its source; anything suppressed by an ignore file (no
  justification) makes EK-VULN at least **WARN**;
- applies `.gitleaks.toml` / `.gitleaksignore`, but also runs a baseline scan with default rules on a
  bare mirror; findings hidden by the repository configuration make EK-SECRETS at least **WARN**.

Inline `gitleaks:allow` comments are still honoured by gitleaks and are not counted.

### Run locally

```sh
git clone https://github.com/AIRCLOUD-PL/evidence-kit ~/evidence-kit
python3 -m venv ~/evidence-kit/.venv        # PEP 668: do not install into the system Python
~/evidence-kit/.venv/bin/pip install --require-hashes -r ~/evidence-kit/requirements.txt
export PYTHONPATH=~/evidence-kit
# then, in the root of the repository you want to assess:
mkdir -p evidence
trivy fs . --skip-dirs evidence --format cyclonedx --output evidence/sbom.cdx.json
trivy sbom --show-suppressed --format json --output evidence/vulnerabilities.trivy.json evidence/sbom.cdx.json
gitleaks git . --redact --exit-code 0 --report-format json --report-path evidence/secrets.gitleaks.json
~/evidence-kit/.venv/bin/python -P -m evidence_kit collect --repo . --out evidence/repo-checks.json
~/evidence-kit/.venv/bin/python -P -m evidence_kit report --evidence-dir evidence
```

`-P` keeps Python from importing modules from the assessed repository.

## What it proves

For one commit, with stored artifacts and hashes:

- which components ship in the software (SBOM) and which known vulnerabilities affect them,
  including your triage decisions (VEX);
- that the git history contains no detectable secrets;
- that a vulnerability reporting channel, a CVD policy and a valid `security.txt` exist;
- that code ownership is defined and the default branch is protected (when the API allows reading it);
- that dependency updates are automated and a supplier register and an incident runbook exist;
- how the repository scores on OpenSSF Scorecard (code review, pinned dependencies, token permissions and more).

Run it on a schedule and the artifacts become a time series: evidence that the process runs,
not only that it was set up once.

## What it does not prove

- an information security management system (SZBI) or its effectiveness;
- risk assessment, business continuity and backups, cryptography policy, physical security;
- staff training, including the annual training of the entity's manager (KSC art. 8e);
- the content quality of your policies and supplier assessments (only their presence is checked);
- incident handling in practice, or notifications sent to CSIRT / ENISA;
- CRA conformity assessment, technical documentation or CE marking;
- the statutory audit (KSC art. 15). These are listed as **manual controls** in every report.

## Controls

Mapping file: [`mappings/controls.yaml`](mappings/controls.yaml). Citations were checked against
the primary texts on 2026-11-25 (Dz.U. 2026 poz. 252 via eli.gov.pl; CRA via EUR-Lex). KSC
references are to the act as amended; CRA references are to Articles 13-14 and Annex I.

| ID | Control | Evidence | KSC (art. 8, 11) | CRA |
|---|---|---|---|---|
| EK-SBOM | SBOM (CycloneDX) | Trivy | 8.1.2 e, m; 8.2 | Annex I II(1); 13(5) |
| EK-VULN | Known vulnerabilities, VEX, suppressions | Trivy | 8.1.3; 8.1.5 b, d | Annex I II(1); I(2)(a), II(2) |
| EK-SECRETS | No secrets in git history (+ suppressions) | gitleaks | 8.1.2 j, n; 8.1.5 a | 13(1); Annex I I(2)(d), (e) |
| EK-SCORECARD | Repository security practices | OpenSSF Scorecard | 8.1.2 b, h | Annex I II(3) |
| EK-SECURITY-POLICY | SECURITY.md with contact | files | 8.1.3; 8.1.4 | Annex I II(6); 13(17) |
| EK-CVD | CVD policy | files | 8.1.3; 8.1.5 d | Annex I II(5); 13(8) |
| EK-SECURITY-TXT | security.txt (RFC 9116), valid Expires | files | 8.1.3 | Annex I II(6); 13(17) |
| EK-CODEOWNERS | CODEOWNERS | files | 8.1.2 n; 8.1.5 c | 13(1); Annex I I(2)(f) |
| EK-BRANCH-PROTECTION | Protected default branch / ruleset | GitHub API | 8.1.5 c; 8.1.2 n | 13(1); Annex I I(2)(d), (f) |
| EK-DEP-UPDATES | Dependabot / Renovate | files | 8.1.5 b | Annex I II(2) |
| EK-SUPPLIERS | Supplier register | files | 8.1.2 e; 8.2 | 13(5) |
| EK-INCIDENT-RUNBOOK | Incident and vulnerability reporting runbook | files | 8.1.4; 11.1 pkt 4-4c | 14 |
| M-RISK, M-BCP, M-CRYPTO, M-ACCESS, M-PEOPLE, M-MONITORING, M-ASSETS, M-UPDATES, M-SECURE-DESIGN, M-AUDIT | Manual: what a human must attach | - | 8.1.1, 8.1.2 a, c, d, f, g, i, k, l, m; 8e; 15.1 | 13(2), 13(8); Annex I I(1), I(2)(b), (c), (e), (h), (j), (l); II(4), (7), (8) |

Notation: `8.1.2 e` = art. 8 ust. 1 pkt 2 lit. e; `Annex I II(1)` = Annex I, Part II, point (1).
Each reference has a **relation**: `direct` (the control produces the artefact the provision names,
e.g. an SBOM for Annex I Part II(1)) or `supporting` (the control contributes evidence but is not
sufficient on its own, e.g. branch protection for Art. 13(1) and Annex I Part I(2)(d)-(f), or a
scan for "no known exploitable vulnerabilities": Trivy finds *known* vulnerabilities, it cannot
judge exploitability). Reports mark supporting references with "(supporting)" / "(pośrednio)".
KSC references are to the act of 5 July 2018 (t.j. Dz.U. 2026 poz. 20) as amended by Dz.U. 2026
poz. 252; the later amendments Dz.U. 2026 poz. 815, 1003 and 1206 do not change the cited provisions.
Outcomes: `pass`, `warn`, `fail`, `unknown` (not verifiable, e.g. no API access), `not-run`
(no tool output; never counted as pass), `manual`. Each control also lists related
[OpenSSF OSPS Baseline](https://baseline.openssf.org) requirements where they exist.

## Example report

Generated from [`tests/fixtures/sample`](tests/fixtures/sample) (a demo app with old
dependencies). Full output: [EN](examples/report/evidence-report.md),
[PL](examples/report/evidence-report.pl.md), [evidence.json](examples/report/evidence.json).

| PASS | WARN | FAIL | UNKNOWN | NOT RUN | MANUAL |
|---|---|---|---|---|---|
| 7 | 3 | 2 | 0 | 0 | 10 |

| ID | Outcome | Result | KSC | CRA |
|---|---|---|---|---|
| EK-SBOM | **PASS** | CycloneDX 1.6 SBOM: 4 package(s), 4 with purl. | art. 8 ust. 1 pkt 2 lit. e, m; art. 8 ust. 2 (supporting) | Annex I, Part II(1); Art. 13(5) (supporting) |
| EK-VULN | **FAIL** | Known vulnerabilities: 7 high, 12 medium. Suppressed by VEX: 1. | art. 8 ust. 1 pkt 3; pkt 5 lit. b, d (supporting) | Annex I, Part II(1); Part I(2)(a), Part II(2) (supporting) |
| EK-SECRETS | **FAIL** | 1 potential secret(s) in git history (rule types: 1). Rotate and remove them. | art. 8 ust. 1 pkt 2 lit. j, n; pkt 5 lit. a (supporting) | Art. 13(1); Annex I, Part I(2)(d), (e) (supporting) |
| EK-SCORECARD | **WARN** | Scorecard 6.2/10 (pass >= 7.0). | art. 8 ust. 1 pkt 2 lit. b, h (supporting) | Annex I, Part II(3) (supporting) |
| EK-BRANCH-PROTECTION | **PASS** | `main` requires pull requests (+ non_fast_forward, deletion). | art. 8 ust. 1 pkt 5 lit. c (supporting) | Art. 13(1); Annex I, Part I(2)(d), (f) (supporting) |
| EK-INCIDENT-RUNBOOK | **WARN** | Incident reporting runbook: not found (see templates/). | art. 8 ust. 1 pkt 4; art. 11 ust. 1 pkt 4-4c (supporting) | Art. 14(1)-(4) (supporting) |

## Templates

[`templates/`](templates/) has English and Polish versions of: `SECURITY.md`, a coordinated
vulnerability disclosure policy, `security.txt`, an incident and vulnerability reporting runbook
(KSC: early warning 24 h, notification 72 h, final report within one month; CRA: 24 h / 72 h /
final report 14 days after a fix for exploited vulnerabilities, one month for severe incidents)
and a supplier register (YAML and CSV). Deadlines were copied from the primary texts and cite the
exact provision.

## Built on

evidence-kit composes existing open-source tools and adds the mapping and the report:

- [Trivy](https://github.com/aquasecurity/trivy) CLI v0.76.2 (release binary, SHA-256 pinned in the workflow) for the CycloneDX SBOM and the vulnerability scan with [VEX](https://openvex.dev) support. We download the binary instead of using trivy-action/setup-trivy, so no third-party action runs in the scanning job.
- [gitleaks](https://github.com/gitleaks/gitleaks) CLI v8.30.1 (MIT, SHA-256 pinned) for secrets; the CLI avoids the licence requirement of gitleaks-action for organisations.
- [OpenSSF Scorecard](https://github.com/ossf/scorecard-action) for repository security practices.
- [CycloneDX](https://cyclonedx.org) (SBOM format) and [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) (`security.txt`).
- [OpenSSF OSPS Baseline](https://baseline.openssf.org) and its draft [CRA mapping](https://github.com/ossf/security-baseline/blob/main/baseline/mappings/osps-to-cra.yaml) as a cross-reference.
- [actions/checkout](https://github.com/actions/checkout), [actions/upload-artifact](https://github.com/actions/upload-artifact); optionally [step-security/harden-runner](https://github.com/step-security/harden-runner) (`harden-runner: true`).
- [zizmor](https://github.com/zizmorcore/zizmor) and [actionlint](https://github.com/rhysd/actionlint) audit the workflows in CI.
- [CERT Polska: good practices for software security management (CRA guide, May 2026)](https://cert.pl/uploads/docs/CERT_Polska_Dobre_praktyki_zarzadzania_bezpieczenstwem_oprogramowania.pdf) for the CVD, `security.txt` and SBOM recommendations.
- Built spec-driven with [github/spec-kit](https://github.com/github/spec-kit): see [`specs/001-evidence-kit-mvp`](specs/001-evidence-kit-mvp).

Considered and not (yet) used: [Syft](https://github.com/anchore/syft) and [OSV-Scanner](https://github.com/google/osv-scanner)
(Trivy covers both jobs in one tool), [pvtr-github-repo-scanner](https://github.com/ossf/pvtr-github-repo-scanner)
(full OSPS Baseline assessment, a good next step), [compliance-trestle](https://github.com/oscal-compass/compliance-trestle)
and [Lula](https://github.com/defenseunicorns/lula) (OSCAL compliance-as-code; heavier than this MVP needs).
None of them maps results to the Polish KSC act.

## Security of the kit itself

- All actions are pinned to full commit SHAs, and `kit-ref` must be a full SHA (tags of a popular
  scanner action were force-pushed to malicious commits in March 2026, GHSA-69fq-xp46-6x23).
- The Trivy, gitleaks (workflow) and actionlint (CI) binaries are verified against SHA-256 values
  pinned in the workflow files. Python dependencies are hash-pinned (`--require-hashes`).
- The scanned repository is treated as data: the kit is moved to `$RUNNER_TEMP` and runs with
  `python3 -P` from there, so a repository cannot shadow the kit's modules
  ([test](tests/test_isolation.py)); inputs are validated before use and never written to `GITHUB_ENV`.
- Permissions default to `contents: read`; no secrets are needed; the kit runs on itself
  ([self-check](.github/workflows/self-check.yml)). Report vulnerabilities as described in
  [SECURITY.md](SECURITY.md).

## Updating pinned tools

Dependabot updates the pinned actions and the hash-pinned Python requirements. The tool binaries
are pinned in workflow `env` blocks, which Dependabot does not read. To update them:

1. Pick the release (Trivy, gitleaks, actionlint) and download its `*_checksums.txt` from the
   GitHub release page; copy the SHA-256 for `Linux-64bit`/`Linux-ARM64` (Trivy),
   `linux_x64`/`linux_arm64` (gitleaks) or `linux_amd64` (actionlint).
2. Update `EK_TRIVY_*` / `EK_GITLEAKS_*` in [`evidence.yml`](.github/workflows/evidence.yml) or
   `ACTIONLINT_*` in [`ci.yml`](.github/workflows/ci.yml), and `docs/suppliers.yaml`.
3. Open a PR: CI and the self-check must pass before release. Check the vendor advisories first.

## Need help? AIRCLOUD

evidence-kit is built and maintained by [AIRCLOUD](https://aircloud.com.pl) (Opole, Poland):
DevOps, cloud and secure software supply chain. If you need help to close the gaps the report
shows, to prepare for a KSC audit or for the CRA, or to roll the kit out across many
repositories: **https://aircloud.com.pl/consulting/?from=evidence-kit** · office@aircloud.com.pl

## License

[Apache-2.0](LICENSE). Contributions welcome; please read [SECURITY.md](SECURITY.md) first for
security issues.

---

## Po polsku

**Dowody zamiast papieru.** Darmowy workflow GitHub, który z Twojego repozytorium robi dowody
techniczne bezpiecznego łańcucha dostaw oprogramowania: SBOM CycloneDX, skan podatności
(opcjonalnie z VEX), skan sekretów w całej historii git, OpenSSF Scorecard i kontrolę higieny
repozytorium. Każdy wynik jest przypisany do przepisów **ustawy o KSC** (wdrożenie NIS2,
Dz.U. 2026 poz. 252) i **aktu o cyberodporności CRA** (rozporządzenie (UE) 2024/2847).
Wynik to jeden artefakt z raportem po polsku i angielsku.

> **Mapowanie ma charakter informacyjny. To nie jest porada prawna ani certyfikacja.**
> Ustawowy audyt KSC (art. 15) wykonuje uprawniony audytor. Zestaw pokazuje stan repozytorium
> w jednym commicie i nie dowodzi istnienia systemu zarządzania bezpieczeństwem informacji.

### Terminy
- **3.04.2026**: weszła w życie nowelizacja ustawy o KSC (Dz.U. 2026 poz. 252).
- **11.09.2026**: CRA, obowiązek zgłaszania aktywnie wykorzystywanych podatności i poważnych incydentów (art. 14).
- **3.04.2027**: podmioty, które spełniały przesłanki 3.04.2026, wdrażają obowiązki z rozdziału 3 ustawy, w tym art. 8 i 11 (art. 33 ust. 1 ustawy nowelizującej).
- **11.12.2027**: CRA stosuje się w całości, w tym zasadnicze wymagania z załącznika I.

### Szybki start (5 minut)
1. Pobierz pełny SHA commita wydania: `gh api repos/AIRCLOUD-PL/evidence-kit/commits/v0.1.0 --jq .sha` (tagi są zmienne i workflow je odrzuca).
2. Dodaj plik `.github/workflows/evidence.yml` z sekcji [Quick start](#quick-start) i wpisz ten SHA w `uses:` oraz `kit-ref:`.
3. Wypchnij zmianę. Raport jest w podsumowaniu zadania (ustaw `lang: pl,en`, żeby był po polsku), a pliki w artefakcie **evidence**.
4. Skopiuj brakujące [szablony](templates/) (SECURITY.md, polityka CVD, security.txt, procedura zgłaszania incydentów, rejestr dostawców) i uruchom ponownie.

Bez sekretów, bez instalowania aplikacji, bez płatnej licencji; domyślnie żadne dane nie trafiają
do usług zewnętrznych poza pobraniami z GitHuba i bazy podatności. Opcja `harden-runner: true`
włącza audyt ruchu StepSecurity (telemetria do StepSecurity, dla repozytoriów prywatnych wymaga
planu StepSecurity). Domyślnie tylko raport; `fail-on: high` i `fail-on-secrets: true` włączają
blokadę. Wyłączenia wyników (VEX, `.trivyignore`, `.gitleaksignore`, `.gitleaks.toml`) są zawsze
wymienione w raporcie, a `trivy.yaml` z repozytorium nie jest stosowany.

### Co dowodzi
Dla jednego commita, z zapisanymi plikami i sumami SHA-256: jakie komponenty zawiera
oprogramowanie (SBOM) i jakie znane podatności ich dotyczą (z decyzjami VEX); że historia git nie
zawiera wykrywalnych sekretów; że istnieje kanał zgłaszania podatności, polityka CVD i ważny
`security.txt`; że są określeni właściciele kodu, a gałąź domyślna jest chroniona; że
aktualizacje zależności są zautomatyzowane, a w repozytorium jest rejestr dostawców i procedura
zgłaszania incydentów; jak repozytorium wypada w OpenSSF Scorecard. Uruchamiany cyklicznie daje
serię dowodów, że proces działa, a nie tylko że kiedyś go ustawiono.

### Czego nie dowodzi
Istnienia i skuteczności SZBI; szacowania ryzyka, ciągłości działania i kopii zapasowych,
polityki kryptograficznej, bezpieczeństwa fizycznego; szkoleń personelu i corocznego szkolenia
kierownika (art. 8e); jakości treści polityk i ocen dostawców (sprawdzana jest tylko obecność);
faktycznej obsługi incydentów i zgłoszeń do CSIRT lub ENISA; oceny zgodności, dokumentacji
technicznej i oznakowania CE według CRA; audytu ustawowego (art. 15). Te obszary każdy raport
wymienia jako **kontrole ręczne**, z listą dowodów do dołączenia.

### Pomoc
Zestaw tworzy i utrzymuje [AIRCLOUD](https://aircloud.com.pl) z Opola: DevOps, chmura
i bezpieczny łańcuch dostaw oprogramowania. Jeśli chcesz domknąć luki z raportu, przygotować się
do audytu KSC lub do CRA albo wdrożyć zestaw w wielu repozytoriach:
**https://aircloud.com.pl/consulting/?from=evidence-kit** · office@aircloud.com.pl
