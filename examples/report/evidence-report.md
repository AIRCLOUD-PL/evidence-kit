# Supply-chain security evidence report

> Informative mapping only. This is not legal advice and not a certification. The statutory KSC audit (art. 15) is performed by an authorised auditor. Automated results show what was observed in the repository at one commit; they do not prove that an information security management system exists.

- **Repository:** `example/demo-app`
- **Commit:** `0123456789ab`
- **Generated:** 2026-11-25T00:00:00+00:00
- **evidence-kit:** 0.1.0 (mapping 0.1.0, 2026-11-25)
- **Workflow run:** https://github.com/example/demo-app/actions/runs/1234567890
- **Tools:** trivy v0.76.2, gitleaks 8.30.1, scorecard_action v2.6.0

## Summary

| PASS | WARN | FAIL | UNKNOWN | NOT RUN | MANUAL |
|---|---|---|---|---|---|
| 7 | 3 | 2 | 0 | 0 | 10 |

Outcomes: PASS, WARN, FAIL, UNKNOWN (not verifiable), NOT RUN (no input), MANUAL.

Relation: a reference without a mark is direct (the control produces the artefact the provision names); (supporting) means the control contributes evidence but is not sufficient on its own.

What this report does not prove: an information security management system (SZBI), risk assessment, business continuity, staff training, physical security or the statutory audit. Those are listed under manual controls.

## Automated controls

| ID | Control | Outcome | Result | KSC | CRA |
|---|---|---|---|---|---|
| EK-SBOM | Software bill of materials (CycloneDX) | **PASS** | CycloneDX 1.6 SBOM: 4 package(s), 4 with purl. | art. 8 ust. 1 pkt 2 lit. e (supporting)<br>art. 8 ust. 1 pkt 2 lit. m (supporting)<br>art. 8 ust. 2 (supporting) | Annex I, Part II(1)<br>Art. 13(5) (supporting) |
| EK-VULN | Known vulnerabilities in dependencies (SBOM scan, optional VEX) | **FAIL** | Known vulnerabilities: 7 high, 12 medium. Suppressed by VEX: 1. | art. 8 ust. 1 pkt 3<br>art. 8 ust. 1 pkt 5 lit. b (supporting)<br>art. 8 ust. 1 pkt 5 lit. d (supporting) | Annex I, Part II(1)<br>Annex I, Part I(2)(a) (supporting)<br>Annex I, Part II(2) (supporting) |
| EK-SECRETS | No secrets in git history (gitleaks) | **FAIL** | 1 potential secret(s) in git history (rule types: 1). Rotate and remove them. | art. 8 ust. 1 pkt 2 lit. n (supporting)<br>art. 8 ust. 1 pkt 2 lit. j (supporting)<br>art. 8 ust. 1 pkt 5 lit. a (supporting) | Art. 13(1) (supporting)<br>Annex I, Part I(2)(d) (supporting)<br>Annex I, Part I(2)(e) (supporting) |
| EK-SCORECARD | OpenSSF Scorecard (repository security practices) | **WARN** | Scorecard 6.2/10 (pass >= 7.0). Lowest: CII-Best-Practices, Fuzzing, Vulnerabilities, Branch-Protection, Contributors. | art. 8 ust. 1 pkt 2 lit. b (supporting)<br>art. 8 ust. 1 pkt 2 lit. h (supporting) | Annex I, Part II(3) (supporting) |
| EK-SECURITY-POLICY | Security policy with a reporting contact (SECURITY.md) | **PASS** | SECURITY.md with a reporting contact. Private vulnerability reporting is enabled. | art. 8 ust. 1 pkt 3 (supporting)<br>art. 8 ust. 1 pkt 4 (supporting) | Annex I, Part II(6)<br>Art. 13(17) |
| EK-CVD | Coordinated vulnerability disclosure (CVD) policy | **PASS** | CVD section found in SECURITY.md. | art. 8 ust. 1 pkt 3 (supporting)<br>art. 8 ust. 1 pkt 5 lit. d (supporting) | Annex I, Part II(5)<br>Art. 13(8) (supporting) |
| EK-SECURITY-TXT | security.txt (RFC 9116) with Contact and valid Expires | **PASS** | .well-known/security.txt valid until 2027-11-01T00:00:00Z. | art. 8 ust. 1 pkt 3 (supporting) | Annex I, Part II(6) (supporting)<br>Art. 13(17) (supporting) |
| EK-CODEOWNERS | Code ownership defined (CODEOWNERS) | **PASS** | .github/CODEOWNERS with 1 rule(s). | art. 8 ust. 1 pkt 2 lit. n (supporting)<br>art. 8 ust. 1 pkt 5 lit. c (supporting) | Art. 13(1) (supporting)<br>Annex I, Part I(2)(f) (supporting) |
| EK-BRANCH-PROTECTION | Default branch protected (branch protection or ruleset) | **PASS** | `main` requires pull requests (+ non_fast_forward, deletion). | art. 8 ust. 1 pkt 5 lit. c (supporting)<br>art. 8 ust. 1 pkt 2 lit. n (supporting) | Art. 13(1) (supporting)<br>Annex I, Part I(2)(d) (supporting)<br>Annex I, Part I(2)(f) (supporting) |
| EK-DEP-UPDATES | Automated dependency updates (Dependabot or Renovate) | **PASS** | Dependency update config: .github/dependabot.yml. | art. 8 ust. 1 pkt 5 lit. b (supporting) | Annex I, Part II(2) (supporting) |
| EK-SUPPLIERS | Supplier register present (content needs human review) | **WARN** | Supplier register: not found (see templates/). | art. 8 ust. 1 pkt 2 lit. e (supporting)<br>art. 8 ust. 2 (supporting) | Art. 13(5) (supporting) |
| EK-INCIDENT-RUNBOOK | Incident and vulnerability reporting runbook present | **WARN** | Incident reporting runbook: not found (see templates/). | art. 8 ust. 1 pkt 4 (supporting)<br>art. 11 ust. 1 pkt 4-4c (supporting) | Art. 14(1)-(4) (supporting) |

## Manual controls (evidence you must provide)

| ID | Control | What to attach | KSC | CRA |
|---|---|---|---|---|
| M-RISK | Risk assessment and risk treatment | Current risk register and method, product risk assessment (CRA), management approval. | art. 8 ust. 1 pkt 1<br>art. 8 ust. 1 pkt 2 lit. a | Art. 13(2)-(3)<br>Annex I, Part I(1) |
| M-BCP | Business continuity, backups and recovery | BCP/DRP, backup policy, results of the last restore test. | art. 8 ust. 1 pkt 2 lit. f | Annex I, Part I(2)(h) |
| M-CRYPTO | Cryptography and encryption policy | Crypto policy (algorithms, key management), TLS and at-rest encryption configuration. | art. 8 ust. 1 pkt 2 lit. k | Annex I, Part I(2)(e) |
| M-ACCESS | Access control, MFA and physical security | Access control policy, MFA enforcement (e.g. GitHub org setting), periodic access reviews. | art. 8 ust. 1 pkt 2 lit. c<br>art. 8 ust. 1 pkt 2 lit. l<br>art. 8 ust. 1 pkt 2 lit. n | Annex I, Part I(2)(d) |
| M-PEOPLE | Staff security, training and cyber hygiene | Training records for staff and the annual training of the manager (art. 8e), onboarding/offboarding procedure. | art. 8 ust. 1 pkt 2 lit. d<br>art. 8 ust. 1 pkt 2 lit. i<br>art. 8 ust. 1 pkt 2 lit. j<br>art. 8e | - |
| M-MONITORING | Continuous monitoring and incident handling | Monitoring/SIEM scope, alerting, incident register, a tested reporting exercise. | art. 8 ust. 1 pkt 2 lit. g<br>art. 8 ust. 1 pkt 4 | Annex I, Part I(2)(l) |
| M-ASSETS | Asset inventory | Inventory of systems, services and repositories in scope, with owners. | art. 8 ust. 1 pkt 2 lit. m | - |
| M-UPDATES | Security update delivery, advisories and support period | Release process (signed releases), published advisories for fixed vulnerabilities, declared support period. | art. 8 ust. 1 pkt 5 lit. b | Annex I, Part I(2)(c)<br>Annex I, Part II(4)<br>Annex I, Part II(7)<br>Annex I, Part II(8)<br>Art. 13(8) |
| M-SECURE-DESIGN | Secure by default and minimal attack surface | Threat model or design review, hardening baseline, default configuration review. | art. 8 ust. 1 pkt 2 lit. b | Annex I, Part I(2)(b)<br>Annex I, Part I(2)(j) |
| M-AUDIT | Statutory security audit | Audit report by an authorised auditor (essential entities). This kit does not replace it. | art. 15 ust. 1 | - |

## Details

### EK-SBOM: Software bill of materials (CycloneDX) (PASS)

CycloneDX 1.6 SBOM: 4 package(s), 4 with purl.

- **KSC:** art. 8 ust. 1 pkt 2 lit. e (supporting): security and continuity of the ICT supply chain (products, services, processes); art. 8 ust. 1 pkt 2 lit. m (supporting): asset management; art. 8 ust. 2 (supporting): supply-chain measures consider supplier vulnerabilities and overall product quality
- **CRA:** Annex I, Part II(1): identify and document vulnerabilities and components, incl. an SBOM; Art. 13(5) (supporting): due diligence when integrating third-party components, incl. open source
- **OSPS Baseline:** OSPS-QA-02.01, OSPS-QA-02.02
- **Evidence:** `sbom.cdx.json`

### EK-VULN: Known vulnerabilities in dependencies (SBOM scan, optional VEX) (FAIL)

Known vulnerabilities: 7 high, 12 medium. Suppressed by VEX: 1.

- **KSC:** art. 8 ust. 1 pkt 3: collecting information on cyber threats and vulnerabilities; art. 8 ust. 1 pkt 5 lit. b (supporting): regular software updates, following vendor recommendations; art. 8 ust. 1 pkt 5 lit. d (supporting): prompt action once vulnerabilities or cyber threats are detected
- **CRA:** Annex I, Part II(1): identify and document vulnerabilities and components, incl. an SBOM; Annex I, Part I(2)(a) (supporting): made available without known exploitable vulnerabilities; Annex I, Part II(2) (supporting): address and remediate vulnerabilities without delay
- **OSPS Baseline:** OSPS-VM-05.03, OSPS-VM-04.02
- **Evidence:** `vulnerabilities.trivy.json`, `sbom.cdx.json`

| Severity | Count | Fixable |
|---|---|---|
| CRITICAL | 0 | 0 |
| HIGH | 7 | 7 |
| MEDIUM | 12 | 12 |
| LOW | 0 | 0 |
| UNKNOWN | 0 | 0 |

| ID | Severity | Package | Installed | Fixed in |
|---|---|---|---|---|
| CVE-2023-43804 | HIGH | urllib3 | 1.26.4 | 2.0.6, 1.26.17 |
| CVE-2025-66418 | HIGH | urllib3 | 1.26.4 | 2.6.0 |
| CVE-2025-66471 | HIGH | urllib3 | 1.26.4 | 2.6.0 |
| CVE-2026-21441 | HIGH | urllib3 | 1.26.4 | 2.6.3 |
| CVE-2026-44431 | HIGH | urllib3 | 1.26.4 | 2.7.0 |
| CVE-2026-97687 | HIGH | urllib3 | 1.26.4 | 2.8.0 |
| CVE-2026-97689 | HIGH | urllib3 | 1.26.4 | 2.8.0 |
| CVE-2023-32681 | MEDIUM | requests | 2.25.0 | 2.31.0 |
| CVE-2023-45803 | MEDIUM | urllib3 | 1.26.4 | 2.0.7, 1.26.18 |
| CVE-2024-22195 | MEDIUM | jinja2 | 3.1.2 | 3.1.3 |
| CVE-2024-34064 | MEDIUM | jinja2 | 3.1.2 | 3.1.4 |
| CVE-2024-35195 | MEDIUM | requests | 2.25.0 | 2.32.0 |
| CVE-2024-37891 | MEDIUM | urllib3 | 1.26.4 | 1.26.19, 2.2.2 |
| CVE-2024-47081 | MEDIUM | requests | 2.25.0 | 2.32.4 |
| CVE-2024-56201 | MEDIUM | jinja2 | 3.1.2 | 3.1.5 |

Suppressed findings (not counted above):

| ID | Severity | Package | Suppressed by | Status / justification |
|---|---|---|---|---|
| CVE-2021-33503 | HIGH | urllib3 | vex (`vex.openvex.json`) | not_affected / vulnerable_code_not_in_execute_path |

### EK-SECRETS: No secrets in git history (gitleaks) (FAIL)

1 potential secret(s) in git history (rule types: 1). Rotate and remove them.

- **KSC:** art. 8 ust. 1 pkt 2 lit. n (supporting): access control policies; art. 8 ust. 1 pkt 2 lit. j (supporting): basic cyber hygiene; art. 8 ust. 1 pkt 5 lit. a (supporting): mechanisms ensuring confidentiality, integrity, availability and authenticity of data
- **CRA:** Art. 13(1) (supporting): product designed, developed and produced in accordance with Annex I Part I (process obligation); Annex I, Part I(2)(d) (supporting): protection from unauthorised access; Annex I, Part I(2)(e) (supporting): confidentiality of data, e.g. encryption at rest and in transit
- **OSPS Baseline:** OSPS-BR-07.01
- **Evidence:** `secrets.gitleaks.json`, `secrets.gitleaks.baseline.json`

Secret values are redacted; only rule, file, line and commit are shown.

| Rule | File | Line | Commit |
|---|---|---|---|
| generic-api-key | `config/settings.example.py` | 12 | `4f2c1d9e8b7a` |

### EK-SCORECARD: OpenSSF Scorecard (repository security practices) (WARN)

Scorecard 6.2/10 (pass >= 7.0). Lowest: CII-Best-Practices, Fuzzing, Vulnerabilities, Branch-Protection, Contributors.

- **KSC:** art. 8 ust. 1 pkt 2 lit. b (supporting): security in acquisition, development, maintenance and operation, incl. testing; art. 8 ust. 1 pkt 2 lit. h (supporting): policies and procedures to assess the effectiveness of measures
- **CRA:** Annex I, Part II(3) (supporting): effective and regular security tests and reviews
- **Evidence:** `scorecard.json`

| Check | Score |
|---|---|
| Packaging | n/a |
| Signed-Releases | n/a |
| CII-Best-Practices | 0 |
| Fuzzing | 0 |
| Vulnerabilities | 0 |
| Branch-Protection | 3 |
| Contributors | 3 |
| Code-Review | 4 |
| Pinned-Dependencies | 6 |
| SAST | 7 |
| Binary-Artifacts | 10 |
| CI-Tests | 10 |
| Dangerous-Workflow | 10 |
| Dependency-Update-Tool | 10 |
| License | 10 |
| Maintained | 10 |
| Security-Policy | 10 |
| Token-Permissions | 10 |

### EK-SECURITY-POLICY: Security policy with a reporting contact (SECURITY.md) (PASS)

SECURITY.md with a reporting contact. Private vulnerability reporting is enabled.

- **KSC:** art. 8 ust. 1 pkt 3 (supporting): collecting information on cyber threats and vulnerabilities; art. 8 ust. 1 pkt 4 (supporting): incident management
- **CRA:** Annex I, Part II(6): facilitate sharing vulnerability information, incl. a contact address; Art. 13(17): single point of contact for users, incl. vulnerability reporting
- **OSPS Baseline:** OSPS-VM-02.01, OSPS-VM-03.01
- **Evidence:** `repo-checks.json`

### EK-CVD: Coordinated vulnerability disclosure (CVD) policy (PASS)

CVD section found in SECURITY.md.

- **KSC:** art. 8 ust. 1 pkt 3 (supporting): collecting information on cyber threats and vulnerabilities; art. 8 ust. 1 pkt 5 lit. d (supporting): prompt action once vulnerabilities or cyber threats are detected
- **CRA:** Annex I, Part II(5): coordinated vulnerability disclosure policy; Art. 13(8) (supporting): effective vulnerability handling during the support period
- **OSPS Baseline:** OSPS-VM-01.01
- **Evidence:** `repo-checks.json`

### EK-SECURITY-TXT: security.txt (RFC 9116) with Contact and valid Expires (PASS)

.well-known/security.txt valid until 2027-11-01T00:00:00Z.

- **KSC:** art. 8 ust. 1 pkt 3 (supporting): collecting information on cyber threats and vulnerabilities
- **CRA:** Annex I, Part II(6) (supporting): facilitate sharing vulnerability information, incl. a contact address; Art. 13(17) (supporting): single point of contact for users, incl. vulnerability reporting
- **Evidence:** `repo-checks.json`

### EK-CODEOWNERS: Code ownership defined (CODEOWNERS) (PASS)

.github/CODEOWNERS with 1 rule(s).

- **KSC:** art. 8 ust. 1 pkt 2 lit. n (supporting): access control policies; art. 8 ust. 1 pkt 5 lit. c (supporting): protection against unauthorised modification
- **CRA:** Art. 13(1) (supporting): product designed, developed and produced in accordance with Annex I Part I (process obligation); Annex I, Part I(2)(f) (supporting): integrity of data, commands, programs and configuration
- **Evidence:** `repo-checks.json`

### EK-BRANCH-PROTECTION: Default branch protected (branch protection or ruleset) (PASS)

`main` requires pull requests (+ non_fast_forward, deletion).

- **KSC:** art. 8 ust. 1 pkt 5 lit. c (supporting): protection against unauthorised modification; art. 8 ust. 1 pkt 2 lit. n (supporting): access control policies
- **CRA:** Art. 13(1) (supporting): product designed, developed and produced in accordance with Annex I Part I (process obligation); Annex I, Part I(2)(d) (supporting): protection from unauthorised access; Annex I, Part I(2)(f) (supporting): integrity of data, commands, programs and configuration
- **OSPS Baseline:** OSPS-AC-03.01, OSPS-AC-03.02, OSPS-QA-07.01
- **Evidence:** `repo-checks.json`

### EK-DEP-UPDATES: Automated dependency updates (Dependabot or Renovate) (PASS)

Dependency update config: .github/dependabot.yml.

- **KSC:** art. 8 ust. 1 pkt 5 lit. b (supporting): regular software updates, following vendor recommendations
- **CRA:** Annex I, Part II(2) (supporting): address and remediate vulnerabilities without delay
- **Evidence:** `repo-checks.json`

### EK-SUPPLIERS: Supplier register present (content needs human review) (WARN)

Supplier register: not found (see templates/).

- **KSC:** art. 8 ust. 1 pkt 2 lit. e (supporting): security and continuity of the ICT supply chain (products, services, processes); art. 8 ust. 2 (supporting): supply-chain measures consider supplier vulnerabilities and overall product quality
- **CRA:** Art. 13(5) (supporting): due diligence when integrating third-party components, incl. open source
- **Evidence:** `repo-checks.json`

### EK-INCIDENT-RUNBOOK: Incident and vulnerability reporting runbook present (WARN)

Incident reporting runbook: not found (see templates/).

- **KSC:** art. 8 ust. 1 pkt 4 (supporting): incident management; art. 11 ust. 1 pkt 4-4c (supporting): significant incident (incydent poważny): early warning within 24 h, notification within 72 h, final report within one month
- **CRA:** Art. 14(1)-(4) (supporting): report actively exploited vulnerabilities and severe incidents via the single reporting platform (24 h / 72 h / final report)
- **Evidence:** `repo-checks.json`

## Evidence files (SHA-256)

| File | SHA-256 | Bytes |
|---|---|---|
| `repo-checks.json` | `055345652c12476e20a621558b79f533c309b1b473aa54e3891e01d9eb1cc81c` | 1911 |
| `sbom.cdx.json` | `e492a09aec2560ca34bdf0fcdf10f9c188db048b034766e2bc5b0249b74b5342` | 3095 |
| `scorecard.json` | `43811c3da7880afe9f2e58fa5709452403229a852070bb53fc902e7a7ffc7d74` | 5328 |
| `secrets.gitleaks.baseline.json` | `6d1f2c23df6e1accdf27a32063d4d31b415fc6299e67d46cc9705fb8b518f381` | 706 |
| `secrets.gitleaks.json` | `6d1f2c23df6e1accdf27a32063d4d31b415fc6299e67d46cc9705fb8b518f381` | 706 |
| `vulnerabilities.trivy.json` | `4ed642216327a45b06061643c760ca128d43cc730c232ce79d388534f4f0ed52` | 13056 |

## Sources

- Polish Act on the National Cybersecurity System (KSC) as amended by Dz.U. 2026 poz. 252: https://eli.gov.pl/eli/DU/2026/252/ogl
- Regulation (EU) 2024/2847 (Cyber Resilience Act): https://eur-lex.europa.eu/eli/reg/2024/2847/oj
- CERT Polska, Good practices for software security management (CRA guide), May 2026: https://cert.pl/uploads/docs/CERT_Polska_Dobre_praktyki_zarzadzania_bezpieczenstwem_oprogramowania.pdf
- OpenSSF Open Source Project Security Baseline: https://baseline.openssf.org

---

Need help closing the gaps? AIRCLOUD: https://aircloud.com.pl/consulting/?from=evidence-kit

Generated by evidence-kit 0.1.0 (https://github.com/AIRCLOUD-PL/evidence-kit), Apache-2.0.
