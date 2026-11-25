# Coordinated vulnerability disclosure (CVD) policy

<!-- Template from evidence-kit (Apache-2.0). Replace everything in <angle brackets>.
     Supports: CRA Annex I Part II(5)-(6) and Art. 13(17); KSC art. 8 ust. 1 pkt 3 and pkt 5 lit. d.
     Informative only, not legal advice. -->

**Owner:** <role, e.g. Product Security Lead> · **Version:** <1.0> · **Effective:** <YYYY-MM-DD>

## 1. Scope
This policy covers <products, services, repositories and domains>. Out of scope:
<third-party services we do not operate, social engineering, physical attacks, DoS testing>.

## 2. How to report
- Private channel: <security@example.com> or GitHub private vulnerability reporting.
- Machine-readable contact: `https://<your-domain>/.well-known/security.txt`.
- Languages: <English, Polish>.
- Please do not access, modify or delete data that is not yours, and stop testing once you
  have confirmed the issue.

## 3. Our commitments
| Step | Target |
|---|---|
| Acknowledge the report | <3> business days |
| Triage and severity (CVSS) | <7> days |
| Keep you informed | at least every <14> days |
| Fix critical / high | <30> days, others in the next regular release |
| Credit (if you want it) | in the advisory |

## 4. Disclosure
- Default embargo: **90 days** from the report or until a fix is available, whichever is first.
  We may agree a different date with the reporter.
- After a security update is available we publish an advisory with: description, affected
  versions, impact and severity, and remediation steps (CRA Annex I Part II(4)). We may delay
  publication in duly justified cases until users had a chance to apply the patch.
- We request a CVE identifier for confirmed vulnerabilities, ourselves or through a CNA
  (for example CERT Polska: https://cert.pl/cvd/).
- Vulnerabilities found in third-party components we use are reported to their maintainers
  (CRA Art. 13(6)).

## 5. Actively exploited vulnerabilities
If a vulnerability is actively exploited, the incident and vulnerability reporting runbook
applies (24 h early warning). This may shorten the embargo.

## 6. Safe harbour
We will not take legal action against research done in good faith and in line with this
policy. If in doubt, ask us first at <security@example.com>.

## 7. Records
Every report is logged (date received, triage, decisions, dates of fix and disclosure). The
log is evidence for audits and is kept for <N> years.
