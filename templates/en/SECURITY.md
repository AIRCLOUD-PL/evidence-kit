# Security policy

<!-- Template from evidence-kit (Apache-2.0). Replace everything in <angle brackets>. -->

## Supported versions

| Version | Supported until | Security updates |
|---|---|---|
| <2.x> | <YYYY-MM-DD> | yes |
| <1.x> | <YYYY-MM-DD> | critical fixes only |
| older | - | no |

The support period is the time during which we handle vulnerabilities and publish
security updates (see Regulation (EU) 2024/2847, Art. 13(8), if it applies to you).

## Reporting a vulnerability

Please **do not** open a public issue. Use one of these private channels:

- GitHub: **Security > Report a vulnerability** (private vulnerability reporting), or
- e-mail: **<security@example.com>** (PGP key: <URL or fingerprint>).

Please include: affected product and version, a description, steps to reproduce or a
proof of concept, the impact you expect, and whether you believe it is actively exploited.

Our machine-readable contact is published in `/.well-known/security.txt` (RFC 9116).

## What happens next

| Step | Target time |
|---|---|
| Acknowledgement of your report | <3> business days |
| Initial assessment (valid, severity, exploited?) | <7> days |
| Fix or mitigation for critical/high issues | <30> days, depending on complexity |
| Public advisory after the fix | with the release, or as agreed with you |

## Coordinated vulnerability disclosure

We follow coordinated vulnerability disclosure (CVD). The full policy, including safe-harbour
terms and the default 90-day disclosure window, is in
[`docs/cvd-policy.md`](docs/cvd-policy.md). We publish fixed vulnerabilities as
GitHub Security Advisories and, where appropriate, request a CVE identifier.

If a report concerns a vulnerability that is actively exploited, we also follow our
incident and vulnerability reporting runbook (`docs/incident-and-vulnerability-reporting.md`).

## Security updates

Security fixes are released separately from feature changes where technically feasible,
announced in the release notes and the advisory, and provided free of charge.
