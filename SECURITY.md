# Security policy

evidence-kit runs inside other people's CI pipelines, so we treat its own supply chain
seriously: pinned actions, checksum-verified binaries, hash-pinned Python dependencies,
least-privilege permissions and a self-check on every change.

## Supported versions

| Version | Supported |
|---|---|
| latest release (v0.1.x) | yes |
| `main` | best effort |
| older releases | no |

## Reporting a vulnerability

Please **do not** open a public issue. Report privately via:

- GitHub: **Security > Report a vulnerability** in this repository, or
- e-mail: **office@aircloud.com.pl** with the subject `SECURITY: evidence-kit`.

Include the affected version or commit, a description, steps to reproduce and the impact you
expect. Machine-readable contact: [`.well-known/security.txt`](.well-known/security.txt).

| Step | Target |
|---|---|
| Acknowledge the report | 3 business days |
| Initial assessment | 7 days |
| Fix for critical / high issues | 30 days |

## Coordinated vulnerability disclosure

We follow coordinated vulnerability disclosure: we agree a disclosure date with the reporter
(default: 90 days or when a fix is released, whichever is first), publish a GitHub Security
Advisory with affected versions, impact and remediation, and credit the reporter if they wish.
We do not take legal action against good-faith research that follows this policy.

Vulnerabilities in the tools we compose (Trivy, gitleaks, OpenSSF Scorecard, GitHub Actions)
should be reported to their maintainers; tell us as well if evidence-kit pins an affected version.
Our runbook for actively exploited issues: [`docs/incident-runbook.md`](docs/incident-runbook.md).
