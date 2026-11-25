# Incident runbook (evidence-kit itself)

evidence-kit is a free, non-commercial open-source tool. This short runbook covers incidents
that affect the kit and its users, for example a compromised pinned action or binary.
The full, reusable template for organisations (KSC and CRA deadlines) is in
[`templates/en/incident-and-vulnerability-reporting.md`](../templates/en/incident-and-vulnerability-reporting.md)
and [`templates/pl/incydenty-i-podatnosci-zglaszanie.md`](../templates/pl/incydenty-i-podatnosci-zglaszanie.md).

**Owner:** maintainer (office@aircloud.com.pl)

1. **Detect and record** the time we became aware (advisory, report, failed checksum, Scorecard alert).
2. **Contain** within 24 h: pin away from the affected action/binary version or disable the
   affected step; publish a GitHub Security Advisory draft.
3. **Inform users** without delay: advisory with affected kit versions, whether evidence produced
   with them can be trusted, and what to do (upgrade the pinned SHA).
4. **Fix and release** a patch version; update `docs/suppliers.yaml`.
5. **Review**: root cause, lessons learned, update this runbook.
