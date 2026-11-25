# Templates / Szablony

Copy the files you need into your repository and fill in everything in `<angle brackets>`.
The evidence workflow detects them in the locations below and turns the related controls green.

Skopiuj potrzebne pliki do swojego repozytorium i uzupełnij wszystko w `<nawiasach>`.
Workflow wykrywa je w poniższych miejscach i zalicza powiązane kontrole.

| Template (EN) | Szablon (PL) | Copy to / Skopiuj do | Control |
|---|---|---|---|
| `en/SECURITY.md` | `pl/SECURITY.md` | `SECURITY.md` or `.github/SECURITY.md` | EK-SECURITY-POLICY |
| `en/cvd-policy.md` | `pl/polityka-cvd.md` | `docs/` | EK-CVD |
| `en/security.txt` | `pl/security.txt` | `.well-known/security.txt` (and your website) | EK-SECURITY-TXT |
| `en/incident-and-vulnerability-reporting.md` | `pl/incydenty-i-podatnosci-zglaszanie.md` | `docs/` | EK-INCIDENT-RUNBOOK |
| `en/suppliers.yaml`, `en/suppliers.csv` | `pl/dostawcy.yaml`, `pl/dostawcy.csv` | `docs/` | EK-SUPPLIERS |

Detection: policy documents are searched in the repository root (files only) and in `.github/`,
`docs/`, `doc/`, `compliance/`, `security/`, `policies/` (up to 3 levels). `security.txt` is
searched in the whole tree, except `templates/`, `tests/`, `fixtures/`, `examples/`.

These templates are informative and are not legal advice. Deadlines in the runbook were
copied from the primary sources on 2026-11-25; check them again before you rely on them.
Szablony mają charakter informacyjny i nie są poradą prawną. Terminy w procedurze przepisano
ze źródeł pierwotnych 2026-11-25; sprawdź je ponownie przed użyciem.
