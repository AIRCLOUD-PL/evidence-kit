# Raport dowodów bezpieczeństwa łańcucha dostaw oprogramowania

> Mapowanie ma charakter wyłącznie informacyjny. To nie jest porada prawna ani certyfikacja; ustawowy audyt KSC (art. 15) wykonuje uprawniony audytor. Wyniki automatyczne pokazują stan repozytorium w jednym commicie i nie dowodzą istnienia systemu zarządzania bezpieczeństwem informacji.

- **Repozytorium:** `example/demo-app`
- **Commit:** `0123456789ab`
- **Wygenerowano:** 2026-11-25T00:00:00+00:00
- **evidence-kit:** 0.1.0 (mapping 0.1.0, 2026-11-25)
- **Uruchomienie workflow:** https://github.com/example/demo-app/actions/runs/1234567890
- **Narzędzia:** trivy v0.70.0, gitleaks 8.30.1, scorecard_action v2.6.0

## Podsumowanie

| PASS | WARN | FAIL | UNKNOWN | NOT RUN | MANUAL |
|---|---|---|---|---|---|
| 7 | 3 | 2 | 0 | 0 | 10 |

Wyniki: PASS (spełnione), WARN (uwaga), FAIL (niespełnione), UNKNOWN (nie do sprawdzenia), NOT RUN (brak danych), MANUAL (ręcznie).

Czego ten raport nie dowodzi: istnienia systemu zarządzania bezpieczeństwem informacji (SZBI), szacowania ryzyka, ciągłości działania, szkoleń personelu, bezpieczeństwa fizycznego ani przeprowadzenia ustawowego audytu. Te obszary są w kontrolach ręcznych.

## Kontrole automatyczne

| ID | Kontrola | Wynik | Opis wyniku | KSC | CRA |
|---|---|---|---|---|---|
| EK-SBOM | Wykaz komponentów oprogramowania (SBOM, CycloneDX) | **PASS** | SBOM CycloneDX 1.6: pakiety: 4 (z purl: 4). | art. 8 ust. 1 pkt 2 lit. e<br>art. 8 ust. 1 pkt 2 lit. m<br>art. 8 ust. 2 | zał. I część II pkt 1<br>art. 13 ust. 5 |
| EK-VULN | Znane podatności w zależnościach (skan SBOM, opcjonalnie VEX) | **FAIL** | Znane podatności: high: 7, medium: 12; wyłączone przez VEX: 1. | art. 8 ust. 1 pkt 3<br>art. 8 ust. 1 pkt 5 lit. b<br>art. 8 ust. 1 pkt 5 lit. d | zał. I część I pkt 2 lit. a<br>zał. I część II pkt 1<br>zał. I część II pkt 2 |
| EK-SECRETS | Brak sekretów w historii git (gitleaks) | **FAIL** | Potencjalne sekrety w historii git: 1 (typy reguł: 1). Unieważnij je i usuń. | art. 8 ust. 1 pkt 2 lit. n<br>art. 8 ust. 1 pkt 2 lit. j<br>art. 8 ust. 1 pkt 5 lit. a | zał. I część I pkt 2 lit. d<br>zał. I część I pkt 2 lit. e |
| EK-SCORECARD | OpenSSF Scorecard (praktyki bezpieczeństwa repozytorium) | **WARN** | Scorecard 6.2/10 (próg zaliczenia 7.0). Najsłabsze: CII-Best-Practices, Fuzzing, Vulnerabilities, Branch-Protection, Contributors. | art. 8 ust. 1 pkt 2 lit. b<br>art. 8 ust. 1 pkt 2 lit. h | zał. I część II pkt 3 |
| EK-SECURITY-POLICY | Polityka bezpieczeństwa z kontaktem do zgłoszeń (SECURITY.md) | **PASS** | SECURITY.md z kontaktem do zgłoszeń. Prywatne zgłaszanie podatności jest włączone. | art. 8 ust. 1 pkt 3<br>art. 8 ust. 1 pkt 4 | zał. I część II pkt 6<br>art. 13 ust. 17 |
| EK-CVD | Polityka skoordynowanego ujawniania podatności (CVD) | **PASS** | Sekcja CVD w SECURITY.md. | art. 8 ust. 1 pkt 3<br>art. 8 ust. 1 pkt 5 lit. d | zał. I część II pkt 5<br>art. 13 ust. 8 |
| EK-SECURITY-TXT | security.txt (RFC 9116) z polem Contact i ważnym Expires | **PASS** | .well-known/security.txt ważny do 2027-11-01T00:00:00Z. | art. 8 ust. 1 pkt 3 | zał. I część II pkt 6<br>art. 13 ust. 17 |
| EK-CODEOWNERS | Określeni właściciele kodu (CODEOWNERS) | **PASS** | .github/CODEOWNERS: reguł 1. | art. 8 ust. 1 pkt 2 lit. n<br>art. 8 ust. 1 pkt 5 lit. c | zał. I część I pkt 2 lit. f |
| EK-BRANCH-PROTECTION | Chroniona gałąź domyślna (ochrona gałęzi lub ruleset) | **PASS** | Gałąź `main` wymaga pull requestów (+ non_fast_forward, deletion). | art. 8 ust. 1 pkt 5 lit. c<br>art. 8 ust. 1 pkt 2 lit. n | zał. I część I pkt 2 lit. f<br>zał. I część I pkt 2 lit. d |
| EK-DEP-UPDATES | Automatyczne aktualizacje zależności (Dependabot lub Renovate) | **PASS** | Konfiguracja aktualizacji zależności: .github/dependabot.yml. | art. 8 ust. 1 pkt 5 lit. b | zał. I część II pkt 2 |
| EK-SUPPLIERS | Rejestr dostawców w repozytorium (treść wymaga oceny człowieka) | **WARN** | Rejestr dostawców: nie znaleziono (zob. templates/). | art. 8 ust. 1 pkt 2 lit. e<br>art. 8 ust. 2 | art. 13 ust. 5 |
| EK-INCIDENT-RUNBOOK | Procedura zgłaszania incydentów i podatności w repozytorium | **WARN** | Procedura zgłaszania incydentów: nie znaleziono (zob. templates/). | art. 8 ust. 1 pkt 4<br>art. 11 ust. 1 pkt 4-4c | art. 14 ust. 1-4 |

## Kontrole ręczne (dowody do dostarczenia)

| ID | Kontrola | Co dołączyć | KSC | CRA |
|---|---|---|---|---|
| M-RISK | Szacowanie ryzyka i postępowanie z ryzykiem | Aktualny rejestr ryzyk i metodyka, ocena ryzyka produktu (CRA), akceptacja kierownictwa. | art. 8 ust. 1 pkt 1<br>art. 8 ust. 1 pkt 2 lit. a | art. 13 ust. 2-3<br>zał. I część I pkt 1 |
| M-BCP | Ciągłość działania, kopie zapasowe i odtwarzanie | Plan ciągłości działania i odtwarzania, polityka kopii, wynik ostatniego testu odtworzenia. | art. 8 ust. 1 pkt 2 lit. f | zał. I część I pkt 2 lit. h |
| M-CRYPTO | Polityka kryptografii i szyfrowania | Polityka kryptograficzna (algorytmy, zarządzanie kluczami), konfiguracja TLS i szyfrowania danych. | art. 8 ust. 1 pkt 2 lit. k | zał. I część I pkt 2 lit. e |
| M-ACCESS | Kontrola dostępu, MFA i bezpieczeństwo fizyczne | Polityka kontroli dostępu, wymuszenie MFA (np. ustawienie organizacji GitHub), okresowe przeglądy uprawnień. | art. 8 ust. 1 pkt 2 lit. c<br>art. 8 ust. 1 pkt 2 lit. l<br>art. 8 ust. 1 pkt 2 lit. n | zał. I część I pkt 2 lit. d |
| M-PEOPLE | Bezpieczeństwo personelu, szkolenia i cyberhigiena | Ewidencja szkoleń personelu i corocznego szkolenia kierownika (art. 8e), procedura przyjęcia i odejścia pracownika. | art. 8 ust. 1 pkt 2 lit. d<br>art. 8 ust. 1 pkt 2 lit. i<br>art. 8 ust. 1 pkt 2 lit. j<br>art. 8e | - |
| M-MONITORING | Monitorowanie w trybie ciągłym i obsługa incydentów | Zakres monitorowania (SIEM), alarmowanie, rejestr incydentów, przećwiczone zgłoszenie. | art. 8 ust. 1 pkt 2 lit. g<br>art. 8 ust. 1 pkt 4 | zał. I część I pkt 2 lit. l |
| M-ASSETS | Inwentaryzacja aktywów | Wykaz systemów, usług i repozytoriów objętych zakresem, z właścicielami. | art. 8 ust. 1 pkt 2 lit. m | - |
| M-UPDATES | Dostarczanie aktualizacji zabezpieczeń, komunikaty i okres wsparcia | Proces wydań (podpisane wydania), publikowane komunikaty o naprawionych podatnościach, zadeklarowany okres wsparcia. | art. 8 ust. 1 pkt 5 lit. b | zał. I część I pkt 2 lit. c<br>zał. I część II pkt 4<br>zał. I część II pkt 7<br>zał. I część II pkt 8<br>art. 13 ust. 8 |
| M-SECURE-DESIGN | Bezpieczna konfiguracja domyślna i ograniczona powierzchnia ataku | Model zagrożeń lub przegląd projektu, standard utwardzania, przegląd konfiguracji domyślnej. | art. 8 ust. 1 pkt 2 lit. b | zał. I część I pkt 2 lit. b<br>zał. I część I pkt 2 lit. j |
| M-AUDIT | Ustawowy audyt bezpieczeństwa | Sprawozdanie z audytu przeprowadzonego przez uprawnionego audytora (podmioty kluczowe). Ten zestaw go nie zastępuje. | art. 15 ust. 1 | - |

## Szczegóły

### EK-SBOM: Wykaz komponentów oprogramowania (SBOM, CycloneDX) (PASS)

SBOM CycloneDX 1.6: pakiety: 4 (z purl: 4).

- **KSC:** art. 8 ust. 1 pkt 2 lit. e: bezpieczeństwo i ciągłość łańcucha dostaw produktów, usług i procesów ICT; art. 8 ust. 1 pkt 2 lit. m: zarządzanie aktywami; art. 8 ust. 2: przy łańcuchu dostaw uwzględnia się podatności i ogólną jakość produktów dostawcy
- **CRA:** zał. I część II pkt 1: identyfikowanie i dokumentowanie podatności i komponentów, w tym SBOM; art. 13 ust. 5: należyta staranność przy integrowaniu komponentów stron trzecich, w tym open source
- **OSPS Baseline:** OSPS-QA-02.01, OSPS-QA-02.02
- **Dowody:** `sbom.cdx.json`

### EK-VULN: Znane podatności w zależnościach (skan SBOM, opcjonalnie VEX) (FAIL)

Znane podatności: high: 7, medium: 12; wyłączone przez VEX: 1.

- **KSC:** art. 8 ust. 1 pkt 3: zbieranie informacji o cyberzagrożeniach i podatnościach; art. 8 ust. 1 pkt 5 lit. b: regularne aktualizacje oprogramowania stosownie do zaleceń producenta; art. 8 ust. 1 pkt 5 lit. d: niezwłoczne działania po dostrzeżeniu podatności lub cyberzagrożeń
- **CRA:** zał. I część I pkt 2 lit. a: udostępniane bez znanych i możliwych do wykorzystania podatności; zał. I część II pkt 1: identyfikowanie i dokumentowanie podatności i komponentów, w tym SBOM; zał. I część II pkt 2: bezzwłoczne reagowanie na podatności i ich eliminowanie
- **OSPS Baseline:** OSPS-VM-05.03, OSPS-VM-04.02
- **Dowody:** `vulnerabilities.trivy.json`, `sbom.cdx.json`

| Waga | Liczba | Z poprawką |
|---|---|---|
| CRITICAL | 0 | 0 |
| HIGH | 7 | 7 |
| MEDIUM | 12 | 12 |
| LOW | 0 | 0 |
| UNKNOWN | 0 | 0 |

| ID | Waga | Pakiet | Wersja | Poprawka w |
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

### EK-SECRETS: Brak sekretów w historii git (gitleaks) (FAIL)

Potencjalne sekrety w historii git: 1 (typy reguł: 1). Unieważnij je i usuń.

- **KSC:** art. 8 ust. 1 pkt 2 lit. n: polityki kontroli dostępu; art. 8 ust. 1 pkt 2 lit. j: podstawowe zasady cyberhigieny; art. 8 ust. 1 pkt 5 lit. a: mechanizmy zapewniające poufność, integralność, dostępność i autentyczność danych
- **CRA:** zał. I część I pkt 2 lit. d: ochrona przed nieuprawnionym dostępem; zał. I część I pkt 2 lit. e: poufność danych, np. szyfrowanie danych odłożonych i przesyłanych
- **OSPS Baseline:** OSPS-BR-07.01
- **Dowody:** `secrets.gitleaks.json`

Wartości sekretów są zamaskowane; pokazano tylko regułę, plik, linię i commit.

| Reguła | Plik | Linia | Commit |
|---|---|---|---|
| generic-api-key | `config/settings.example.py` | 12 | `4f2c1d9e8b7a` |

### EK-SCORECARD: OpenSSF Scorecard (praktyki bezpieczeństwa repozytorium) (WARN)

Scorecard 6.2/10 (próg zaliczenia 7.0). Najsłabsze: CII-Best-Practices, Fuzzing, Vulnerabilities, Branch-Protection, Contributors.

- **KSC:** art. 8 ust. 1 pkt 2 lit. b: bezpieczeństwo w procesie nabywania, rozwoju, utrzymania i eksploatacji, w tym testowanie; art. 8 ust. 1 pkt 2 lit. h: polityki i procedury oceny skuteczności środków technicznych i organizacyjnych
- **CRA:** zał. I część II pkt 3: skuteczne i regularne testy oraz przeglądy bezpieczeństwa
- **Dowody:** `scorecard.json`

| Sprawdzenie | Ocena |
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

### EK-SECURITY-POLICY: Polityka bezpieczeństwa z kontaktem do zgłoszeń (SECURITY.md) (PASS)

SECURITY.md z kontaktem do zgłoszeń. Prywatne zgłaszanie podatności jest włączone.

- **KSC:** art. 8 ust. 1 pkt 3: zbieranie informacji o cyberzagrożeniach i podatnościach; art. 8 ust. 1 pkt 4: zarządzanie incydentami
- **CRA:** zał. I część II pkt 6: ułatwianie wymiany informacji o podatnościach, w tym adres kontaktowy; art. 13 ust. 17: pojedynczy punkt kontaktowy dla użytkowników, w tym do zgłaszania podatności
- **OSPS Baseline:** OSPS-VM-02.01, OSPS-VM-03.01
- **Dowody:** `repo-checks.json`

### EK-CVD: Polityka skoordynowanego ujawniania podatności (CVD) (PASS)

Sekcja CVD w SECURITY.md.

- **KSC:** art. 8 ust. 1 pkt 3: zbieranie informacji o cyberzagrożeniach i podatnościach; art. 8 ust. 1 pkt 5 lit. d: niezwłoczne działania po dostrzeżeniu podatności lub cyberzagrożeń
- **CRA:** zał. I część II pkt 5: polityka skoordynowanego ujawniania podatności; art. 13 ust. 8: skuteczne postępowanie z podatnościami w okresie wsparcia
- **OSPS Baseline:** OSPS-VM-01.01
- **Dowody:** `repo-checks.json`

### EK-SECURITY-TXT: security.txt (RFC 9116) z polem Contact i ważnym Expires (PASS)

.well-known/security.txt ważny do 2027-11-01T00:00:00Z.

- **KSC:** art. 8 ust. 1 pkt 3: zbieranie informacji o cyberzagrożeniach i podatnościach
- **CRA:** zał. I część II pkt 6: ułatwianie wymiany informacji o podatnościach, w tym adres kontaktowy; art. 13 ust. 17: pojedynczy punkt kontaktowy dla użytkowników, w tym do zgłaszania podatności
- **Dowody:** `repo-checks.json`

### EK-CODEOWNERS: Określeni właściciele kodu (CODEOWNERS) (PASS)

.github/CODEOWNERS: reguł 1.

- **KSC:** art. 8 ust. 1 pkt 2 lit. n: polityki kontroli dostępu; art. 8 ust. 1 pkt 5 lit. c: ochrona przed nieuprawnioną modyfikacją w systemie informacyjnym
- **CRA:** zał. I część I pkt 2 lit. f: integralność danych, komend, programów i konfiguracji
- **Dowody:** `repo-checks.json`

### EK-BRANCH-PROTECTION: Chroniona gałąź domyślna (ochrona gałęzi lub ruleset) (PASS)

Gałąź `main` wymaga pull requestów (+ non_fast_forward, deletion).

- **KSC:** art. 8 ust. 1 pkt 5 lit. c: ochrona przed nieuprawnioną modyfikacją w systemie informacyjnym; art. 8 ust. 1 pkt 2 lit. n: polityki kontroli dostępu
- **CRA:** zał. I część I pkt 2 lit. f: integralność danych, komend, programów i konfiguracji; zał. I część I pkt 2 lit. d: ochrona przed nieuprawnionym dostępem
- **OSPS Baseline:** OSPS-AC-03.01, OSPS-AC-03.02, OSPS-QA-07.01
- **Dowody:** `repo-checks.json`

### EK-DEP-UPDATES: Automatyczne aktualizacje zależności (Dependabot lub Renovate) (PASS)

Konfiguracja aktualizacji zależności: .github/dependabot.yml.

- **KSC:** art. 8 ust. 1 pkt 5 lit. b: regularne aktualizacje oprogramowania stosownie do zaleceń producenta
- **CRA:** zał. I część II pkt 2: bezzwłoczne reagowanie na podatności i ich eliminowanie
- **Dowody:** `repo-checks.json`

### EK-SUPPLIERS: Rejestr dostawców w repozytorium (treść wymaga oceny człowieka) (WARN)

Rejestr dostawców: nie znaleziono (zob. templates/).

- **KSC:** art. 8 ust. 1 pkt 2 lit. e: bezpieczeństwo i ciągłość łańcucha dostaw produktów, usług i procesów ICT; art. 8 ust. 2: przy łańcuchu dostaw uwzględnia się podatności i ogólną jakość produktów dostawcy
- **CRA:** art. 13 ust. 5: należyta staranność przy integrowaniu komponentów stron trzecich, w tym open source
- **Dowody:** `repo-checks.json`

### EK-INCIDENT-RUNBOOK: Procedura zgłaszania incydentów i podatności w repozytorium (WARN)

Procedura zgłaszania incydentów: nie znaleziono (zob. templates/).

- **KSC:** art. 8 ust. 1 pkt 4: zarządzanie incydentami; art. 11 ust. 1 pkt 4-4c: incydent poważny: wczesne ostrzeżenie do 24 h, zgłoszenie do 72 h, sprawozdanie końcowe w ciągu miesiąca
- **CRA:** art. 14 ust. 1-4: zgłaszanie aktywnie wykorzystywanych podatności i poważnych incydentów przez pojedynczą platformę zgłaszania (24 h / 72 h / raport końcowy)
- **Dowody:** `repo-checks.json`

## Pliki dowodowe (SHA-256)

| Plik | SHA-256 | Bajty |
|---|---|---|
| `repo-checks.json` | `91ebda29928f1844bf25f6a5d1ff24a9104ffd54ab6851d2188de0a940593698` | 1769 |
| `sbom.cdx.json` | `e492a09aec2560ca34bdf0fcdf10f9c188db048b034766e2bc5b0249b74b5342` | 3095 |
| `scorecard.json` | `43811c3da7880afe9f2e58fa5709452403229a852070bb53fc902e7a7ffc7d74` | 5328 |
| `secrets.gitleaks.json` | `6d1f2c23df6e1accdf27a32063d4d31b415fc6299e67d46cc9705fb8b518f381` | 706 |
| `vulnerabilities.trivy.json` | `4ed642216327a45b06061643c760ca128d43cc730c232ce79d388534f4f0ed52` | 13056 |

## Źródła

- Ustawa o krajowym systemie cyberbezpieczeństwa w brzmieniu nadanym ustawą z 23.01.2026 r. (Dz.U. 2026 poz. 252): https://eli.gov.pl/eli/DU/2026/252/ogl
- Rozporządzenie (UE) 2024/2847 (akt o cyberodporności, CRA): https://eur-lex.europa.eu/eli/reg/2024/2847/oj
- CERT Polska, Dobre praktyki zarządzania bezpieczeństwem oprogramowania (poradnik CRA), maj 2026: https://cert.pl/uploads/docs/CERT_Polska_Dobre_praktyki_zarzadzania_bezpieczenstwem_oprogramowania.pdf
- OpenSSF Open Source Project Security Baseline: https://baseline.openssf.org

---

Potrzebujesz pomocy w domknięciu luk? AIRCLOUD: https://aircloud.com.pl/consulting/?from=evidence-kit

Wygenerowano przez evidence-kit 0.1.0 (https://github.com/lkolo-prez/evidence-kit), Apache-2.0.
