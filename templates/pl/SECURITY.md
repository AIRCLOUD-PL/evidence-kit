# Polityka bezpieczeństwa

<!-- Szablon z evidence-kit (Apache-2.0). Uzupełnij wszystko w <nawiasach>. -->

## Wspierane wersje

| Wersja | Wsparcie do | Aktualizacje zabezpieczeń |
|---|---|---|
| <2.x> | <RRRR-MM-DD> | tak |
| <1.x> | <RRRR-MM-DD> | tylko krytyczne |
| starsze | - | nie |

Okres wsparcia to czas, w którym obsługujemy podatności i publikujemy aktualizacje
zabezpieczeń (zob. art. 13 ust. 8 rozporządzenia (UE) 2024/2847, jeśli Cię obowiązuje).

## Zgłaszanie podatności

**Nie** zakładaj publicznego zgłoszenia (issue). Skorzystaj z jednego z kanałów poufnych:

- GitHub: **Security > Report a vulnerability** (prywatne zgłaszanie podatności), albo
- e-mail: **<security@example.com>** (klucz PGP: <adres lub odcisk>).

W zgłoszeniu podaj: produkt i wersję, opis, kroki odtworzenia lub dowód koncepcji (PoC),
przewidywany wpływ oraz to, czy podatność jest Twoim zdaniem aktywnie wykorzystywana.

Kontakt w formacie maszynowym publikujemy w `/.well-known/security.txt` (RFC 9116).

## Co dzieje się dalej

| Etap | Termin docelowy |
|---|---|
| Potwierdzenie otrzymania zgłoszenia | <3> dni robocze |
| Wstępna ocena (zasadność, waga, czy wykorzystywana) | <7> dni |
| Poprawka lub obejście dla krytycznych i wysokich | <30> dni, zależnie od złożoności |
| Publiczny komunikat po poprawce | razem z wydaniem lub w uzgodnionym terminie |

## Skoordynowane ujawnianie podatności

Stosujemy skoordynowane ujawnianie podatności (CVD). Pełna polityka, z zasadami
bezpiecznej przystani (safe harbour) i domyślnym 90-dniowym terminem ujawnienia,
jest w [`docs/polityka-cvd.md`](docs/polityka-cvd.md). Naprawione podatności publikujemy
jako GitHub Security Advisories i w razie potrzeby występujemy o identyfikator CVE
(np. przez CERT Polska, który ma status CNA: https://cert.pl/cvd/).

Jeśli zgłoszenie dotyczy podatności aktywnie wykorzystywanej, stosujemy też procedurę
zgłaszania incydentów i podatności (`docs/incydenty-i-podatnosci-zglaszanie.md`).

## Aktualizacje zabezpieczeń

Poprawki bezpieczeństwa wydajemy, gdy to technicznie wykonalne, oddzielnie od zmian
funkcjonalnych, opisujemy je w informacjach o wydaniu i w komunikacie oraz udostępniamy
bezpłatnie.
