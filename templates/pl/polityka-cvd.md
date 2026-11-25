# Polityka skoordynowanego ujawniania podatności (CVD)

<!-- Szablon z evidence-kit (Apache-2.0). Uzupełnij wszystko w <nawiasach>.
     Wspiera: CRA zał. I część II pkt 5-6 i art. 13 ust. 17; KSC art. 8 ust. 1 pkt 3 i pkt 5 lit. d.
     Materiał informacyjny, nie jest poradą prawną. -->

**Właściciel:** <rola, np. kierownik ds. bezpieczeństwa produktu> · **Wersja:** <1.0> · **Obowiązuje od:** <RRRR-MM-DD>

## 1. Zakres
Polityka obejmuje <produkty, usługi, repozytoria i domeny>. Poza zakresem:
<usługi stron trzecich, których nie utrzymujemy, socjotechnika, ataki fizyczne, testy DoS>.

## 2. Jak zgłosić
- Kanał poufny: <security@example.com> albo prywatne zgłoszenie podatności na GitHubie.
- Kontakt w formacie maszynowym: `https://<twoja-domena>/.well-known/security.txt`.
- Języki: <polski, angielski>.
- Nie uzyskuj dostępu do cudzych danych, nie zmieniaj ich ani nie usuwaj; przerwij testy po
  potwierdzeniu problemu.

## 3. Nasze zobowiązania
| Etap | Termin docelowy |
|---|---|
| Potwierdzenie zgłoszenia | <3> dni robocze |
| Analiza i ocena wagi (CVSS) | <7> dni |
| Informowanie zgłaszającego | co najmniej co <14> dni |
| Poprawka krytycznych i wysokich | <30> dni, pozostałe w najbliższym wydaniu |
| Podziękowanie (jeśli chcesz) | w komunikacie |

## 4. Ujawnienie
- Domyślne embargo: **90 dni** od zgłoszenia albo do udostępnienia poprawki, zależnie od tego,
  co nastąpi wcześniej. Inny termin możemy uzgodnić ze zgłaszającym.
- Po udostępnieniu aktualizacji publikujemy komunikat: opis, wersje, których dotyczy, wpływ
  i wagę oraz sposób usunięcia (CRA zał. I część II pkt 4). W uzasadnionych przypadkach możemy
  opóźnić publikację, aż użytkownicy będą mogli zainstalować poprawkę.
- Dla potwierdzonych podatności występujemy o identyfikator CVE, samodzielnie lub przez CNA
  (np. CERT Polska: https://cert.pl/cvd/). W przypadku podatności o istotnym wpływie
  CERT Polska zachęca do współpracy przy koordynacji ujawnienia.
- Podatności w komponentach stron trzecich zgłaszamy ich opiekunom (CRA art. 13 ust. 6).

## 5. Podatności aktywnie wykorzystywane
Jeśli podatność jest aktywnie wykorzystywana, stosujemy procedurę zgłaszania incydentów
i podatności (wczesne ostrzeżenie do 24 h). Może to skrócić embargo.

## 6. Bezpieczna przystań (safe harbour)
Nie podejmiemy kroków prawnych wobec badań prowadzonych w dobrej wierze i zgodnie z tą
polityką. W razie wątpliwości zapytaj najpierw: <security@example.com>.

## 7. Ewidencja
Każde zgłoszenie rejestrujemy (data wpływu, analiza, decyzje, daty poprawki i ujawnienia).
Rejestr jest dowodem na potrzeby audytu i przechowujemy go przez <N> lat.
