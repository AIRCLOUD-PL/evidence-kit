# Procedura zgłaszania incydentów i podatności (KSC i CRA)

<!-- Szablon z evidence-kit (Apache-2.0). Uzupełnij wszystko w <nawiasach>.
     Terminy przepisano z: art. 11 ust. 1 pkt 4-4c i art. 12a-12c ustawy o KSC w brzmieniu
     nadanym ustawą z 23.01.2026 r. (Dz.U. 2026 poz. 252) oraz art. 14 rozporządzenia
     (UE) 2024/2847 (CRA). Stan na 2026-11-25. To nie jest porada prawna: zakres obowiązków
     zależy od tego, czy jesteś podmiotem kluczowym/ważnym (KSC) i producentem (CRA).
     Sprawdź aktualne brzmienie przepisów i rozporządzeń wykonawczych. -->

**Właściciel procedury:** <rola> · **Zastępca:** <rola> · **Wersja:** <1.0> · **Przegląd:** co <12> miesięcy i po każdym incydencie

## 0. Kiedy stosować
| Sytuacja | Reżim | Sekcja |
|---|---|---|
| Incydent poważny w systemie informacyjnym, za pomocą którego świadczymy usługę | KSC (podmiot kluczowy lub ważny) | 2 |
| Aktywnie wykorzystywana podatność w naszym produkcie z elementami cyfrowymi | CRA (producent) | 3 |
| Poważny incydent mający wpływ na bezpieczeństwo naszego produktu | CRA (producent) | 3 |
| Zgłoszenie podatności od badacza, bez oznak wykorzystania | polityka CVD | `polityka-cvd.md` |

Jedno zdarzenie może podlegać obu reżimom. Wtedy prowadzimy dwa zgłoszenia równolegle.

## 1. Pierwsza godzina (wspólne)
1. Zapisz **czas wykrycia** (KSC) lub **czas uzyskania wiedzy** (CRA) w rejestrze: <link do rejestru>.
2. Powołaj kierownika obsługi incydentu: <rola> i kanał komunikacji: <kanał>.
3. Zabezpiecz dowody (logi, obrazy, wersje, SBOM z artefaktu `evidence`).
4. Oceń wstępnie: czy to incydent poważny (KSC), aktywnie wykorzystywana podatność lub poważny
   incydent dotyczący produktu (CRA, art. 14 ust. 5)?
5. Zawiadom kierownictwo: <osoba>. Kierownik podmiotu odpowiada za wykonanie obowiązków (KSC art. 8c).

## 2. KSC: incydent poważny (podmiot kluczowy lub ważny)
Zgłoszenia przekazuje się do właściwego CSIRT sektorowego za pomocą systemu
teleinformatycznego, o którym mowa w art. 46 ust. 1 ustawy (art. 11 ust. 2).
Właściwy CSIRT dla naszego sektora: <nazwa, kontakt>.

| Krok | Termin | Podstawa | Kto | Gotowe |
|---|---|---|---|---|
| Wczesne ostrzeżenie | niezwłocznie, nie później niż **24 h od wykrycia** | art. 11 ust. 1 pkt 4 | <rola> | [ ] |
| Zgłoszenie incydentu poważnego | niezwłocznie, nie później niż **72 h od wykrycia** | art. 11 ust. 1 pkt 4a | <rola> | [ ] |
| Sprawozdanie okresowe | na wniosek CSIRT sektorowego | art. 11 ust. 1 pkt 4b | <rola> | [ ] |
| Sprawozdanie końcowe | nie później niż **w ciągu miesiąca od dnia zgłoszenia** (pkt 4a) | art. 11 ust. 1 pkt 4c, art. 12a | <rola> | [ ] |
| Sprawozdanie z postępu (gdy obsługa trwa dłużej) | w terminie sprawozdania końcowego; końcowe w ciągu miesiąca od zakończenia obsługi | art. 12b | <rola> | [ ] |

Sprawozdanie końcowe zawiera (art. 12a): szczegółowy opis incydentu, w tym zakłócenia i szkody;
rodzaj zagrożenia lub prawdopodobną przyczynę; zastosowane i wdrażane środki ograniczające
ryzyko; skutki transgraniczne, jeśli wystąpiły.

Dodatkowo: przy poważnym cyberzagrożeniu poinformuj użytkowników usług o możliwych środkach
zapobiegawczych (art. 11 ust. 2a). Wyjątki: dostawcy usług zaufania zgłaszają incydent poważny
w ciągu 24 h (art. 11 ust. 1a); podmioty ważne będące podmiotami publicznymi mają odrębne
zasady (art. 12c).

## 3. CRA: producent produktu z elementami cyfrowymi (od 11.09.2026)
Zgłoszenia składa się przez pojedynczą platformę zgłaszania (single reporting platform, art. 16),
do punktu końcowego CSIRT wyznaczonego jako koordynator w państwie głównego miejsca prowadzenia
działalności, jednocześnie dostępne dla ENISA (art. 14 ust. 7). CSIRT koordynator: <ustal>.

### 3a. Aktywnie wykorzystywana podatność (art. 14 ust. 1-2)
| Krok | Termin | Podstawa | Gotowe |
|---|---|---|---|
| Wczesne ostrzeżenie (w tym państwa członkowskie, w których udostępniono produkt) | bez zbędnej zwłoki, najpóźniej **24 h od uzyskania wiedzy** | art. 14 ust. 2 lit. a | [ ] |
| Zgłoszenie podatności (charakter exploita i podatności, środki naprawcze, wrażliwość informacji) | najpóźniej **72 h od uzyskania wiedzy** | art. 14 ust. 2 lit. b | [ ] |
| Raport końcowy (opis i waga, informacje o sprawcy, szczegóły aktualizacji) | najpóźniej **14 dni od udostępnienia środka naprawczego lub ograniczającego** | art. 14 ust. 2 lit. c | [ ] |

### 3b. Poważny incydent mający wpływ na bezpieczeństwo produktu (art. 14 ust. 3-5)
| Krok | Termin | Podstawa | Gotowe |
|---|---|---|---|
| Wczesne ostrzeżenie (w tym czy podejrzewa się działanie bezprawne lub złośliwe) | bez zbędnej zwłoki, najpóźniej **24 h od uzyskania wiedzy** | art. 14 ust. 4 lit. a | [ ] |
| Zgłoszenie incydentu (wstępna ocena, środki) | najpóźniej **72 h od uzyskania wiedzy** | art. 14 ust. 4 lit. b | [ ] |
| Raport końcowy (opis, przyczyna, środki) | **w ciągu miesiąca od zgłoszenia incydentu** | art. 14 ust. 4 lit. c | [ ] |

CSIRT koordynator może poprosić o raport pośredni (art. 14 ust. 6). Po uzyskaniu wiedzy
poinformuj użytkowników, których to dotyczy, o podatności lub incydencie i o środkach, które
mogą zastosować, w miarę możliwości w formacie maszynowym (art. 14 ust. 8), np. komunikat
CSAF lub VEX.

## 4. Po zdarzeniu
- [ ] Wpis w rejestrze incydentów i podatności z datami wszystkich zgłoszeń.
- [ ] Poprawka, komunikat bezpieczeństwa i (dla CRA) aktualizacja VEX / SBOM.
- [ ] Analiza przyczyn i aktualizacja szacowania ryzyka.
- [ ] Przegląd tej procedury (data, zmiany).

## 5. Ćwiczenia
Ćwiczymy procedurę co najmniej raz w roku (scenariusz stołowy). Ostatnie ćwiczenie: <data>, wnioski: <link>.
