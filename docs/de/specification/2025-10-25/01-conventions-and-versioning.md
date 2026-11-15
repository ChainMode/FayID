---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: de
canonical: false
chapter: 1
---

# Kapitel 1: Normative Konventionen, Kernterminologie und Versionsführung

## 1.1 Geltungsbereich und Nicht-Ziele

FayID 1.0 definiert für das gesamte iFay-Ökosystem selbstsouveräne Identitätsbezeichner, die Ableitung zweckgebundener Unterschlüssel, Invarianten für Entitätseigentum und Organisationshierarchien, nicht verkettbare Dynamic Codes, den Autorisierungsaustausch für Bestandsanmeldedaten, den kaskadierenden Widerruf sowie datenschutzfreundliche Anker natürlicher Personen für `GMChain`.

Folgende Aufgabenbereiche liegen ausdrücklich außerhalb des Geltungsbereichs von FayID 1.0:

1. **Transport-Framing und Sitzungsaufbau**: Nachrichtenrahmung und Transportsicherheit zwischen Agenten sind Gegenstand der Faying-Protokollfamilie; FayID liefert dafür Identitätsprimitive, Signaturumschläge und Verifikationsquittungen.
2. **Laufzeit-Prozesssteuerung**: Die Prozessorchestrierung von `iFay`- und `coFay`-Instanzen auf Endgeräten obliegt der FayGer-Laufzeitumgebung.
3. **Reputationsverbuchung und Berechnung von Governance-Gewichten**: Akkumulation und Governance-Gewichtung von `MeriToken` legt `GMChain` eigenständig fest. FayID wahrt gegenüber `GMChain` eine rein lesende Grenze und gibt ausschließlich den blinden Anker `gmcref_` aus.
4. **Zentrale Identitätsprüfung (KYC)**: FayID 1.0 setzt weder ein zentrales Verzeichnis noch eine Wurzelzertifizierungsstelle voraus.

## 1.2 Normative Schlüsselwörter (Normativ)

Die normativen Schlüsselwörter in diesem Dokument sind gemäß [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) und [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) genau dann im dort definierten Sinn auszulegen, wenn sie vollständig in Großbuchstaben gesetzt sind. In dieser deutschen Ausgabe gelten die nachstehenden deutschen Entsprechungen gleichrangig zu den englischen RFC-Schlüsselwörtern:

| Schlüsselwort nach RFC 2119 / RFC 8174 | Deutsches normatives Äquivalent | Normative Bedeutung |
| --- | --- | --- |
| `MUST` / `SHALL` / `REQUIRED` | `MUSS` / `MÜSSEN` / `ERFORDERLICH` | Unbedingte Protokollanforderung; jeder Verstoß führt zur Nichtkonformität der Implementierung |
| `MUST NOT` / `SHALL NOT` | `DARF NICHT` / `DÜRFEN NICHT` | Unbedingtes Protokollverbot; jeder Verstoß führt zur Nichtkonformität der Implementierung |
| `SHOULD` / `RECOMMENDED` | `SOLLTE` / `SOLLTEN` / `EMPFOHLEN` | Verbindliche Standardvorgabe, von der nur aus dokumentierten technischen Gründen abgewichen werden darf |
| `SHOULD NOT` / `NOT RECOMMENDED` | `SOLLTE NICHT` / `SOLLTEN NICHT` / `NICHT EMPFOHLEN` | Verhalten, das außer aus dokumentierten technischen Gründen unterbleiben sollte |
| `MAY` / `OPTIONAL` | `DARF` / `DÜRFEN` / `OPTIONAL` | Frei wählbares Leistungsmerkmal; interoperable Gegenstellen müssen sowohl dessen Vorhandensein als auch dessen Fehlen verarbeiten können |

## 1.3 Kernterminologie (Normativ)

Alle Implementierungen, Schemata und abgeleiteten Dokumente `MÜSSEN` die folgenden Begriffsabgrenzungen durchsetzen:

- **`Human Prime`**: Die reale natürliche Person, die durch eine `HumanID` (`hid_`) identifiziert wird und individuelle digitale Personas besitzt sowie kontrolliert. Spezifikationen, Codekommentare und API-Felder `MÜSSEN` zur Bezeichnung der natürlichen Person durchgängig `Human Prime` verwenden.
- **`Host`**: Bezeichnet **ausschließlich** ein Endgerät, eine Betriebssystemumgebung oder eine Client-Anwendung, auf der eine `Fay`-Instanz ausgeführt oder eingebunden wird. Der Begriff `Host` `DARF NICHT` in Implementierungen oder Dokumentationen zur Bezeichnung einer natürlichen Person oder eines `Human Prime` verwendet werden.
- **`Fay` (`Fay = iFay + coFay`)**: Sammelbegriff für alle rechenschaftspflichtigen digitalen Entitäten mit überprüfbarer Identität im iFay-Ökosystem, aufgeteilt in zwei disjunkte Teilmengen:
  - **`iFay` (Individual Fay, `ifay_`)**: Persönliche digitale Persona, die nicht übertragbar im Verhältnis `1:N` an genau eine `HumanID` gebunden ist (`HumanID : iFayID = 1:N`).
  - **`coFay` (Shared-Role Fay, `cofay_`)**: Digitale Entität für kollaborative Aufgaben, Dienste oder öffentliche Rollen, die unmittelbar an genau eine `HumanID` oder genau eine `OrganizationID` gebunden ist und sowohl Eigentumsübertragung als auch eine davon unabhängige Delegation der laufenden Betriebsführung unterstützt.
- **`OrganizationID` (`org_`)**: Rechtliche oder organisatorische Einheit mit Verantwortung für Organisationsressourcen, vertreten durch eine natürliche Person als `Steward` und teilnahmeberechtigt an einem zyklenfreien Organisationsbaum mit jeweils höchstens einer direkten übergeordneten Organisation.
- **`Holder Agent`**: Lokale Softwarekomponente zur Schlüsselverwaltung und Selbstausstellung, die unter der Kontrolle eines `Human Prime` oder einer Organisation auf einem kontrollierten `Host` (Endgerät oder Anwendung) läuft, statt als zentrale entfernte Instanz aufzutreten.
- **`GMChain` und `MeriToken`**: `GMChain` ist das öffentliche Reputationsregister zur Erfassung gesellschaftlicher Beiträge im gesamten Ökosystem; `MeriToken` (gemessen in `Merit Unit`) ist eine nicht-monetäre Kennzahl für gesellschaftliche Beiträge, keine Kryptowährung, nicht gegen Fiatwährung eintauschbar, wird nicht durch Schürfverfahren erzeugt, ist kein Finanzabwicklungssystem und kein spekulativer Vermögenswert.

## 1.4 Protokollversionierung und Versionsaushandlung (Normativ)

### 1.4.1 Drei orthogonale Achsen

FayID trennt drei eigenständige Achsen; diese `DÜRFEN NICHT` miteinander vermischt werden:

1. **Protokoll-Wire-Version (`MAJOR.MINOR`)**: Verwendet eine zweistellige Zeichenkette `MAJOR.MINOR` (`"1.0"` für FayID 1.0) **ohne `PATCH`-Segment**. In `version`-Umschlagfeldern auf dem Übertragungsweg und in `const`-Vorgaben des JSON-Schemas `MUSS` ausschließlich `"1.0"` stehen.
2. **Dokumentstatus**: Kennzeichnet den Reifegrad der Spezifikation (etwa `Draft` oder `Final`). Der Dokumentstatus erscheint ausschließlich im Front Matter der Spezifikation und `DARF NICHT` in Wire-Format-Payloads eingehen.
3. **Ausgabedatum**: Bezeichnet im ISO-Format `YYYY-MM-DD` (`2025-10-25` für diese Ausgabe) Archivverzeichnisse der Spezifikation sowie Pfade von Schema-Snapshots und `DARF NICHT` in Wire-Format-Payloads eingehen.

### 1.4.2 Kriterien für Major- und Minor-Versionssprünge

- **Minor-Erhöhung (`MINOR`)**: Beschränkt auf abwärtskompatible additive Erweiterungen (wie optionale Umschlagfelder, neue Domänenkonstanten für Zweckunterschlüssel oder optionale Nachweis-Metadaten). Gegenstellen mit einer älteren `1.x`-Minor-Version können Signaturen und Kerninvarianten weiterhin prüfen und unbekannte optionale Felder übergehen.
- **Major-Erhöhung (`MAJOR`)**: Jede inkompatible Änderung (Anpassung regulärer Ausdrücke für Bezeichner, Austausch grundlegender Hash- oder Signaturprimitive, Änderung von HKDF-Domänenzeichenketten, Verschärfung bestehender Pflichtfelder oder Änderung der Ergebnisse beim kaskadierenden Widerruf) `MUSS` `MAJOR` erhöhen.
- **Redaktionelle Überarbeitungen**: Aktualisierungen einer Ausgabe innerhalb derselben `MAJOR.MINOR`-Version beschränken sich auf nicht-normative Klarstellungen und `DÜRFEN NICHT` zu abweichenden Konformitätsergebnissen führen.

### 1.4.3 Versions-Handshake und Vorwärtskompatibilität

1. Gegenstellen, die FayID-Datensätze, Umschläge oder Quittungen austauschen, `MÜSSEN` das Feld `version` prüfen. Konforme FayID-1.0-Datensätze `MÜSSEN` `version` exakt auf `"1.0"` setzen (`"1"`, `"1.0.0"` und `"v1.0"` sind ungültig).
2. Implementierungen, die mehrere Minor-Versionen innerhalb von `MAJOR = 1` unterstützen, `MÜSSEN` die höchste gemeinsam unterstützte `1.x`-Version aushandeln und Abwärtskompatibilität bis `"1.0"` wahren.
3. Trifft ein Prüfer auf eine unbekannte oder nicht unterstützte `MAJOR`-Version, `MUSS` er die Payload sofort abweisen und `DARF NICHT` stillschweigend auf eine andere Version ausweichen oder die Signaturprüfung umgehen.
4. Prüfer, die Payloads derselben `MAJOR`-Version auswerten, `MÜSSEN` unbekannte optionale Erweiterungsfelder bei der fachlichen Validierung ignorieren, bei der Berechnung der kanonischen Bytes nach RFC 8785 JCS zur Signaturprüfung jedoch sämtliche im signierten Objekt vorhandenen Felder unverändert beibehalten.
5. Schrittweise Aktualisierungen über `1.x`-Minor-Versionen hinweg `DÜRFEN NICHT` dazu führen, dass zuvor ausgestellte, noch nicht abgelaufene `dyn_`-, `grt_`- oder `vrf_`-Nachweise vorzeitig ungültig werden.
