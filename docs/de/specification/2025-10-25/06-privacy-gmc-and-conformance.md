---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: de
canonical: false
chapter: 6
---

# Kapitel 6: Datenschutzgrenzen, `GMChain`-Schnittstelle, Fehlercodes und Konformität

## 6.1 Datenschutzgrenzen für ausgehende Payloads und Protokollierung (Normativ)

Jede konforme Implementierung `MUSS` sowohl bei der Wire-Serialisierung als auch bei der Betriebs- und Diagnoseprotokollierung die folgenden nicht umgehbaren Datenschutzregeln durchsetzen:

1. **`hid_` im Klartext verlässt niemals die lokale Grenze und gelangt niemals in Protokolle**: Netzwerk-Payloads, öffentliche Verzeichnis-Snapshots, `.ego`-Exportpakete, parteiübergreifende Verifikationsquittungen (`vrf_`), Absturzabbilder (Crash Dumps) und Audit-Logs `DÜRFEN NICHT` `hid_<base32>`-Zeichenketten im Klartext enthalten. Externe Interaktionen `MÜSSEN` `ifay_`, `cofay_`, `dyn_`, `hidproof_` oder blinde Anker `gmcref_` verwenden.
2. **Keinerlei ausgehende Seeds oder privates Schlüsselmaterial**: Master-Seeds (`masterSeed`), Mnemonik-Phrasen, rohe private Schlüssel (`privateKey` / `secretKey`) sowie `userBlindSalt`-Werte `MÜSSEN` im sicheren lokalen Speicher des `Holder Agent` verbleiben und `DÜRFEN NICHT` in serialisierten öffentlichen Datensätzen oder ausgehenden Payloads erscheinen.
3. **Nichtverkettbarkeit über Namensräume hinweg**: Verschiedene externe Anwendungsdomänen `MÜSSEN` getrennte Domänentrennungs-Strings oder Salts einsetzen, damit externe Beobachter Bezeichner nicht über Namensraumgrenzen hinweg korrelieren und daraus ein Profil eines `Human Prime` erstellen können.

## 6.2 Schreibgeschützte `GMChain`-Grenze und blinder Anker `gmcref_` (Normativ)

`GMChain` normiert das Governance-Gewicht natürlicher Personen und den Sybil-Schutz derart, dass eine einzelne natürliche Person unabhängig von der Anzahl ihrer betriebenen `iFay`-Personas genau einmal als Anker einer natürlichen Person zählt, ohne jemals `hid_` im Klartext zu erfahren. FayID 1.0 leitet den deterministischen blinden Anker `gmcref_<base32>` wie folgt ab:

```text
prk    = HKDF-SHA256(ikm = userBlindSalt, salt = SHA-256("fayid.gmc.salt.v1"), info = "ifay.gmc.natural-person.v1:" || namespace, len = 32)
digest = HMAC-SHA256(key = prk, data = UTF8("gmcref:" || canonicalHumanId))
gmcref = "gmcref_" || base32EncodeNoPad(digest)
```

Normative Invarianten:

1. **Determinismus und Nichtumkehrbarkeit**: Bei identischer kanonischer `HumanID`, identischem `userBlindSalt` (`>= 32` Byte) und identischem `namespace` (Standardwert `"gmchain.main"`) liefert `deriveBlindGmcRef` stets dieselbe `gmcref_`-Zeichenkette. Ohne Kenntnis von `userBlindSalt` können Dritte (einschließlich `GMChain`-Knoten) `gmcref_` weder zu `hid_` zurückrechnen noch mit öffentlichen `ifay_`-Datensätzen desselben `Human Prime` korrelieren.
2. **Strikte schreibgeschützte Registergrenze**: FayID stellt gegenüber `GMChain` ausschließlich die Einwegableitung des Ankers sowie Eingaben zum Widerrufsstatus bereit; FayID verändert keinen `GMChain`-Registerzustand und berechnet, prägt oder verteilt keine `MeriToken`. `MeriToken` ist eine nicht-monetäre Kennzahl für gesellschaftliche Beiträge, keine Kryptowährung, nicht gegen Fiatwährung eintauschbar, kein Finanzabwicklungssystem und kein spekulativer Vermögenswert.
3. **Beschränkung auf natürliche Personen**: `deriveBlindGmcRef` akzeptiert ausschließlich eine gültige `HumanID` (`hid_`); die Übergabe eines `ifay_`-, `cofay_`- oder `org_`-Bezeichners `MUSS` mit `MALFORMED_FAYID_STRING` fehlschlagen.

## 6.3 Normatives Fehlercode-Verzeichnis (Normativ)

Konforme FayID-1.0-Implementierungen `MÜSSEN` die folgenden 24 stabilen Fehlercode-Konstanten beibehalten (14 Basis-Protokollcodes sowie 10 Codes für Kontenmodell, Domänentrennung und kaskadierende Governance):

| Fehlercode-Konstante | Auslösebedingung |
| --- | --- |
| `INSUFFICIENT_ENTROPY` | Master-Seed, Blind-Salt oder Zufallsentropie ist kürzer als 256 Bit (32 Byte) |
| `HUMAN_ID_OWNERSHIP_NOT_PROVEN` | Erforderliche `HumanID`-Holder-of-Key-Signatur fehlt oder besteht die Prüfung nicht |
| `OWNERSHIP_NOT_PROVEN` | Entitätskontrolle oder Eigentumsübertragung enthält keine gültige Signatur des aktuellen Eigentümers |
| `TARGET_OWNERSHIP_NOT_PROVEN` | Bei der `grt_`-Ausstellung fehlt ein gültiger Holder-of-Key-Nachweis für `targetFayId` (wird mit höchstem Vorrang zurückgegeben, um das Ausspähen von Bindungen zu verhindern) |
| `LEGACY_SUBJECT_MISMATCH` | Der HMAC des kanonisierten Subjekts der Bestandsanmeldedaten stimmt nicht mit dem gebundenen `LegacySubjectRef` überein |
| `DYNAMIC_CODE_EXPIRED` | Prüfzeitstempel von `dyn_` liegt nach `expiresAt` |
| `DYNAMIC_CODE_INVALID` | `dyn_`-Syntax oder -HMAC ist ungültig, `audience` weicht ab oder die angeforderte TTL überschreitet 600 Sekunden |
| `VERIFICATION_RATE_LIMITED` | Aufeinanderfolgende Prüffehler erreichen den Rate-Limit-Schwellenwert (5 Fehlversuche innerhalb von 600 s lösen exponentielles Backoff aus) |
| `IDENTITY_REVOKED` | Basisindikator für eine widerrufene Identität |
| `LEGACY_AUTH_FAILED` | Vorgelagerte Authentifizierung des Bestandsnachweises (Passwort, Zertifikat, Token, Smart Contract) ist fehlgeschlagen |
| `GRANT_EXPIRED` | Prüfzeitstempel von `grt_` liegt nach `expiresAt` |
| `GRANT_REVOKED` | Einzelner `grt_`-Grant wurde explizit widerrufen |
| `GRANT_INVALID` | `grt_` ist unbekannt, syntaktisch ungültig, adressiert einen unzulässigen Entitätstyp oder `requestedResourceRef` liegt außerhalb des freigegebenen Geltungsbereichs |
| `MALFORMED_FAYID_STRING` | Bezeichnerpräfix oder Base32-Rumpf ist ungültig, `resourceRef`-Syntax schlägt fehl oder es wurde ein unerwarteter Präfixtyp übergeben |
| `OWNER_TYPE_NOT_ALLOWED` | Versuch, ein `iFay` oder `coFay` als Eigentümer eines `coFay` einzutragen (Verstoß gegen die einstufige Eigentümerschaft) |
| `HIERARCHY_CONSENT_MISSING` | Einhängen einer Organisation enthält keine gültige Signatur der Unterorganisation oder der übergeordneten Organisation |
| `HIERARCHY_CYCLE_CONFLICT` | Einhängen einer Organisation verweist auf sie selbst oder auf einen bestehenden Nachfahren und erzeugt einen Zyklus |
| `AUTHORITY_GRANT_UNAUTHORIZED` | Nicht-Eigentümer (etwa ein Eintrag in `coFay.managers`) hat versucht, `managers` zu ändern oder weiterzudelegieren |
| `STEWARD_TYPE_NOT_ALLOWED` | `Steward` der Organisation ist keine gültige, nicht widerrufene `HumanID` (`hid_`) einer natürlichen Person |
| `ENTITY_REVOKED` | Zielentität oder ihre übergeordnete besitzende `HumanID` bzw. `OrganizationID` wurde direkt oder kaskadierend widerrufen |
| `DYNAMIC_CODE_REPLAYED` | Zur Einmalverwendung bestimmtes `dyn_`-Token wurde mehr als einmal vorgelegt |
| `DYNAMIC_CODE_TARGET_NOT_ALLOWED` | Versuch, ein `dyn_`-Token für einen unzulässigen Zieltyp wie `OrganizationID` auszustellen |
| `DOMAIN_SEPARATION_REQUIRED` | HKDF-Unterschlüsselableitung wurde ohne gültige `SubkeyDomain` oder ohne nichtleeren Kontext-String aufgerufen |
| `RECEIPT_INVALID` | `vrf_`-Verifikationsquittung ist fehlerhaft geformt oder besteht die Ed25519-Signaturprüfung nicht |

## 6.4 Konformitätskriterien (Normativ)

Eine Implementierung, Bibliothek oder ein `Holder Agent` mit Anspruch auf Konformität zu **FayID 1.0** `MUSS` sämtliche fünf nachprüfbaren Bedingungen erfüllen:

1. **Versions- und Schemakonformität**: Jeder ausgegebene öffentliche Entitätsdatensatz und jeder Nachweisumschlag führt `version: "1.0"` und validiert gegen [schemas/fayid-1.0.json](../../../../schemas/fayid-1.0.json).
2. **Konformität bei Bezeichnern und Ressourcenabgleich**: Setzt die Acht-Präfix-Normalisierung aus Kapitel 2, die strikte Abweisung ohne stillschweigende Eingabereparatur sowie den segmentsicheren `EXACT`-/`PREFIX`-Abgleich auf `resourceRef` um.
3. **Kryptografie- und Wurzelschlüssel-Isolationskonformität**: Setzt aus Kapitel 3 Ed25519, SHA-256, die fünf HKDF-SHA256-Zweckunterschlüssel-Domänen sowie die kanonische Signierung nach RFC 8785 JCS um und verwendet `ifay.ego.package-signing.v1` ausschließlich für `.ego`-Paketsignaturen ohne jegliches Durchsickern von Seeds oder privaten Schlüsseln.
4. **Konformität bei Kontenhierarchie und kaskadierendem Widerruf**: Setzt aus Kapitel 4 die einstufige `coFay`-Eigentümerschaft, die natürliche Person als `Steward` und zyklenfreie Organisationsbäume mit Einzel-Elternknoten und beiderseitiger Zustimmung sowie aus Kapitel 5 die Anti-Replay-Prüfung für `dyn_`, den geltungsbereichsgebundenen `grt_`-/`vrf_`-Austausch und den deterministischen kaskadierenden Widerruf über alle vier Entitätsklassen durch.
5. **100 % Bestehensquote der Konformitätsvektoren**: Besteht ausnahmslos alle Positiv- und Negativszenarien in [vectors/hierarchy/](../../../../vectors/hierarchy) und [vectors/crypto-and-revocation-vectors.json](../../../../vectors/crypto-and-revocation-vectors.json).
