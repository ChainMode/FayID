---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: de
canonical: false
---

# FayID-1.0-Protokollspezifikation

FayID ist das selbstsouveräne (Holder-of-Key) Identitätsprotokoll für zurechenbare Verantwortung im iFay-Ökosystem. Ohne Abhängigkeit von einer zentralen Zertifizierungsstelle (CA) oder einem zentralen Identity Provider (IdP) bindet FayID jede individuelle digitale Persona (`iFay`) nicht übertragbar im Verhältnis eins zu viele an genau einen **Human Prime** (`hid_`) und ordnet jede digitale Entität mit geteilter Rolle (`coFay`) in einer einstufigen Eigentümerschaft unmittelbar einer rechenschaftspflichtigen `HumanID` (`hid_`) oder `OrganizationID` (`org_`) zu.

Dieses Verzeichnis enthält die deutsche Ausgabe der **endgültigen FayID-1.0-Spezifikation (Ausgabe `2025-10-25`)**. Alle Kapitel und normativen Bestimmungen entsprechen eins zu eins der maßgeblichen kanonischen Ausgabe in Vereinfachtem Chinesisch (`zh-CN`); bei sprachübergreifenden Abweichungen gibt die `zh-CN`-Ausgabe den Ausschlag.

## Kapitelübersicht

| Kapitel | Datei | Normativer Umfang |
| --- | --- | --- |
| Kapitel 1 | [01-conventions-and-versioning.md](./01-conventions-and-versioning.md) | Geltungsbereich, normative Schlüsselwörter nach RFC 2119 / RFC 8174, Begriffsabgrenzungen sowie zweistellige `1.0`-Protokollversionierung und Versionsaushandlung |
| Kapitel 2 | [02-identifiers-and-encoding.md](./02-identifiers-and-encoding.md) | Acht kanonische Präfixe, füllzeichenlose RFC-4648-Base32-Kodierung in Kleinbuchstaben, strikte Abweisungs- und Round-Trip-Invarianten, `resourceRef`-Abgleich und Anbindung älterer 64-stelliger Hex-Schlüssel |
| Kapitel 3 | [03-cryptography-and-subkeys.md](./03-cryptography-and-subkeys.md) | Selbstsouveränes Ed25519-Holder-of-Key-Vertrauensmodell, Master-Seed-Entropie, HKDF-SHA256-Ableitung zweckgebundener Unterschlüssel (einschließlich `ifay.ego.package-signing.v1`) und kanonische Signierung nach RFC 8785 JCS |
| Kapitel 4 | [04-entities-ownership-and-hierarchy.md](./04-entities-ownership-and-hierarchy.md) | Vier Entitätsklassen, Bindung `HumanID : iFayID = 1:N`, einstufige `coFay`-Eigentümerschaft und orthogonale `managers`-Delegation, natürliche Person als `Steward` sowie zyklenfreie Organisationshierarchie mit beiderseitiger Zustimmung |
| Kapitel 5 | [05-dynamic-codes-and-auth-exchange.md](./05-dynamic-codes-and-auth-exchange.md) | Ausstellung und Anti-Replay-Prüfung nicht verkettbarer Dynamic Codes (`dyn_`), HMAC-Bindung von Bestandsidentitäten, geltungsbereichsgebundene Authorization Grants (`grt_`), Verifikationsquittungen (`vrf_`) und kaskadierender Widerruf |
| Kapitel 6 | [06-privacy-gmc-and-conformance.md](./06-privacy-gmc-and-conformance.md) | Datenschutzgrenzen für ausgehende Payloads und Protokolle, schreibgeschützte `GMChain`-Grenze und blinder Anker natürlicher Personen (`gmcref_`), normatives Verzeichnis der 24 Fehlercodes und Konformitätskriterien |

## Begleitende normative Artefakte

| Artefaktpfad | Beschreibung |
| --- | --- |
| [schemas/fayid-1.0.json](../../../../schemas/fayid-1.0.json) | Eingefrorenes JSON-Schema für FayID 1.0 (Draft 2020-12, erzwingt `version: "1.0"`) |
| [schema/2025-10-25/schema.json](../../../../schema/2025-10-25/schema.json) | Byteidentischer Ausgabespiegel von `schemas/fayid-1.0.json` |
| [schema/2025-10-25/schema.ts](../../../../schema/2025-10-25/schema.ts) | Normative TypeScript-Konstanten und Schnittstellenspiegelung |
| [src/fayid-toolkit.mjs](../../../../src/fayid-toolkit.mjs) | Abhängigkeitsfreie Node.js-Referenzimplementierung auf Basis von `node:crypto` |
| [vectors/](../../../../vectors/) | Deterministische implementierungsübergreifende Konformitätsvektoren (`account-hierarchy-vectors.json` und `crypto-and-revocation-vectors.json`) |
