---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: de
canonical: false
chapter: 2
---

# Kapitel 2: Bezeichnersyntax, Base32-Kodierung und Ressourcenreferenzen

## 2.1 Kanonische Bezeichnerpräfixe (Normativ)

Jeder kryptografische FayID-Bezeichner und jede abgeleitete Nachweiszeichenkette `MUSS` der Syntax `<prefix>_<body>` folgen. Mit Ausnahme von `org_`, das Kleinbuchstaben-Slug-Zeichen `[a-z0-9-]+` zulässt, `MUSS` der Rumpf jedes Bezeichners **füllzeichenloses RFC-4648-Base32 in Kleinbuchstaben** (`[a-z2-7]+`) verwenden:

| Typkonstante | Präfix | Rumpfmuster | Typische Nutzdatengröße und Zurechnungssemantik |
| --- | --- | --- | --- |
| `HUMAN_ID` | `hid_` | `^[a-z2-7]+$` | `SHA-256(humanPublicKey)` (32 Byte -> 52 Base32-Zeichen); Wurzelidentität eines `Human Prime` |
| `IFAY_ID` | `ifay_` | `^[a-z2-7]+$` | `SHA-256("ifay:" \|\| humanId \|\| ":" \|\| publicKey)` (32 Byte); individuelle digitale Persona |
| `COFAY_ID` | `cofay_` | `^[a-z2-7]+$` | `SHA-256("cofay:" \|\| ownerId \|\| ":" \|\| publicKey)` (32 Byte); digitale Entität mit geteilter Rolle |
| `ORGANIZATION_ID` | `org_` | `^[a-z0-9-]+$` | Zurechenbarer Organisationsbezeichner (deterministischer Hash-Rumpf oder normalisierter Kleinbuchstaben-Slug) |
| `DYNAMIC_CODE` | `dyn_` | `^[a-z2-7]+$` | Auf 20 Byte gekürztes HMAC-Tag (32 Base32-Zeichen); kurzlebiges, nicht verkettbares Vorweis-Token |
| `VERIFICATION_CODE` | `vrf_` | `^[a-z2-7]+$` | 20-Byte-Prüfwert einer Verifikationsquittung, gebunden an eine erfolgreiche `grt_`- oder `cofay_`-Prüfung |
| `AUTHORIZATION_GRANT` | `grt_` | `^[a-z2-7]+$` | 20-Byte-Bezeichner eines geltungsbereichsgebundenen Authorization Grants aus dem Austausch von Bestandsanmeldedaten |
| `OPAQUE_REF` | `gmcref_` | `^[a-z2-7]+$` | 32 Byte langer blinder Anker einer natürlichen Person (52 Base32-Zeichen) zur Deduplizierung auf `GMChain` |

Darüber hinaus stellen öffentliche `iFay`-Registrierungsdatensätze und Offline-Pakete das gesalzene Einweg-Commitment auf ihre besitzende `HumanID` als `hidproof_<lowercase-base32-nopad>` (`^hidproof_[a-z2-7]{16,}$`) dar, sodass `hid_` im Klartext niemals in öffentlichen Datensätzen erscheint.

## 2.2 Normalisierung und strikte Abweisungsregeln (Normativ)

`normalizeFayID(input)` `MUSS` die folgenden deterministischen Regeln durchsetzen:

1. **Typ- und Nichtleer-Prüfung**: Eingaben, die keine Zeichenkette sind, sowie leere Zeichenketten `MÜSSEN` sofort mit `MALFORMED_FAYID_STRING` fehlschlagen.
2. **ASCII-Kleinschreibung**: Der Parser `MUSS` ASCII-Großbuchstaben vor dem Abgleich mit den acht kanonischen Präfixen in Kleinbuchstaben überführen (`input.toLowerCase()`).
3. **Strikte Abweisung ohne stillschweigende Reparatur**: Ein Parser `DARF NICHT` stillschweigend Eingaben bereinigen: Weder führende oder abschließende Leerzeichen noch Bindestriche (außerhalb zulässiger `org_`-Rümpfe) oder `=`-Füllzeichen dürfen entfernt werden, noch dürfen ähnlich aussehende Ziffern (wie `0`, `1`, `8` oder `9`) auf Base32-Buchstaben abgebildet werden. Jede Eingabe mit Leerzeichen, `=`-Füllzeichen, unbekanntem Präfix, leerem Rumpf oder Zeichen außerhalb des Alphabets `MUSS` mit `MALFORMED_FAYID_STRING` fehlschlagen.
4. **Round-Trip-Invarianten**: Für jeden gültigen kanonischen Bezeichner `x` `MUSS` ein erneuter Aufruf von `normalizeFayID(x)` `ok: true` mit `value.canonical === x` zurückgeben. Das Kodieren eines beliebigen Byte-Arrays `b` in füllzeichenloses Kleinbuchstaben-Base32 und anschließendes Dekodieren `MUSS` `b` Byte für Byte wiederherstellen; verbleibende Überhangbits (Slack-Bits) ungleich null bei der Base32-Dekodierung `MÜSSEN` abgewiesen werden.

## 2.3 Syntax und Geltungsbereichsabgleich von `resourceRef` (Normativ)

Zielressourcen im Auth Exchange werden über `resourceRef` adressiert. `normalizeResourceRef(input)` und `matchesResourceRef(grantedResourceRef, requestedResourceRef, scopeMode)` `MÜSSEN` folgende Regeln durchsetzen:

1. **Grammatik**: `resourceRef` folgt dem Aufbau `<namespace>:<path>`:
   - `<namespace>` `MUSS` nach Umwandlung in Kleinbuchstaben auf `^[a-z][a-z0-9+.-]*$` passen;
   - `<path>` rechts von `:` `MUSS` nichtleer sein, darf keinerlei Leerzeichen enthalten und nicht auf `/` enden (sofern der Pfad nicht allein aus `/` besteht); leere Segmente (`//`) sowie Punkt-Traversierungssegmente (`.` oder `..`) `DÜRFEN NICHT` in `<path>` vorkommen.
   - Jeder Verstoß `MUSS` `MALFORMED_FAYID_STRING` zurückgeben.
2. **Groß-/Kleinschreibung**: `<namespace>` wird in Kleinbuchstaben normalisiert, während `<path>` die exakte Schreibweise beibehalten `MUSS`.
3. **Geltungsbereichsabgleich (`scopeMode`)**:
   - `EXACT` (Standardwert): Stimmt genau dann überein, wenn für die normalisierten Werte `requestedResourceRef === grantedResourceRef` gilt.
   - `PREFIX`: Stimmt genau dann überein, wenn der normalisierte `requestedResourceRef` gleich `grantedResourceRef` ist oder an einer expliziten `/`-Segmentgrenze mit `grantedResourceRef + "/"` beginnt. Beispielsweise passt eine `PREFIX`-Freigabe für `cap:repo/fayid` auf `cap:repo/fayid/issues` und `DARF NICHT` auf den Nachbarpfad `cap:repo/fayid-ext` passen.

## 2.4 Anbindung älterer 64-stelliger Hex-Schlüssel (Normativ)

Zur Migration früherer Datensätze, die rohe öffentliche 32-Byte-Ed25519-Schlüssel als 64 Hexadezimalzeichen speichern, stellen Implementierungen `adaptLegacyHexIdentifier(hex64, prefix)` bereit:

1. Nach dem Entfernen äußerer Leerzeichen `MUSS` `hex64` auf `^[0-9a-fA-F]{64}$` passen, und `prefix` `MUSS` eines der Präfixe `hid_`, `ifay_` oder `cofay_` sein; andernfalls `MUSS` der Aufruf mit `MALFORMED_FAYID_STRING` fehlschlagen.
2. Der Adapter berechnet `SHA-256` über den dekodierten öffentlichen 32-Byte-Schlüssel und kodiert den Prüfwert als `<prefix><base32-nopad>` übereinstimmend mit der nativen Ableitung von Wurzelbezeichnern.
3. Bloße 64-stellige Hex-Zeichenketten `DÜRFEN NICHT` anstelle kanonischer FayID-Bezeichner in konformen FayID-1.0-Wire-Payloads übertragen werden; die Umwandlung `MUSS` explizit an der Eingabegrenze stattfinden.
