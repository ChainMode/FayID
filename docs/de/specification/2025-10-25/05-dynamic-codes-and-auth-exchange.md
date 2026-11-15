---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: de
canonical: false
chapter: 5
---

# Kapitel 5: Nicht verkettbare Dynamic Codes, Auth Exchange und kaskadierender Widerruf

## 5.1 Ausstellung und Prüfung nicht verkettbarer Dynamic Codes (`dyn_`) (Normativ)

Da `hid_` im Klartext die lokale Vertrauensgrenze niemals verlässt, weisen ein `Human Prime` sowie dessen `iFay`- oder `coFay`-Entitäten über Vertrauensgrenzen hinweg kurzlebige, mit einer Nonce versehene Dynamic Codes (`dyn_<base32>`) vor:

1. **Zulässige Zielentitäten**: Dynamic Codes `DÜRFEN` ausschließlich für nicht widerrufene Subjekte vom Typ `HumanID` (`hid_`), `iFayID` (`ifay_`) oder `coFayID` (`cofay_`) ausgestellt werden. Die Anforderung eines Dynamic Codes für eine `OrganizationID` (`org_`) `MUSS` mit `DYNAMIC_CODE_TARGET_NOT_ALLOWED` fehlschlagen (Organisationsbezeichner sind konzeptionsgemäß öffentlich).
2. **Nonce-gesalzene, nicht verkettbare Konstruktion**: Jede Ausstellung erzeugt mindestens 16 Byte kryptografisch zufälliger `nonce`, berechnet HMAC-SHA256 unter dem Domänenschlüssel `ifay.fayid.dynamic-code.v1` über die kanonische JCS-Payload `{audience, expiresAt, issuedAt, nonceHex, targetId, version: "1.0"}` und kodiert die führenden 20 Byte als `dyn_<base32>`. Passive Beobachter ohne Zugriff auf den Prüfschlüsselkontext können zwei vom selben Subjekt vorgelegte `dyn_`-Tokens nicht miteinander korrelieren.
3. **Strikte TTL-Obergrenze**: `expiresAt - issuedAt` `MUSS` strikt positiv sein und `DARF NICHT` über **`600` Sekunden (`DYNAMIC_CODE_MAX_TTL_SECONDS = 600`)** liegen; TTL-Anforderungen außerhalb dieses Bereichs `MÜSSEN` mit `DYNAMIC_CODE_INVALID` fehlschlagen.
4. **Einmalverwendung und Anti-Replay-Prüfung**: Bei der Prüfung eines `dyn_`-Tokens gilt:
   - Ist das zugrunde liegende Subjekt oder dessen übergeordneter Eigentümer widerrufen, `MUSS` die Prüfung mit `ENTITY_REVOKED` fehlschlagen;
   - Erfolgt die Prüfung nach `expiresAt`, `MUSS` sie mit `DYNAMIC_CODE_EXPIRED` fehlschlagen;
   - Weicht `audience` ab (sofern an einen Zieladressaten gebunden) oder ist das Token unbekannt, `MUSS` die Prüfung mit `DYNAMIC_CODE_INVALID` fehlschlagen;
   - Jede `dyn_`-Nonce `DARF` höchstens **einmal** erfolgreich eingelöst werden; jede zweite oder weitere Vorlage desselben `dyn_`-Tokens `MUSS` mit `DYNAMIC_CODE_REPLAYED` fehlschlagen.
5. **Datenschutzfreundliche Auflösung bei `HumanID`**: Ist das zugrunde liegende Subjekt eines geprüften `dyn_`-Tokens eine `HumanID`, gilt: `hid_` im Klartext `DARF NICHT` in der Prüfantwort offengelegt werden; stattdessen `MUSS` die Antwort den Subjekttyp `"HUMAN"` zusammen mit dem deterministischen blinden Anker `gmcref_<base32>` zurückgeben.

## 5.2 Bindung von Bestandsanmeldedaten und Auth Exchange (`grt_` / `vrf_`) (Normativ)

Auth Exchange überführt externe Bestandsanmeldedaten in geltungsbereichsgebundene FayID Authorization Grants (`grt_<base32>`) und erzeugt offline überprüfbare Verifikationsquittungen (`vrf_<base32>`):

1. **HMAC-gehashtes `LegacySubjectRef`**: Externe Subjektbezeichner `MÜSSEN` kanonisiert und mittels schlüsselgebundenem HMAC in die Form `<legacySourceKind>:<issuerOrAuthority>:<subjectHash>` gehasht werden, wobei `subjectHash = base32NoPad(HMAC-SHA256(legacySecret, canonicalSubject))` gilt. E-Mail-Adressen, Telefonnummern, X.509-Distinguished-Names, rohe OAuth-Tokens oder Blockchain-Wallet-Adressen im Klartext `DÜRFEN NICHT` in `LegacySubjectRef` eingebettet werden.
2. **Standardzuordnung für `LegacyTrustLevel`**:
   - `PASSWORD` -> `LOW` (TTL-Obergrenze des Grants: **`900` Sekunden**, `LOW_TRUST_GRANT_MAX_TTL_SECONDS`);
   - `ACCESS_TOKEN`, `AUTHORIZATION` -> `MEDIUM` (TTL-Obergrenze des Grants: **`3600` Sekunden**, `GRANT_MAX_TTL_SECONDS`);
   - `CERTIFICATE`, `SMART_CONTRACT` -> `HIGH` (TTL-Obergrenze des Grants: **`3600` Sekunden**).
   Implementierungen `DÜRFEN` Vertrauensstufen gemäß lokaler Risikorichtlinie herabstufen oder TTLs verkürzen und `DÜRFEN NICHT` ohne zusätzlichen mehrstufigen Inhabernachweis eine höhere Vertrauensstufe vergeben.
3. **Vorrang des Eigentumsnachweises für das Zielsubjekt (Schutz vor Ausspähung)**: `grt_`-Grants `DÜRFEN` ausschließlich nicht widerrufene Entitäten vom Typ `iFayID` oder `coFayID` adressieren, und die Ausstellung `MUSS` eine Holder-of-Key-Signatur prüfen, die die Kontrolle über `targetFayId` belegt. Fehlt der Eigentumsnachweis für das Zielsubjekt oder ist er ungültig, `MUSS` die Ausstellung noch vor der Auswertung von `LegacySubjectRef`-Bindungen `TARGET_OWNERSHIP_NOT_PROVEN` zurückgeben, damit Angreifer nicht ausforschen können, ob ein Bestandskonto an eine bestimmte FayID gebunden ist.
4. **Geltungsbereichsgebundene Grant-Prüfung und `vrf_`-Quittungen**: `verifyAuthGrant` prüft in genau dieser Reihenfolge:
   - Existenz und syntaktische Gültigkeit des Grants (andernfalls `GRANT_INVALID`);
   - Widerrufsstatus von `targetFayId` und dessen übergeordnetem Eigentümer (bei Widerruf `ENTITY_REVOKED`);
   - Expliziten Widerrufsstatus des Grants selbst (andernfalls `GRANT_REVOKED`);
   - Ablauf gegenüber `expiresAt` (andernfalls `GRANT_EXPIRED`);
   - Geltungsbereichsabgleich zwischen `requestedResourceRef` und `resourceRef` gemäß `scopeMode` aus Abschnitt 2.3 (`EXACT` oder `PREFIX`, bei Abweichung `GRANT_INVALID`).
   Bei Erfolg signiert der Prüfer die kanonische Quittungs-Payload mit dem Ed25519-Schlüssel der Domäne `ifay.fayid.auth-exchange.v1` und gibt eine `vrf_<base32>`-Quittung zurück. Jede vertrauende Gegenstelle kann `verifyAuthReceipt(receipt)` aufrufen, um Ed25519-Signatur und Struktur offline zu prüfen; jedes manipulierte Feld `MUSS` mit `RECEIPT_INVALID` fehlschlagen.

## 5.3 Deterministischer kaskadierender Widerruf (Normativ)

Ein Widerruf ist monoton und unumkehrbar. Der Widerruf einer Entität `MUSS` synchron auf sämtliche nachgelagerten Entitäten und aktiven Nachweise durchgreifen, ohne verwaiste aktive Datensätze zurückzulassen:

| Widerrufene Auslöser-Entität | Kaskadierte nachgelagerte Entitäten | Verbindliche Bereinigung bei Managern und Nachweisen |
| --- | --- | --- |
| **`HumanID` (`hid_`)** | Jedes an diese `hid_` gebundene `iFay` (`ifay_`) sowie jedes unmittelbar von dieser `hid_` gehaltene `coFay` (`cofay_`) | Entfernen aller kaskadierten `ifay_`-IDs aus jeder verbleibenden `coFay.managers`-Liste; Widerruf aller aktiven `grt_`-Grants und unverbrauchten `dyn_`-Tokens für jedes kaskadierte `ifay_` oder `cofay_` |
| **`OrganizationID` (`org_`)** | Die Organisation selbst, ihr gesamter Teilbaum nachgelagerter Unterorganisationen (rekursiv) sowie jedes `coFay` im unmittelbaren Eigentum der Organisation oder einer ihrer Unterorganisationen | Widerruf aller aktiven `grt_`-Grants und unverbrauchten `dyn_`-Tokens für jedes kaskadierte `cofay_` |
| **`iFayID` (`ifay_`)** | Diese `iFay`-Instanz | Sofortiges Entfernen dieses `ifay_` aus jeder verbleibenden `coFay.managers`-Liste; Widerruf aller aktiven `grt_`-Grants und unverbrauchten `dyn_`-Tokens für dieses `ifay_` |
| **`coFayID` (`cofay_`)** | Diese `coFay`-Instanz | Widerruf aller aktiven `grt_`-Grants und unverbrauchten `dyn_`-Tokens für dieses `cofay_` |

Nach Abschluss des Widerrufs gilt:
1. Das Ausstellen neuer `dyn_`-Tokens, das Ausstellen neuer `grt_`-Grants, das Registrieren untergeordneter Entitäten sowie das Prüfen bestehender Nachweise für eine direkt oder kaskadierend widerrufene Entität `MÜSSEN` deterministisch mit `ENTITY_REVOKED` fehlschlagen (während der isolierte Widerruf eines einzelnen Grants bei weiterhin aktiver Zielentität `GRANT_REVOKED` zurückgibt).
2. An eine widerrufene Entität gebundene Nachweise verlieren **sofort** ihre Gültigkeit, selbst wenn ihr ursprünglicher `expiresAt`-Zeitstempel noch nicht erreicht ist.
