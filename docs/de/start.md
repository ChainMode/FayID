# FayID 1.0 Schnellstart

**FayID 1.0** (Ausgabe `2025-10-25` Final) definiert das selbstsouveräne Holder-of-Key-Identitätsprotokoll im iFay-Ökosystem. Jedes persönliche `iFay` ist `1:N` und nicht übertragbar an genau einen **Human Prime** gebunden; jedes gemeinsam genutzte `coFay` gehört in einer einzigen Eigentumsebene einer `HumanID` oder `OrganizationID`. Wurzelschlüssel verbleiben ausschließlich innerhalb der lokalen **Host**-Umgebung (Gerät bzw. Laufzeitumgebung).

## 1. Voraussetzungen und lokale Prüfung

Die Referenzimplementierung unter [`src/fayid-toolkit.mjs`](../../src/fayid-toolkit.mjs) nutzt ausschließlich `node:crypto` ab Node.js 20 (`Ed25519`, `SHA-256`, `HKDF-SHA256`, RFC 8785 JCS) ohne externe Laufzeitabhängigkeiten. Alle Unit-Tests und Konformitätsvektoren lassen sich im Repository-Wurzelverzeichnis ausführen:

```bash
npm test
```

## 2. Kanonische Präfixe im Überblick

Kryptografische Bezeichner folgen dem Format `<prefix>_<lowercase-rfc4648-base32-nopad>` (`org_` erlaubt zusätzlich kleingeschriebene Slugs `[a-z0-9-]+`):

| Präfix | Entität / Token | Verantwortlichkeit und Datenschutzgrenze |
| --- | --- | --- |
| `hid_` | `HumanID` | Wurzelidentität eines `Human Prime` (`SHA-256(publicKey)`); **verlässt niemals den lokalen Host und erscheint nicht in Logs** |
| `ifay_` | `IFayID` | Persönliches `iFay`, `1:N` und nicht übertragbar mit seiner `hid_` verknüpft |
| `cofay_` | `CoFayID` | Rollenbasiertes `coFay` mit einstufigem Eigentümer (`hid_` oder `org_`) und orthogonaler Verwaltungsachse `managers: iFayID[]` |
| `org_` | `OrganizationID` | Organisationseinheit mit natürlicher Person als `Steward` (`hid_`) in einem zustimmungspflichtigen azyklischen Baum |
| `dyn_` | `DynamicCode` | Kurzlebiges (`<= 600s`), einmalig einlösbares, nicht verkettbares Vorzeigetoken mit Replay-Schutz |
| `grt_` / `vrf_` | `AuthorizationGrant` / `VerificationCode` | Bereichsgebundene (`EXACT` / `PREFIX`) Freigabe im Auth Exchange samt offline prüfbarer Ed25519-Quittung |
| `gmcref_` | `OpaqueRef` | Blinder Anker natürlicher Personen (`ifay.gmc.natural-person.v1`) für die Lese-Normalisierung auf der `GMChain` |

## 3. Holder-of-Key-Identität mit Ed25519 erzeugen

```js
import { randomBytes } from "node:crypto";
import {
  AccountDirectory,
  deriveEntityKeypair,
  deriveHumanIdentityFromSeed,
} from "../../src/fayid-toolkit.mjs";

const rootSeed = randomBytes(32); // Verbleibt im sicheren Speicher des lokalen Hosts
const human = deriveHumanIdentityFromSeed(rootSeed); // human.humanId => "hid_..." (kein Egress)
const ifay = deriveEntityKeypair(rootSeed, "ifay", 0).value; // ifay.entityId => "ifay_..."

const directory = new AccountDirectory();
directory.registerHuman(human.humanId);
directory.registerIFay(ifay.entityId, human.humanId);

const dyn = directory.issueDynamicCode({
  subjectId: ifay.entityId,
  ttlSec: 120,
});
console.log("Outbound unlinkable token:", dyn.value.code); // "dyn_..."
```

## 4. Weiterführende Dokumentation

- **Architektur-Blueprint**: [`./blueprint/`](./blueprint/) – Entwurfsentscheidungen zu Eigentum vs. Vertretungsbefugnis, Lebenszyklus und Auth Exchange.
- **Normative Spezifikation (Final 1.0)**: [`./specification/2025-10-25/README.md`](./specification/2025-10-25/README.md) – verbindliche Kapitel, [`schemas/fayid-1.0.json`](../../schemas/fayid-1.0.json) und Konformitätskriterien.
