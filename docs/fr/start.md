# Guide de démarrage rapide FayID 1.0

**FayID 1.0** (édition finale `2025-10-25`) est le protocole d'identité responsable auto-souveraine (*Holder-of-Key*) de l'écosystème iFay. Chaque `iFay` individuel est lié selon une relation `1:N` incessible à un unique **Human Prime**, chaque `coFay` à rôle partagé dépend sur une seule couche d'un `HumanID` ou d'un `OrganizationID`, et les clés privées racines restent confinées dans l'environnement matériel **Host** local.

## 1. Prérequis et vérification locale

L'implémentation de référence [`src/fayid-toolkit.mjs`](../../src/fayid-toolkit.mjs) repose exclusivement sur le module natif `node:crypto` de Node.js 20+ (`Ed25519`, `SHA-256`, `HKDF-SHA256`, JCS RFC 8785), sans aucune dépendance externe à l'exécution. Lancez la suite complète de tests unitaires et de vecteurs de conformité depuis la racine du dépôt :

```bash
npm test
```

## 2. Préfixes canoniques des identifiants

Tous les identifiants cryptographiques respectent la forme `<prefix>_<lowercase-rfc4648-base32-nopad>` (`org_` autorise également un identifiant court en minuscules `[a-z0-9-]+`) :

| Préfixe | Entité / Jeton | Règle de responsabilité et de confidentialité |
| --- | --- | --- |
| `hid_` | `HumanID` | Identité racine d'un `Human Prime` (`SHA-256(publicKey)`) ; **ne quitte jamais le Host local et n'est jamais journalisée** |
| `ifay_` | `IFayID` | `iFay` individuel rattaché en `1:N` de manière incessible à son `hid_` propriétaire |
| `cofay_` | `CoFayID` | `coFay` partagé détenu sur une seule couche par `hid_` ou `org_`, avec axe de gestion orthogonal `managers: iFayID[]` |
| `org_` | `OrganizationID` | Organisation responsable dotée d'un `Steward` personne physique (`hid_`) au sein d'un arbre acyclique à consentement mutuel |
| `dyn_` | `DynamicCode` | Jeton de présentation éphémère (`<= 600s`), à usage unique, anti-rejeu et non corrélable |
| `grt_` / `vrf_` | `AuthorizationGrant` / `VerificationCode` | Autorisation d'échange à portée restreinte (`EXACT` / `PREFIX`) et reçu Ed25519 vérifiable hors ligne |
| `gmcref_` | `OpaqueRef` | Ancre aveugle de personne physique (`ifay.gmc.natural-person.v1`) pour la normalisation en lecture seule sur `GMChain` |

## 3. Créer une identité Ed25519 « Holder-of-Key »

```js
import { randomBytes } from "node:crypto";
import {
  AccountDirectory,
  deriveEntityKeypair,
  deriveHumanIdentityFromSeed,
} from "../../src/fayid-toolkit.mjs";

const rootSeed = randomBytes(32); // Confinée dans le stockage sécurisé du Host local
const human = deriveHumanIdentityFromSeed(rootSeed); // human.humanId => "hid_..." (zéro exfiltration)
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

## 4. Pour aller plus loin

- **Plan directeur d'architecture** : [`./blueprint/`](./blueprint/) présente la séparation entre propriété et autorité, le cycle de vie des justificatifs et l'échange d'authentification.
- **Spécification normative (Final 1.0)** : [`./specification/2025-10-25/README.md`](./specification/2025-10-25/README.md) regroupe l'ensemble des chapitres normatifs, le schéma [`schemas/fayid-1.0.json`](../../schemas/fayid-1.0.json) et les critères de conformité.
