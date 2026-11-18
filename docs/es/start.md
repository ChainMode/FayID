# Guía de inicio rápido de FayID 1.0

**FayID 1.0** (edición `2025-10-25` Final) es el protocolo de identidad responsable autosoberana (Holder-of-Key) del ecosistema iFay. Cada `iFay` individual queda vinculado de forma `1:N` e intransferible a un único **Human Prime**, cada `coFay` de rol compartido pertenece en una sola capa a un `HumanID` u `OrganizationID`, y las claves privadas raíz permanecen estrictamente dentro del entorno local del dispositivo **Host**.

## 1. Requisitos previos y verificación

La implementación de referencia en [`src/fayid-toolkit.mjs`](../../src/fayid-toolkit.mjs) utiliza únicamente `node:crypto` nativo de Node.js 20+ (`Ed25519`, `SHA-256`, `HKDF-SHA256` y JCS RFC 8785), sin dependencias externas en tiempo de ejecución. Ejecute las pruebas unitarias y los vectores de conformidad desde la raíz del repositorio:

```bash
npm test
```

## 2. Prefijos canónicos de identificadores

Todos los identificadores criptográficos siguen el formato `<prefix>_<lowercase-rfc4648-base32-nopad>` (`org_` admite además slugs en minúsculas `[a-z0-9-]+`):

| Prefijo | Entidad / Token | Regla de responsabilidad y privacidad |
| --- | --- | --- |
| `hid_` | `HumanID` | Identidad raíz de un `Human Prime` (`SHA-256(publicKey)`); **nunca sale del Host local ni se registra en logs públicos** |
| `ifay_` | `IFayID` | `iFay` individual vinculado `1:N` de forma intransferible a su `hid_` propietario |
| `cofay_` | `CoFayID` | `coFay` compartido con titularidad de capa única (`hid_` u `org_`) y eje ortogonal `managers: iFayID[]` |
| `org_` | `OrganizationID` | Organización responsable con `Steward` persona física (`hid_`) en un árbol acíclico de padre único con consentimiento mutuo |
| `dyn_` | `DynamicCode` | Token de presentación efímero (`<= 600s`), de un solo uso, antirrepetición y no vinculable |
| `grt_` / `vrf_` | `AuthorizationGrant` / `VerificationCode` | Concesión de Auth Exchange acotada (`EXACT` / `PREFIX`) y recibo Ed25519 verificable sin conexión |
| `gmcref_` | `OpaqueRef` | Ancla ciega de persona física (`ifay.gmc.natural-person.v1`) para la normalización de solo lectura en `GMChain` |

## 3. Crear una identidad Ed25519 Holder-of-Key

```js
import { randomBytes } from "node:crypto";
import {
  AccountDirectory,
  deriveEntityKeypair,
  deriveHumanIdentityFromSeed,
} from "../../src/fayid-toolkit.mjs";

const rootSeed = randomBytes(32); // Permanece aislado en el almacenamiento seguro del Host local
const human = deriveHumanIdentityFromSeed(rootSeed); // human.humanId => "hid_..." (sin egreso externo)
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

## 4. Documentación relacionada

- **Plano arquitectónico**: [`./blueprint/`](./blueprint/) — fundamentos de titularidad frente a autoridad, ciclo de vida de credenciales e intercambio de autenticación.
- **Especificación normativa (Final 1.0)**: [`./specification/2025-10-25/README.md`](./specification/2025-10-25/README.md) — capítulos normativos completos, [`schemas/fayid-1.0.json`](../../schemas/fayid-1.0.json) y requisitos de conformidad.
