---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: es
canonical: false
---

# Especificación del Protocolo FayID 1.0

FayID es el protocolo de identidad autosoberana con posesión de clave (Holder-of-Key) y responsabilidad trazable del ecosistema iFay. Sin depender de ninguna autoridad de certificación (CA) ni proveedor de identidad (IdP) centralizado, FayID vincula cada identidad digital individual (`iFay`) de forma intransferible y en relación uno a muchos con un único **Human Prime** (`hid_`), y vincula cada entidad digital de rol compartido (`coFay`) directamente, en una sola capa de titularidad, con un único `HumanID` (`hid_`) u `OrganizationID` (`org_`) responsable.

Este directorio contiene la edición en español de la **Especificación Final de FayID 1.0 (Edición `2025-10-25`)**. Todos los capítulos y cláusulas normativas guardan correspondencia uno a uno con la especificación en chino simplificado (`zh-CN`), que constituye la edición canónica y autoritativa; en caso de discrepancia entre idiomas, prevalece la edición `zh-CN`.

## Capítulos de la especificación

| Capítulo | Archivo | Alcance normativo |
| --- | --- | --- |
| Capítulo 1 | [01-conventions-and-versioning.md](./01-conventions-and-versioning.md) | Alcance, palabras clave normativas RFC 2119 / RFC 8174, fronteras terminológicas centrales y versionado y negociación de protocolo de dos segmentos `1.0` |
| Capítulo 2 | [02-identifiers-and-encoding.md](./02-identifiers-and-encoding.md) | Ocho prefijos canónicos, codificación Base32 RFC 4648 en minúsculas sin relleno, reglas de rechazo estricto e invariantes de ida y vuelta, coincidencia de `resourceRef` y adaptación heredada de 64 caracteres hexadecimales |
| Capítulo 3 | [03-cryptography-and-subkeys.md](./03-cryptography-and-subkeys.md) | Modelo de confianza autosoberano Ed25519 Holder-of-Key, entropía de semilla maestra, derivación de subclaves por propósito mediante HKDF-SHA256 (incluido `ifay.ego.package-signing.v1`) y firma canónica JCS según RFC 8785 |
| Capítulo 4 | [04-entities-ownership-and-hierarchy.md](./04-entities-ownership-and-hierarchy.md) | Cuatro clases de entidades, vinculación `HumanID : iFayID = 1:N`, titularidad de capa única de `coFay` y delegación operativa ortogonal mediante `managers`, `Steward` persona natural y jerarquía organizacional acíclica de padre único con consentimiento mutuo |
| Capítulo 5 | [05-dynamic-codes-and-auth-exchange.md](./05-dynamic-codes-and-auth-exchange.md) | Emisión de Dynamic Codes (`dyn_`) no correlacionables y verificación antirrepetición, vinculación HMAC de sujetos heredados, Authorization Grants (`grt_`) con alcance acotado, recibos de verificación (`vrf_`) y revocación en cascada |
| Capítulo 6 | [06-privacy-gmc-and-conformance.md](./06-privacy-gmc-and-conformance.md) | Fronteras de redacción en cargas salientes y registros, frontera de solo lectura frente a `GMChain` y ancla ciega de persona natural (`gmcref_`), registro normativo de 24 códigos de error y criterios de conformidad |

## Artefactos normativos complementarios

| Ruta del artefacto | Descripción |
| --- | --- |
| [schemas/fayid-1.0.json](../../../../schemas/fayid-1.0.json) | JSON Schema congelado de FayID 1.0 (Draft 2020-12, exige `version: "1.0"`) |
| [schema/2025-10-25/schema.json](../../../../schema/2025-10-25/schema.json) | Espejo de edición sincronizado byte a byte con `schemas/fayid-1.0.json` |
| [schema/2025-10-25/schema.ts](../../../../schema/2025-10-25/schema.ts) | Espejo normativo de constantes e interfaces en TypeScript |
| [src/fayid-toolkit.mjs](../../../../src/fayid-toolkit.mjs) | Implementación de referencia en Node.js (`node:crypto`) sin dependencias externas |
| [vectors/](../../../../vectors/) | Vectores deterministas de conformidad entre implementaciones (`account-hierarchy-vectors.json` y `crypto-and-revocation-vectors.json`) |
