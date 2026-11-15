---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: es
canonical: false
chapter: 4
---

# Capítulo 4: Entidades de identidad, titularidad de capa única y jerarquía organizacional

## 4.1 Vinculación uno a muchos entre `HumanID` e `iFay` (Normativo)

1. **Derivación de la identidad raíz**: un `Human Prime` genera o deriva una clave pública Ed25519 `pk_human` dentro de un `Holder Agent` local y calcula `hid_ || base32NoPad(SHA-256(pk_human))` como su `HumanID`.
2. **Vinculación `1:N` intransferible**: un mismo `HumanID` `PUEDE` registrar y poseer una cantidad arbitraria de instancias `iFay` (`HumanID : iFayID = 1:N`). El registro de un `iFay` `DEBE` incluir firmas Ed25519 conjuntas tanto de la clave privada del `HumanID` propietario como de la clave privada del nuevo `iFay` sobre la carga canónica de vinculación; toda prueba ausente o inválida `DEBE` fallar con `HUMAN_ID_OWNERSHIP_NOT_PROVEN`.
3. **No correlacionabilidad predeterminada entre instancias `iFay`**: todo objeto público `IFayRecord` almacena únicamente el compromiso unidireccional con sal `humanIdProofRef` (`hidproof_<base32>`) y `NO DEBE` exponer `hid_` en texto plano. Sin una prueba conjunta presentada voluntariamente por el `Human Prime`, un observador externo no puede determinar si dos registros públicos `ifay_` pertenecen al mismo `Human Prime`.
4. **Intransferibilidad permanente**: una vez vinculado a un `HumanID`, un `iFay` `NO DEBE` transferirse a otro `HumanID` ni a ningún `OrganizationID`.

## 4.2 Titularidad de capa única de `coFay` y delegación ortogonal en `managers` (Normativo)

Para garantizar una responsabilidad directa y verificable sin capas opacas en cada entidad de rol compartido, FayID 1.0 impone **Titularidad de Capa Única** sobre `coFay`:

1. **Tipos de propietario permitidos**: `coFay.ownerId` `DEBE` ser un `HumanID` (`hid_`) o un `OrganizationID` (`org_`), con `ownerKind` fijado en `"HUMAN"` u `"ORGANIZATION"`. Todo intento de registrar o transferir un `coFay` bajo un `iFay` (`ifay_`) u otro `coFay` (`cofay_`) `DEBE` fallar de inmediato con `OWNER_TYPE_NOT_ALLOWED` (las cadenas anidadas de titularidad de `coFay` están prohibidas).
2. **Transferencia de titularidad**: el propietario directo actual (`hid_` u `org_`) `PUEDE` transferir un `coFay` a un nuevo propietario válido (`hid_` u `org_`) mediante una prueba de transferencia firmada, preservando `version: "1.0"` y actualizando el vínculo de titularidad.
3. **Administradores operativos ortogonales (`managers: iFayID[]`)**:
   - El propietario directo (`hid_` u `org_`) de un `coFay` `PUEDE` autorizar cero o más identificadores `iFayID` en `managers` para ejercer la administración operativa cotidiana.
   - Solo el propietario directo tiene autoridad para agregar o eliminar entradas en `managers`; un `iFay` incluido en `managers` `NO DEBE` agregar, eliminar ni redelegar otros administradores. Todo intento no autorizado de delegación `DEBE` fallar con `AUTHORITY_GRANT_UNAUTHORIZED` (delegación de un solo salto sin subdelegación).
   - La pertenencia operativa a `managers` nunca altera la titularidad jurídica o de gobernanza del `coFay`.

## 4.3 `OrganizationID` y `Steward` persona natural (Normativo)

1. **`Steward` persona natural obligatorio**: todo `OrganizationRecord` registrado `DEBE` designar un representante de gobernanza persona natural en `stewardHumanId` que referencie un `HumanID` (`hid_`) registrado y no revocado. Todo intento de asignar un identificador `ifay_`, `cofay_` u `org_` como `Steward` `DEBE` fallar con `STEWARD_TYPE_NOT_ALLOWED`.
2. **Rotación del `Steward`**: una organización `PUEDE` rotar `stewardHumanId` mediante una orden firmada por el par de claves de control de la organización, siempre que el sustituto sea también un `HumanID` válido y no revocado.

## 4.4 Jerarquía organizacional autónoma acíclica de padre único (Normativo)

FayID 1.0 define la jerarquía entre organizaciones directamente en esta especificación:

1. **Topología arbórea de padre único**: cada `OrganizationRecord` incluye `parentOrgId: OrganizationID | null`. Cada organización hija tiene como máximo una organización padre directa en cualquier instante, conformando un bosque de árboles dirigidos acíclicos. El protocolo **no impone ningún límite artificial fijo de profundidad** (como 16 niveles).
2. **Consentimiento mutuo bilateral**: vincular o reasignar `childOrg.parentOrgId = parentOrgId` `DEBE` incluir firmas Ed25519 válidas de consentimiento tanto de la clave de control de la organización hija como de la clave de control de la organización padre objetivo. La ausencia o invalidez del consentimiento de cualquiera de las partes `DEBE` fallar con `HIERARCHY_CONSENT_MISSING`.
3. **Rechazo determinista de ciclos**: toda vinculación que fije `parentOrgId` en la propia organización o en cualquiera de sus descendientes actuales `DEBE` fallar de manera determinista con `HIERARCHY_CYCLE_CONFLICT`.
4. **Sin absorción implícita de titularidad de `coFay`**: un `coFay` propiedad de una organización hija conserva ese `org_` hijo como su `ownerId` directo; incorporar una organización a un árbol padre no transfiere ni consolida de forma implícita la titularidad directa de los registros `coFay` de la organización hija.
