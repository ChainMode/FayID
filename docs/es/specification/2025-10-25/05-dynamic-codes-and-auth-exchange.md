---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: es
canonical: false
chapter: 5
---

# Capítulo 5: Dynamic Codes no correlacionables, Auth Exchange y revocación en cascada

## 5.1 Emisión y verificación de Dynamic Codes (`dyn_`) no correlacionables (Normativo)

Dado que `hid_` en texto plano nunca abandona la frontera local de confianza, un `Human Prime` y sus entidades `iFay` o `coFay` presentan Dynamic Codes (`dyn_<base32>`) efímeros y protegidos con `nonce` al cruzar fronteras de confianza:

1. **Entidades objetivo permitidas**: solo se `PUEDE` emitir un Dynamic Code para sujetos `HumanID` (`hid_`), `iFayID` (`ifay_`) o `coFayID` (`cofay_`) no revocados. Solicitar un Dynamic Code para un `OrganizationID` (`org_`) `DEBE` fallar con `DYNAMIC_CODE_TARGET_NOT_ALLOWED` (los identificadores organizacionales son públicos por diseño).
2. **Construcción no correlacionable con `nonce`**: cada emisión genera al menos 16 bytes de `nonce` aleatorio criptográfico, calcula HMAC-SHA256 bajo la clave de dominio `ifay.fayid.dynamic-code.v1` sobre la carga canónica JCS `{audience, expiresAt, issuedAt, nonceHex, targetId, version: "1.0"}` y codifica los primeros 20 bytes como `dyn_<base32>`. Un observador pasivo que carezca del contexto de clave de verificación no puede correlacionar dos tokens `dyn_` presentados por el mismo sujeto.
3. **Límite superior estricto de TTL**: `expiresAt - issuedAt` `DEBE` ser estrictamente positivo y `NO DEBE` superar **`600` segundos (`DYNAMIC_CODE_MAX_TTL_SECONDS = 600`)**; toda solicitud con un TTL fuera de rango `DEBE` fallar con `DYNAMIC_CODE_INVALID`.
4. **Verificación antirrepetición de un solo uso**: al verificar un token `dyn_`:
   - Si el sujeto subyacente o su propietario ascendente ha sido revocado, la verificación `DEBE` fallar con `ENTITY_REVOKED`;
   - Si la verificación ocurre después de `expiresAt`, la verificación `DEBE` fallar con `DYNAMIC_CODE_EXPIRED`;
   - Si `audience` no coincide (cuando está vinculado a una audiencia objetivo) o el token es desconocido, la verificación `DEBE` fallar con `DYNAMIC_CODE_INVALID`;
   - Cada `nonce` de `dyn_` `DEBE` aceptarse con éxito como máximo **una vez**; toda segunda o posterior presentación del mismo token `dyn_` `DEBE` fallar con `DYNAMIC_CODE_REPLAYED`.
5. **Resolución con preservación de privacidad para `HumanID`**: cuando el sujeto subyacente de un token `dyn_` verificado es un `HumanID`, la respuesta de verificación `NO DEBE` revelar `hid_` en texto plano; en su lugar, `DEBE` devolver el tipo de sujeto `"HUMAN"` junto con el ancla ciega determinista `gmcref_<base32>`.

## 5.2 Vinculación de credenciales heredadas y Auth Exchange (`grt_` / `vrf_`) (Normativo)

Auth Exchange conecta credenciales heredadas externas con Authorization Grants (`grt_<base32>`) de FayID con alcance acotado y produce recibos de verificación (`vrf_<base32>`) verificables sin conexión:

1. **`LegacySubjectRef` resumido mediante HMAC**: todo identificador externo de sujeto `DEBE` canonizarse y resumirse mediante HMAC con clave en la forma `<legacySourceKind>:<issuerOrAuthority>:<subjectHash>`, donde `subjectHash = base32NoPad(HMAC-SHA256(legacySecret, canonicalSubject))`. `LegacySubjectRef` `NO DEBE` incrustar direcciones de correo electrónico en texto plano, números telefónicos, nombres distinguidos X.509, tokens OAuth crudos ni direcciones de billeteras de cadenas de bloques en texto plano.
2. **Asignación predeterminada de `LegacyTrustLevel`**:
   - `PASSWORD` -> `LOW` (límite superior de TTL de la concesión: **`900` segundos**, `LOW_TRUST_GRANT_MAX_TTL_SECONDS`);
   - `ACCESS_TOKEN`, `AUTHORIZATION` -> `MEDIUM` (límite superior de TTL de la concesión: **`3600` segundos**, `GRANT_MAX_TTL_SECONDS`);
   - `CERTIFICATE`, `SMART_CONTRACT` -> `HIGH` (límite superior de TTL de la concesión: **`3600` segundos**).
   Una implementación `PUEDE` reducir el nivel de confianza o acortar el TTL conforme a su política local de riesgo, y `NO DEBE` elevar el nivel de confianza sin una prueba adicional multifactor de posesión por parte del titular.
3. **Precedencia de la prueba de titularidad objetivo (antisondeo)**: una concesión `grt_` `PUEDE` dirigirse únicamente a entidades `iFayID` o `coFayID` no revocadas, y su emisión `DEBE` verificar una firma Holder-of-Key que demuestre control sobre `targetFayId`. Si falta la prueba de titularidad objetivo o resulta inválida, la emisión `DEBE` devolver `TARGET_OWNERSHIP_NOT_PROVEN` antes de evaluar cualquier vínculo de sujeto heredado, impidiendo que un atacante sondee si una cuenta heredada está vinculada a un FayID específico.
4. **Verificación de concesiones con alcance acotado y recibos `vrf_`**: `verifyAuthGrant` evalúa, en este orden:
   - Existencia y validez sintáctica de la concesión (de lo contrario, `GRANT_INVALID`);
   - Estado de revocación de `targetFayId` y de su propietario ascendente (devuelve `ENTITY_REVOKED` si está revocado);
   - Estado de revocación explícita de la concesión (de lo contrario, `GRANT_REVOKED`);
   - Expiración frente a `expiresAt` (de lo contrario, `GRANT_EXPIRED`);
   - Coincidencia de alcance entre `requestedResourceRef` y `resourceRef` según `scopeMode` de la Sección 2.3 (`EXACT` o `PREFIX`, devolviendo `GRANT_INVALID` si no coincide).
   En caso de éxito, el verificador firma la carga canónica del recibo con la clave Ed25519 del dominio `ifay.fayid.auth-exchange.v1` y devuelve un recibo `vrf_<base32>`. Cualquier parte confiante puede invocar `verifyAuthReceipt(receipt)` para validar sin conexión la firma Ed25519 y su estructura; cualquier campo alterado `DEBE` fallar con `RECEIPT_INVALID`.

## 5.3 Revocación determinista en cascada (Normativo)

La revocación es monótona e irreversible. Revocar cualquier entidad `DEBE` propagarse de manera síncrona en cascada hacia todas las entidades descendientes y credenciales activas sin dejar registros activos huérfanos:

| Entidad disparadora revocada | Entidades descendientes revocadas en cascada | Limpieza colateral obligatoria sobre administradores y credenciales |
| --- | --- | --- |
| **`HumanID` (`hid_`)** | Todo `iFay` (`ifay_`) vinculado a ese `hid_`, más todo `coFay` (`cofay_`) cuyo propietario directo sea ese `hid_` | Retirar todos los identificadores `ifay_` revocados en cascada de toda lista `coFay.managers` superviviente; revocar toda concesión `grt_` activa y todo token `dyn_` no consumido dirigido a cualquier `ifay_` o `cofay_` afectado en cascada |
| **`OrganizationID` (`org_`)** | La propia organización, todo su subárbol recursivo de organizaciones descendientes y todo `coFay` cuyo propietario directo sea la organización o cualquiera de sus organizaciones descendientes | Revocar toda concesión `grt_` activa y todo token `dyn_` no consumido dirigido a cualquier `cofay_` afectado en cascada |
| **`iFayID` (`ifay_`)** | Esa instancia `iFay` | Retirar de inmediato ese `ifay_` de toda lista `coFay.managers` superviviente; revocar toda concesión `grt_` activa y todo token `dyn_` no consumido dirigido a ese `ifay_` |
| **`coFayID` (`cofay_`)** | Esa instancia `coFay` | Revocar toda concesión `grt_` activa y todo token `dyn_` no consumido dirigido a ese `cofay_` |

Una vez completada la revocación:
1. Emitir nuevos tokens `dyn_`, emitir nuevas concesiones `grt_`, registrar entidades subordinadas o verificar credenciales existentes frente a cualquier entidad revocada directa o en cascada `DEBE` fallar de manera determinista con `ENTITY_REVOKED` (mientras que la revocación individual de una concesión cuya entidad objetivo permanece activa devuelve `GRANT_REVOKED`).
2. Toda credencial vinculada a una entidad revocada queda invalidada **de inmediato**, aun cuando su marca temporal original `expiresAt` no haya vencido todavía.
