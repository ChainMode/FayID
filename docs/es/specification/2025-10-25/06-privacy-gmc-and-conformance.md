---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: es
canonical: false
chapter: 6
---

# Capítulo 6: Fronteras de privacidad, interfaz `GMChain`, códigos de error y conformidad

## 6.1 Fronteras de redacción en cargas salientes y registros (Normativo)

Toda implementación conforme `DEBE` hacer cumplir las siguientes reglas ineludibles de privacidad tanto en la serialización en tránsito como en los registros de observabilidad:

1. **`hid_` en texto plano nunca abandona la frontera local ni entra en registros**: toda carga de red, instantánea de directorio público, paquete de exportación `.ego`, recibo de verificación entre partes (`vrf_`), volcado de fallos y registro de auditoría `NO DEBE` contener cadenas `hid_<base32>` en texto plano. Toda interacción externa `DEBE` realizarse empleando `ifay_`, `cofay_`, `dyn_`, `hidproof_` o anclas ciegas `gmcref_`.
2. **Cero material saliente de semillas o claves privadas**: toda semilla maestra (`masterSeed`), frase mnemónica, clave privada cruda (`privateKey` / `secretKey`) y valor `userBlindSalt` `DEBE` mantenerse confinado dentro del almacenamiento seguro local del `Holder Agent` y `NO DEBE` aparecer en registros públicos serializados ni en cargas salientes.
3. **No correlacionabilidad entre espacios de nombres**: cada dominio externo de consumo distinto `DEBE` aplicar cadenas de separación de dominio o sales diferenciadas para impedir que observadores externos correlacionen identificadores entre espacios de nombres con el fin de perfilar a un `Human Prime`.

## 6.2 Frontera de solo lectura frente a `GMChain` y ancla ciega `gmcref_` (Normativo)

`GMChain` normaliza el peso de gobernanza de persona natural y la resistencia Sybil de modo que una misma persona natural cuente como una única ancla de persona natural con independencia de cuántas identidades digitales `iFay` opere, sin conocer jamás `hid_` en texto plano. FayID 1.0 deriva de forma determinista el ancla ciega `gmcref_<base32>` como sigue:

```text
prk    = HKDF-SHA256(ikm = userBlindSalt, salt = SHA-256("fayid.gmc.salt.v1"), info = "ifay.gmc.natural-person.v1:" || namespace, len = 32)
digest = HMAC-SHA256(key = prk, data = UTF8("gmcref:" || canonicalHumanId))
gmcref = "gmcref_" || base32EncodeNoPad(digest)
```

Invariantes normativas:

1. **Determinismo e irreversibilidad**: dados el mismo `HumanID` canónico, `userBlindSalt` (`>= 32` bytes) y `namespace` (por defecto `"gmchain.main"`), `deriveBlindGmcRef` produce una cadena `gmcref_` idéntica. Sin `userBlindSalt`, ninguna parte externa (incluidos los nodos de `GMChain`) puede invertir `gmcref_` para recuperar `hid_` ni correlacionarlo con los registros públicos `ifay_` pertenecientes a ese `Human Prime`.
2. **Frontera estricta de solo lectura frente al libro mayor**: FayID suministra a `GMChain` únicamente entradas unidireccionales de derivación de anclas y estados de revocación; FayID no muta el estado del libro mayor de `GMChain` ni calcula, acuña o distribuye `MeriToken`. `MeriToken` es una métrica no monetaria de contribución social; no es una criptomoneda, no es canjeable por moneda fiduciaria, no se emite mediante minería, no es una red de liquidación financiera ni un activo especulativo.
3. **Alcance exclusivo de persona natural**: `deriveBlindGmcRef` acepta únicamente un `HumanID` (`hid_`) válido; suministrar un identificador `ifay_`, `cofay_` u `org_` `DEBE` fallar con `MALFORMED_FAYID_STRING`.

## 6.3 Registro normativo de códigos de error (Normativo)

Toda implementación conforme a FayID 1.0 `DEBE` preservar las siguientes 24 constantes estables de códigos de error (14 códigos base del protocolo más 10 códigos de cuentas, separación de dominio y gobernanza en cascada):

| Constante de código de error | Condición de disparo |
| --- | --- |
| `INSUFFICIENT_ENTROPY` | La semilla maestra, la sal ciega o la entropía aleatoria tiene menos de 256 bits (32 bytes) |
| `HUMAN_ID_OWNERSHIP_NOT_PROVEN` | Falta la firma Holder-of-Key requerida de `HumanID` o falla su verificación |
| `OWNERSHIP_NOT_PROVEN` | El control de la entidad o la transferencia de titularidad carece de una firma válida del propietario actual |
| `TARGET_OWNERSHIP_NOT_PROVEN` | La emisión de `grt_` carece de prueba Holder-of-Key válida para `targetFayId` (se devuelve con máxima precedencia para evitar el sondeo de vínculos) |
| `LEGACY_SUBJECT_MISMATCH` | El HMAC del sujeto canonizado de la credencial heredada no coincide con el `LegacySubjectRef` vinculado |
| `DYNAMIC_CODE_EXPIRED` | La marca temporal de verificación de `dyn_` supera `expiresAt` |
| `DYNAMIC_CODE_INVALID` | La sintaxis o el HMAC de `dyn_` es inválido, `audience` no coincide o el TTL solicitado supera 600 segundos |
| `VERIFICATION_RATE_LIMITED` | Los fallos consecutivos de verificación alcanzan el umbral de limitación de tasa (5 fallos en 600 s activan retroceso exponencial) |
| `IDENTITY_REVOKED` | Indicador base del estado de revocación de identidad |
| `LEGACY_AUTH_FAILED` | Falló la autenticación ascendente de la credencial heredada (contraseña, certificado, token o contrato inteligente) |
| `GRANT_EXPIRED` | La marca temporal de verificación de `grt_` supera `expiresAt` |
| `GRANT_REVOKED` | La concesión individual `grt_` ha sido revocada explícitamente |
| `GRANT_INVALID` | `grt_` es desconocido, está mal formado, apunta a un tipo de entidad inválido o `requestedResourceRef` cae fuera del alcance concedido |
| `MALFORMED_FAYID_STRING` | El prefijo o cuerpo Base32 del identificador es inválido, falla la validación sintáctica de `resourceRef` o se suministró un tipo de prefijo inesperado |
| `OWNER_TYPE_NOT_ALLOWED` | Intento de asignar un `iFay` o `coFay` como propietario de un `coFay` (vulnerando la titularidad de capa única) |
| `HIERARCHY_CONSENT_MISSING` | La vinculación jerárquica organizacional carece de una firma válida de la organización hija o de la organización padre |
| `HIERARCHY_CYCLE_CONFLICT` | La vinculación organizacional apunta a sí misma o a un descendiente existente, creando un ciclo |
| `AUTHORITY_GRANT_UNAUTHORIZED` | Un sujeto distinto del propietario (como una entrada en `coFay.managers`) intentó modificar o redelegar `managers` |
| `STEWARD_TYPE_NOT_ALLOWED` | El `Steward` de la organización no es un `HumanID` (`hid_`) válido y no revocado de persona natural |
| `ENTITY_REVOKED` | La entidad objetivo o su `HumanID` / `OrganizationID` propietario ascendente ha sido revocado directa o en cascada |
| `DYNAMIC_CODE_REPLAYED` | Un token `dyn_` de un solo uso se presentó más de una vez |
| `DYNAMIC_CODE_TARGET_NOT_ALLOWED` | Intento de emitir un token `dyn_` para un tipo de entidad objetivo no permitido, como `OrganizationID` |
| `DOMAIN_SEPARATION_REQUIRED` | La derivación HKDF de subclaves omitió un `SubkeyDomain` válido o una cadena de contexto no vacía |
| `RECEIPT_INVALID` | El recibo de verificación `vrf_` está mal formado o falla su verificación de firma Ed25519 |

## 6.4 Criterios de conformidad (Normativo)

Toda implementación, biblioteca o `Holder Agent` que declare conformidad con **FayID 1.0** `DEBE` satisfacer las cinco condiciones verificables siguientes:

1. **Conformidad de versión y esquema**: todo registro público de entidad y todo sobre de credencial emitido porta `version: "1.0"` y valida frente a [schemas/fayid-1.0.json](../../../../schemas/fayid-1.0.json).
2. **Conformidad de identificadores y coincidencia de recursos**: implementa la normalización de ocho prefijos del Capítulo 2, el rechazo estricto sin reparación silenciosa de entradas y la coincidencia segura por segmentos `EXACT` / `PREFIX` sobre `resourceRef`.
3. **Conformidad criptográfica y de aislamiento de claves raíz**: implementa Ed25519, SHA-256, los cinco dominios HKDF-SHA256 de subclaves por propósito y la firma canónica JCS (RFC 8785) del Capítulo 3, empleando `ifay.ego.package-signing.v1` exclusivamente para firmas de paquetes `.ego` con fuga cero de semillas o claves privadas.
4. **Conformidad de jerarquía de cuentas y revocación en cascada**: hace cumplir la titularidad de capa única de `coFay`, el `Steward` persona natural y los árboles organizacionales acíclicos de padre único con consentimiento mutuo del Capítulo 4, junto con la verificación antirrepetición de `dyn_`, el intercambio `grt_` / `vrf_` con alcance acotado y la revocación determinista en cascada sobre las cuatro clases de entidades del Capítulo 5.
5. **100% de aprobación de los vectores de conformidad**: supera todos los escenarios de prueba positivos y negativos definidos en [vectors/hierarchy/](../../../../vectors/hierarchy) y [vectors/crypto-and-revocation-vectors.json](../../../../vectors/crypto-and-revocation-vectors.json).
