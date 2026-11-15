---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: es
canonical: false
chapter: 3
---

# Capítulo 3: Suite criptográfica autosoberana y derivación de subclaves por propósito

## 3.1 Modelo de confianza autosoberano Holder-of-Key (Normativo)

FayID 1.0 opera bajo un modelo de confianza puramente autosoberano basado en posesión de clave (Holder-of-Key):

1. La creación y el control de una identidad dependen exclusivamente de la prueba criptográfica de posesión de la clave privada Ed25519 correspondiente, sin depender en absoluto de firmas de emisores centralizados.
2. Toda operación de mutación de estado que reclame autoridad sobre un `HumanID`, `iFayID`, `coFayID` u `OrganizationID` (registro, delegación de administradores, vinculación jerárquica, transferencia de titularidad o revocación) `DEBE` portar una firma válida del par de claves de control; el verificador `DEBE` rechazar cualquier prueba ausente o inválida con `HUMAN_ID_OWNERSHIP_NOT_PROVEN`, `OWNERSHIP_NOT_PROVEN` o `TARGET_OWNERSHIP_NOT_PROVEN`.

## 3.2 Primitivas criptográficas obligatorias (Normativo)

FayID 1.0 estandariza primitivas criptográficas abiertas disponibles sin dependencias externas de caja negra:

| Función | Primitiva obligatoria | Tamaño de salida canónica |
| --- | --- | --- |
| Firmas asimétricas y pruebas Holder-of-Key | Ed25519 (RFC 8032 PureEdDSA) | Clave pública cruda de 32 bytes, firma de 64 bytes |
| Resúmenes de identificadores y compromisos con sal | SHA-256 (FIPS 180-4) | Resumen de 32 bytes |
| Derivación determinista de subclaves por propósito | HKDF-SHA256 (RFC 5869) | Semilla derivada de 32 bytes |
| Hash de sujetos heredados y MAC de Dynamic Codes | HMAC-SHA256 (RFC 2104) | MAC de 32 bytes (truncado a 20 bytes donde se especifique) |
| Cargas JSON canónicas de firma | JCS (RFC 8785 JSON Canonicalization Scheme) | Secuencia determinista de bytes UTF-8 |

La entropía cruda suministrada a `masterSeed` y `userBlindSalt` `DEBE` tener al menos **256 bits (32 bytes)**; toda entrada inferior a 32 bytes `DEBE` fallar con `INSUFFICIENT_ENTROPY`.

## 3.3 Subclaves por propósito con separación de dominio HKDF-SHA256 (Normativo)

Para garantizar que las semillas maestras y las claves privadas raíz nunca entren en rutas de firma de alta frecuencia ni en paquetes de archivo salientes, un `Holder Agent` `DEBE` derivar subclaves de 32 bytes criptográficamente aisladas por propósito a partir de una semilla maestra (`>= 32` bytes) mediante HKDF-SHA256:

```text
subkeySeed32 = HKDF-SHA256(
  ikm  = masterSeedBytes,
  salt = SHA-256(UTF8("fayid.subkey.salt:" || domain)),
  info = UTF8(domain || ":" || context),
  len  = 32
)
```

FayID 1.0 define cinco constantes normativas de `SubkeyDomain`:

| Constante | Cadena de separación de dominio (`domain`) | Propósito y frontera de seguridad |
| --- | --- | --- |
| `ENTITY` | `ifay.fayid.entity.v1` | Deriva pares de claves Ed25519 de control de entidad para `HumanID`, `iFay`, `coFay` y `OrganizationID` |
| `EGO_PACKAGE_SIGNING` | `ifay.ego.package-signing.v1` | Subclave de firma Ed25519 dedicada exclusivamente a paquetes salientes `.ego` de identidad digital y estado |
| `DYNAMIC_CODE` | `ifay.fayid.dynamic-code.v1` | Deriva material de clave simétrica para contextos de emisión y verificación de Dynamic Codes (`dyn_`) |
| `AUTH_EXCHANGE` | `ifay.fayid.auth-exchange.v1` | Deriva material de clave de firma para Authorization Grants (`grt_`) y recibos de verificación (`vrf_`) |
| `GMC_NATURAL_PERSON` | `ifay.gmc.natural-person.v1` | Deriva material de clave seudoaleatoria para anclas ciegas de persona natural (`gmcref_`) en `GMChain` |

Toda implementación `DEBE` hacer cumplir dos invariantes estrictas de aislamiento:

1. **Separación de dominio obligatoria**: toda invocación a la derivación de subclaves `DEBE` suministrar cadenas no vacías para `domain` y `context`, donde `domain` pertenezca al conjunto registrado `SubkeyDomain`; un dominio ausente o no reconocido `DEBE` fallar con `DOMAIN_SEPARATION_REQUIRED`.
2. **Exposición cero de claves raíz en paquetes Ego salientes**: todo paquete `.ego` saliente `DEBE` firmarse exclusivamente con una subclave derivada bajo `ifay.ego.package-signing.v1`, produciendo un sobre de firma que contenga `version: "1.0"`, `domain: "ifay.ego.package-signing.v1"`, `signerFayId`, `keyId`, `signingPublicKeyHex`, `manifestDigestSha256`, `signedAt` y `signatureHex`. Todo paquete saliente, registro público de entidad y recibo de verificación `NO DEBE` contener campos `masterSeed`, `seed`, `privateKey`, `secretKey` ni `mnemonic`; todo verificador `DEBE` rechazar cualquier sobre que porte material de clave privada.

## 3.4 Reglas de firma canónica JCS según RFC 8785 (Normativo)

Toda carga estructurada que se verifique entre implementaciones (pruebas de vinculación de titularidad, consentimientos mutuos de jerarquía, cargas de firma de manifiestos de paquetes Ego y cargas de recibos de verificación `vrf_`) `DEBE` serializarse en una secuencia determinista de bytes UTF-8 conforme a RFC 8785 JCS antes de ejecutar la firma o verificación Ed25519 o el resumen SHA-256:

1. El serializador ordena los nombres de propiedades de objetos en orden lexicográfico ascendente por unidades de código UTF-16 y omite aquellas propiedades cuyo valor sea `undefined`;
2. Representa los números finitos mediante la notación decimal mínima de ECMAScript (`-0` se serializa como `"0"`, y `NaN` o `Infinity` se rechazan);
3. Preserva intacto el orden de los elementos de los arreglos, aplica el escape estándar mínimo de cadenas JSON y no emite espacios en blanco no significativos entre tokens.
