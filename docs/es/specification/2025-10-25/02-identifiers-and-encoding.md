---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: es
canonical: false
chapter: 2
---

# Capítulo 2: Sintaxis de identificadores, codificación Base32 y referencias de recursos

## 2.1 Prefijos canónicos de identificadores (Normativo)

Todo identificador criptográfico y cadena de credencial derivada en FayID `DEBE` seguir la sintaxis `<prefix>_<body>`. Salvo `org_`, que admite caracteres de identificador legible en minúsculas `[a-z0-9-]+`, el cuerpo de todo identificador `DEBE` utilizar **Base32 RFC 4648 en minúsculas y sin relleno** (`[a-z2-7]+`):

| Constante de tipo | Prefijo | Patrón del cuerpo | Tamaño típico de carga y semántica de responsabilidad |
| --- | --- | --- | --- |
| `HUMAN_ID` | `hid_` | `^[a-z2-7]+$` | `SHA-256(humanPublicKey)` (32 bytes -> 52 caracteres Base32); identidad raíz de un `Human Prime` |
| `IFAY_ID` | `ifay_` | `^[a-z2-7]+$` | `SHA-256("ifay:" \|\| humanId \|\| ":" \|\| publicKey)` (32 bytes); identidad digital individual |
| `COFAY_ID` | `cofay_` | `^[a-z2-7]+$` | `SHA-256("cofay:" \|\| ownerId \|\| ":" \|\| publicKey)` (32 bytes); entidad digital de rol compartido |
| `ORGANIZATION_ID` | `org_` | `^[a-z0-9-]+$` | Identificador de organización responsable (cuerpo hash determinista o slug normalizado en minúsculas) |
| `DYNAMIC_CODE` | `dyn_` | `^[a-z2-7]+$` | Etiqueta HMAC truncada a 20 bytes (32 caracteres Base32); token de presentación efímero y no correlacionable |
| `VERIFICATION_CODE` | `vrf_` | `^[a-z2-7]+$` | Resumen de recibo de verificación de 20 bytes vinculado a una comprobación verificada de `grt_` o `cofay_` |
| `AUTHORIZATION_GRANT` | `grt_` | `^[a-z2-7]+$` | Identificador de concesión de intercambio de credencial heredada con alcance acotado de 20 bytes |
| `OPAQUE_REF` | `gmcref_` | `^[a-z2-7]+$` | Ancla ciega de persona natural de 32 bytes (52 caracteres Base32) para deduplicación en `GMChain` |

Adicionalmente, los registros públicos de inscripción de `iFay` y los paquetes sin conexión representan el compromiso unidireccional con sal hacia su `HumanID` propietario mediante `hidproof_<lowercase-base32-nopad>` (`^hidproof_[a-z2-7]{16,}$`), de modo que `hid_` nunca aparece en texto plano en registros públicos.

## 2.2 Reglas de normalización y rechazo estricto (Normativo)

La función `normalizeFayID(input)` `DEBE` aplicar de manera determinista las siguientes reglas:

1. **Comprobación de tipo y cadena no vacía**: toda entrada que no sea una cadena o que sea una cadena vacía `DEBE` fallar de inmediato con `MALFORMED_FAYID_STRING`.
2. **Conversión ASCII a minúsculas**: el analizador `DEBE` convertir las letras mayúsculas ASCII a minúsculas (`input.toLowerCase()`) antes de evaluar los ocho prefijos canónicos.
3. **Rechazo estricto sin reparación silenciosa**: el analizador `NO DEBE` recortar espacios iniciales o finales, eliminar guiones (fuera de cuerpos `org_` válidos), suprimir caracteres de relleno `=` ni sustituir dígitos visualmente similares (como convertir `0`, `1`, `8` o `9` en letras Base32). Toda entrada que contenga espacios en blanco, relleno `=`, un prefijo desconocido, un cuerpo vacío o caracteres fuera del alfabeto permitido `DEBE` fallar con `MALFORMED_FAYID_STRING`.
4. **Invariantes de ida y vuelta**: para todo identificador canónico válido `x`, invocar nuevamente `normalizeFayID(x)` `DEBE` devolver `ok: true` con `value.canonical === x`. Codificar cualquier arreglo de bytes `b` en Base32 en minúsculas sin relleno y decodificarlo de vuelta `DEBE` recuperar `b` byte por byte, y el decodificador `DEBE` rechazar cualquier bit sobrante final distinto de cero durante la decodificación Base32.

## 2.3 Sintaxis de `resourceRef` y coincidencia de alcance (Normativo)

Auth Exchange direcciona los recursos objetivo mediante `resourceRef`. Cada una de las funciones `normalizeResourceRef(input)` y `matchesResourceRef(grantedResourceRef, requestedResourceRef, scopeMode)` `DEBE` hacer cumplir las reglas siguientes:

1. **Gramática**: `resourceRef` sigue el formato `<namespace>:<path>`:
   - `<namespace>`, tras su conversión a minúsculas, `DEBE` coincidir con `^[a-z][a-z0-9+.-]*$`;
   - `<path>` a la derecha de `:` `DEBE` ser no vacío, contener cero caracteres de espacio en blanco, no terminar en `/` (salvo que la ruta sea únicamente `/`), y `NO DEBE` contener segmentos vacíos (`//`) ni segmentos de navegación relativa (`.` o `..`).
   - Cualquier incumplimiento `DEBE` devolver `MALFORMED_FAYID_STRING`.
2. **Sensibilidad a mayúsculas y minúsculas**: `<namespace>` se normaliza a minúsculas, mientras que `<path>` `DEBE` preservar exactamente sus mayúsculas y minúsculas originales.
3. **Coincidencia de alcance (`scopeMode`)**:
   - `EXACT` (predeterminado): coincide si y solo si el valor normalizado cumple `requestedResourceRef === grantedResourceRef`.
   - `PREFIX`: coincide si y solo si el valor normalizado `requestedResourceRef` es igual a `grantedResourceRef` o comienza con `grantedResourceRef + "/"` sobre una frontera explícita de segmento `/`. Por ejemplo, una concesión `PREFIX` sobre `cap:repo/fayid` coincide con `cap:repo/fayid/issues`, pero `NO DEBE` coincidir con la ruta hermana `cap:repo/fayid-ext`.

## 2.4 Adaptación heredada de claves públicas de 64 caracteres hexadecimales (Normativo)

Para migrar registros tempranos que almacenan claves públicas Ed25519 crudas de 32 bytes como 64 caracteres hexadecimales, las implementaciones proveen `adaptLegacyHexIdentifier(hex64, prefix)`:

1. Tras recortar los espacios exteriores, `hex64` `DEBE` coincidir con `^[0-9a-fA-F]{64}$`, y `prefix` `DEBE` ser `hid_`, `ifay_` o `cofay_`; en caso contrario, la invocación `DEBE` fallar con `MALFORMED_FAYID_STRING`.
2. El adaptador calcula `SHA-256` sobre la clave pública decodificada de 32 bytes y codifica el resumen como `<prefix><base32-nopad>`, coincidiendo con la derivación nativa de identificadores raíz.
3. Una carga en tránsito conforme a FayID 1.0 `NO DEBE` transmitir cadenas crudas de 64 caracteres hexadecimales en lugar de identificadores FayID canónicos; la conversión `DEBE` efectuarse de forma explícita en la frontera de ingesta.
