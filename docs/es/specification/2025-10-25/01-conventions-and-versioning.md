---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: es
canonical: false
chapter: 1
---

# Capítulo 1: Convenciones normativas, terminología central y gobernanza de versiones

## 1.1 Alcance y exclusiones

FayID 1.0 define los identificadores de identidad autosoberana, la derivación de subclaves acotadas por propósito, las invariantes de titularidad de entidades y jerarquía organizacional, los códigos dinámicos no correlacionables, el intercambio de autorización de credenciales heredadas, la revocación en cascada y las anclas de persona natural que preservan la privacidad frente a `GMChain` en todo el ecosistema iFay.

Los siguientes aspectos quedan explícitamente fuera del alcance de FayID 1.0:

1. **Encapsulado de transporte y negociación de sesiones**: la familia de protocolos Faying gobierna el entramado de mensajes entre agentes y la seguridad de transporte; FayID aporta las primitivas de identidad, los sobres de firma y los recibos de verificación.
2. **Planificación de procesos en tiempo de ejecución**: el entorno de ejecución FayGer gobierna la orquestación de procesos de instancias `iFay` y `coFay` en dispositivos terminales.
3. **Contabilidad de reputación y cálculo de peso de gobernanza**: `GMChain` define de forma independiente la acumulación y la ponderación de gobernanza de `MeriToken`. FayID mantiene una frontera de solo lectura hacia `GMChain` y emite únicamente el ancla ciega `gmcref_`.
4. **Verificación centralizada de identidad (KYC)**: FayID 1.0 no presupone ningún registro centralizado ni autoridad de certificación raíz.

## 1.2 Palabras clave normativas (Normativo)

Las palabras clave normativas en español `DEBE`, `REQUERIDO`, `NO DEBE`, `DEBERÍA`, `RECOMENDADO`, `NO DEBERÍA`, `NO RECOMENDADO`, `PUEDE` y `OPCIONAL` empleadas en este documento corresponden directamente a los términos `MUST`, `MUST NOT`, `REQUIRED`, `SHALL`, `SHALL NOT`, `SHOULD`, `SHOULD NOT`, `RECOMMENDED`, `NOT RECOMMENDED`, `MAY` y `OPTIONAL` definidos en [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) y [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174), única y exclusivamente cuando aparecen en mayúsculas, según se resume a continuación:

| Equivalente normativo en español | Palabra clave RFC 2119 / RFC 8174 | Significado normativo |
| --- | --- | --- |
| `DEBE` / `REQUERIDO` | `MUST` / `SHALL` / `REQUIRED` | Requisito absoluto del protocolo; cualquier incumplimiento invalida la conformidad de la implementación |
| `NO DEBE` | `MUST NOT` / `SHALL NOT` | Prohibición absoluta del protocolo; cualquier incumplimiento invalida la conformidad de la implementación |
| `DEBERÍA` / `RECOMENDADO` | `SHOULD` / `RECOMMENDED` | Requisito predeterminado firme que corresponde seguir salvo que existan razones de ingeniería documentadas que justifiquen lo contrario |
| `NO DEBERÍA` / `NO RECOMENDADO` | `SHOULD NOT` / `NOT RECOMMENDED` | Comportamiento que corresponde evitar salvo que existan razones de ingeniería documentadas que justifiquen lo contrario |
| `PUEDE` / `OPCIONAL` | `MAY` / `OPTIONAL` | Capacidad genuinamente discrecional; los pares interoperables deben admitir tanto su presencia como su ausencia |

## 1.3 Terminología central (Normativo)

Toda implementación, esquema y documento derivado `DEBE` hacer cumplir las siguientes fronteras terminológicas:

- **`Human Prime`**: la persona natural real identificada por un `HumanID` (`hid_`) que posee y controla sus identidades digitales individuales. Toda especificación, comentario de código y campo de API `DEBE` emplear de manera uniforme `Human Prime` al referirse a la persona natural.
- **`Host`**: se refiere **exclusivamente** a un dispositivo terminal, entorno de sistema operativo o aplicación cliente donde se ejecuta o monta una instancia `Fay`. Toda implementación y documentación `NO DEBE` utilizar `Host` para referirse a una persona natural ni a un `Human Prime`.
- **`Fay` (`Fay = iFay + coFay`)**: término colectivo que abarca todas las entidades digitales responsables con identidad verificable dentro del ecosistema iFay, divididas en dos subconjuntos mutuamente excluyentes:
  - **`iFay` (Fay individual, `ifay_`)**: identidad digital personal vinculada de forma intransferible en relación `1:N` a un único `HumanID` (`HumanID : iFayID = 1:N`).
  - **`coFay` (Fay de rol compartido, `cofay_`)**: entidad digital colaborativa, de servicio o de rol público vinculada directamente a un único `HumanID` o a un único `OrganizationID`, que admite transferencia de titularidad y delegación ortogonal de administración operativa.
- **`OrganizationID` (`org_`)**: entidad jurídica o de gobernanza responsable de activos organizacionales, representada por un `Steward` persona natural y habilitada para participar en un árbol organizacional acíclico de padre único.
- **`Holder Agent`**: componente local de software de gestión de claves y autoemisión controlado por un `Human Prime` o una organización y ejecutado sobre un `Host` controlado (dispositivo terminal o aplicación cliente), en lugar de una autoridad remota centralizada.
- **`GMChain` y `MeriToken`**: `GMChain` es el libro mayor público de reputación que registra las contribuciones sociales en todo el ecosistema; `MeriToken` (medido en `Merit Unit`) es una métrica no monetaria de contribución social; no es una criptomoneda, no es canjeable por moneda fiduciaria, no se emite mediante minería, no es una red de liquidación financiera ni un activo especulativo.

## 1.4 Gobernanza y negociación de versiones del protocolo (Normativo)

### 1.4.1 Tres ejes ortogonales

FayID separa tres ejes distintos que `NO DEBE` confundir ninguna implementación:

1. **Versión de protocolo en tránsito (`MAJOR.MINOR`)**: utiliza una cadena `MAJOR.MINOR` de dos segmentos (`"1.0"` para FayID 1.0) **sin segmento `PATCH`**. Todo campo `version` en sobres en tránsito y toda restricción `const` de JSON Schema `DEBE` fijarse únicamente en `"1.0"`.
2. **Estado del documento**: indica la madurez de la especificación (como `Draft` o `Final`). El estado del documento figura exclusivamente en el encabezado documental y `NO DEBE` incorporarse en cargas en tránsito.
3. **Fecha de edición**: emplea una fecha ISO `YYYY-MM-DD` (`2025-10-25` para esta edición) para identificar directorios de archivo de la especificación y rutas de instantáneas de esquemas, y `NO DEBE` incorporarse en cargas en tránsito.

### 1.4.2 Criterios de evolución mayor y menor

- **Incremento menor (`MINOR`)**: reservado a extensiones aditivas retrocompatibles (tales como campos opcionales de sobre, nuevas constantes de dominio para subclaves por propósito o metadatos opcionales de credenciales). Los pares que implementan una versión menor `1.x` anterior conservan la capacidad de validar firmas e invariantes centrales ignorando los campos opcionales desconocidos.
- **Incremento mayor (`MAJOR`)**: todo cambio incompatible (alterar expresiones regulares de identificadores, sustituir primitivas base de hash o firma, modificar cadenas de dominio HKDF, endurecer campos obligatorios existentes o cambiar los efectos de la revocación en cascada) `DEBE` incrementar `MAJOR`.
- **Revisiones editoriales**: toda actualización de edición dentro de una misma versión `MAJOR.MINOR` se limita a aclaraciones no normativas y `NO DEBE` alterar ningún resultado de conformidad.

### 1.4.3 Negociación de versión y compatibilidad hacia adelante

1. Todo par que intercambie registros, sobres o recibos FayID `DEBE` validar el campo `version`. Un registro conforme a FayID 1.0 `DEBE` establecer `version` exactamente en `"1.0"` (`"1"`, `"1.0.0"` y `"v1.0"` son inválidos).
2. Toda implementación compatible con múltiples versiones menores dentro de `MAJOR = 1` `DEBE` negociar la versión `1.x` más alta soportada mutuamente y mantener compatibilidad hacia atrás hasta `"1.0"`.
3. Ante una versión `MAJOR` desconocida o no soportada, el verificador `DEBE` rechazar la carga de inmediato y `NO DEBE` intentar una degradación silenciosa ni omitir la verificación de firma.
4. Todo verificador que procese cargas dentro de la misma versión `MAJOR` `DEBE` ignorar los campos de extensión opcionales no reconocidos durante la validación de negocio, pero `DEBE` preservar todos los campos presentes en un objeto firmado al calcular los bytes canónicos JCS (RFC 8785) para verificar la firma.
5. Una actualización progresiva entre versiones menores `1.x` `NO DEBE` invalidar prematuramente credenciales `dyn_`, `grt_` o `vrf_` emitidas previamente que aún no hayan expirado.
