---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: de
canonical: false
chapter: 3
---

# Kapitel 3: Selbstsouveräne Kryptografie-Suite und Ableitung von Zweckunterschlüsseln

## 3.1 Selbstsouveränes Holder-of-Key-Vertrauensmodell (Normativ)

FayID 1.0 arbeitet nach einem rein selbstsouveränen Holder-of-Key-Vertrauensmodell:

1. Erzeugung und Kontrolle einer Identität beruhen ausschließlich auf dem kryptografischen Besitznachweis des zugehörigen privaten Ed25519-Schlüssels ohne jede Abhängigkeit von Signaturen zentraler Aussteller.
2. Jede zustandsverändernde Operation, die Berechtigung über eine `HumanID`, `iFayID`, `coFayID` oder `OrganizationID` beansprucht (Registrierung, Manager-Delegation, Einbindung in eine Organisationshierarchie, Eigentumsübertragung oder Widerruf), `MUSS` eine gültige Signatur des kontrollierenden Schlüsselpaars mitführen; fehlende oder ungültige Nachweise `MÜSSEN` mit `HUMAN_ID_OWNERSHIP_NOT_PROVEN`, `OWNERSHIP_NOT_PROVEN` oder `TARGET_OWNERSHIP_NOT_PROVEN` abgewiesen werden.

## 3.2 Verbindliche kryptografische Primitive (Normativ)

FayID 1.0 legt standardisierte kryptografische Primitive fest, die ohne externe Black-Box-Abhängigkeiten verfügbar sind:

| Funktion | Verbindliches Primitiv | Kanonische Ausgabegröße |
| --- | --- | --- |
| Asymmetrische Signaturen & Holder-of-Key-Nachweise | Ed25519 (RFC 8032 PureEdDSA) | 32 Byte roher öffentlicher Schlüssel, 64 Byte Signatur |
| Bezeichner-Digests & gesalzene Commitments | SHA-256 (FIPS 180-4) | 32 Byte Digest |
| Deterministische Ableitung von Zweckunterschlüsseln | HKDF-SHA256 (RFC 5869) | 32 Byte abgeleiteter Seed |
| Hashing von Bestandssubjekten & Dynamic-Code-MACs | HMAC-SHA256 (RFC 2104) | 32 Byte MAC (wo spezifiziert auf 20 Byte gekürzt) |
| Kanonische JSON-Signatur-Payloads | JCS (RFC 8785 JSON Canonicalization Scheme) | Deterministische UTF-8-Bytesequenz |

Die Rohentropie für `masterSeed`- und `userBlindSalt`-Eingaben `MUSS` mindestens **256 Bit (32 Byte)** betragen; Eingaben unter 32 Byte `MÜSSEN` mit `INSUFFICIENT_ENTROPY` fehlschlagen.

## 3.3 Domänengetrennte HKDF-SHA256-Zweckunterschlüssel (Normativ)

Damit Master-Seeds und private Wurzelschlüssel niemals in hochfrequente Signaturpfade oder ausgehende Archivpakete gelangen, `MUSS` ein `Holder Agent` kryptografisch isolierte 32-Byte-Zweckunterschlüssel mittels HKDF-SHA256 aus einem Master-Seed (`>= 32` Byte) ableiten:

```text
subkeySeed32 = HKDF-SHA256(
  ikm  = masterSeedBytes,
  salt = SHA-256(UTF8("fayid.subkey.salt:" || domain)),
  info = UTF8(domain || ":" || context),
  len  = 32
)
```

FayID 1.0 definiert fünf normative `SubkeyDomain`-Konstanten:

| Konstante | Domänentrennungs-String (`domain`) | Verwendungszweck und Sicherheitsgrenze |
| --- | --- | --- |
| `ENTITY` | `ifay.fayid.entity.v1` | Leitet entitätskontrollierende Ed25519-Schlüsselpaare für `HumanID`, `iFay`, `coFay` und `OrganizationID` ab |
| `EGO_PACKAGE_SIGNING` | `ifay.ego.package-signing.v1` | Eigener Ed25519-Signaturunterschlüssel ausschließlich für ausgehende `.ego`-Persona- und Zustandspakete |
| `DYNAMIC_CODE` | `ifay.fayid.dynamic-code.v1` | Leitet symmetrisches Schlüsselmaterial für Ausstellungs- und Prüfkontexte von Dynamic Codes (`dyn_`) ab |
| `AUTH_EXCHANGE` | `ifay.fayid.auth-exchange.v1` | Leitet Signaturschlüsselmaterial für Authorization Grants (`grt_`) und Verifikationsquittungen (`vrf_`) ab |
| `GMC_NATURAL_PERSON` | `ifay.gmc.natural-person.v1` | Leitet pseudozufälliges Schlüsselmaterial für blinde Anker natürlicher Personen (`gmcref_`) auf `GMChain` ab |

Implementierungen `MÜSSEN` zwei strikte Isolationsinvarianten durchsetzen:

1. **Verbindliche Domänentrennung**: Aufrufe zur Unterschlüsselableitung `MÜSSEN` nichtleere Zeichenketten für `domain` und `context` übergeben, wobei `domain` zur registrierten `SubkeyDomain`-Menge gehört; fehlende oder unbekannte Domänen `MÜSSEN` mit `DOMAIN_SEPARATION_REQUIRED` fehlschlagen.
2. **Keinerlei Offenlegung von Wurzelschlüsseln in ausgehenden Ego-Paketen**: Ausgehende `.ego`-Pakete `MÜSSEN` ausschließlich mit einem unter `ifay.ego.package-signing.v1` abgeleiteten Unterschlüssel signiert werden und einen Signaturumschlag mit `version: "1.0"`, `domain: "ifay.ego.package-signing.v1"`, `signerFayId`, `keyId`, `signingPublicKeyHex`, `manifestDigestSha256`, `signedAt` und `signatureHex` erzeugen. Die Felder `masterSeed`, `seed`, `privateKey`, `secretKey` oder `mnemonic` `DÜRFEN NICHT` in ausgehenden Paketen, öffentlichen Entitätsdatensätzen oder Verifikationsquittungen vorkommen; Prüfer `MÜSSEN` jeden Umschlag abweisen, der privates Schlüsselmaterial mitführt.

## 3.4 Kanonische Signaturregeln nach RFC 8785 JCS (Normativ)

Jede strukturierte Payload, die implementierungsübergreifend geprüft wird (Eigentumsbindungsnachweise, gegenseitige Hierarchie-Zustimmungen, Manifest-Signatur-Payloads von Ego-Paketen sowie Payloads von `vrf_`-Verifikationsquittungen), `MUSS` vor der Ed25519-Signierung bzw. -Prüfung oder dem SHA-256-Hashing gemäß RFC 8785 JCS in deterministische UTF-8-Bytes serialisiert werden:

1. Eigenschaftsnamen von Objekten werden in aufsteigender lexikografischer Reihenfolge nach UTF-16-Codeeinheiten sortiert; Eigenschaften mit dem Wert `undefined` entfallen;
2. Endliche Zahlen verwenden die minimale dezimale ECMAScript-Darstellung (`-0` wird als `"0"` serialisiert, `NaN` und `Infinity` werden abgewiesen);
3. Die Elementreihenfolge von Arrays bleibt unverändert erhalten, Zeichenketten nutzen minimales Standard-JSON-Escaping, und zwischen Tokens werden keinerlei bedeutungslose Leerzeichen ausgegeben.
