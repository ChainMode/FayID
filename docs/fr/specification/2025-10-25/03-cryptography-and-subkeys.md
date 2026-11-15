---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: fr
canonical: false
chapter: 3
---

# Chapitre 3 : Suite cryptographique auto-souveraine et dérivation de sous-clés dédiées par finalité

## 3.1 Modèle de confiance auto-souverain `Holder-of-Key` (Normatif)

FayID 1.0 repose sur un modèle de confiance `Holder-of-Key` purement auto-souverain :

1. La création et le contrôle d'une identité reposent exclusivement sur la preuve cryptographique de possession de la clé privée Ed25519 correspondante, sans aucune dépendance envers les signatures d'un émetteur centralisé.
2. Toute opération modifiant l'état qui revendique une autorité sur un `HumanID`, un `iFayID`, un `coFayID` ou un `OrganizationID` (inscription, délégation de gestionnaires, rattachement hiérarchique, transfert de propriété ou révocation) `DOIT` comporter une signature valide émise par la paire de clés de contrôle ; toute preuve absente ou invalide `DOIT` être rejetée avec `HUMAN_ID_OWNERSHIP_NOT_PROVEN`, `OWNERSHIP_NOT_PROVEN` ou `TARGET_OWNERSHIP_NOT_PROVEN`.

## 3.2 Primitives cryptographiques obligatoires (Normatif)

FayID 1.0 normalise l'emploi de primitives cryptographiques standards disponibles sans dépendances opaques externes :

| Fonction | Primitive obligatoire | Taille de sortie canonique |
| --- | --- | --- |
| Signatures asymétriques et preuves `Holder-of-Key` | Ed25519 (RFC 8032 PureEdDSA) | Clé publique brute de 32 octets, signature de 64 octets |
| Condensats d'identifiants et engagements salés | SHA-256 (FIPS 180-4) | Condensat de 32 octets |
| Dérivation déterministe de sous-clés par finalité | HKDF-SHA256 (RFC 5869) | Graine dérivée de 32 octets |
| Hachage de sujets patrimoniaux et MAC de Dynamic Codes | HMAC-SHA256 (RFC 2104) | MAC de 32 octets (tronqué à 20 octets lorsque spécifié) |
| Charges utiles JSON canoniques à signer | JCS (RFC 8785 JSON Canonicalization Scheme) | Séquence d'octets UTF-8 déterministe |

L'entropie brute fournie en entrée pour `masterSeed` et `userBlindSalt` `DOIT` atteindre au minimum **256 bits (32 octets)** ; toute entrée inférieure à 32 octets `DOIT` échouer avec `INSUFFICIENT_ENTROPY`.

## 3.3 Sous-clés dédiées par finalité à séparation de domaine HKDF-SHA256 (Normatif)

Afin de garantir que les graines maîtresses et les clés privées racines n'entrent jamais dans les chemins de signature à haute fréquence ni dans les lots d'archives sortants, un `Holder Agent` `DOIT` dériver des sous-clés dédiées par finalité de 32 octets, isolées cryptographiquement, à partir d'une graine maîtresse (`>= 32` octets) via HKDF-SHA256 :

```text
subkeySeed32 = HKDF-SHA256(
  ikm  = masterSeedBytes,
  salt = SHA-256(UTF8("fayid.subkey.salt:" || domain)),
  info = UTF8(domain || ":" || context),
  len  = 32
)
```

FayID 1.0 définit cinq constantes normatives `SubkeyDomain` :

| Constante | Chaîne de séparation de domaine (`domain`) | Finalité et frontière de sécurité |
| --- | --- | --- |
| `ENTITY` | `ifay.fayid.entity.v1` | Dérive les paires de clés Ed25519 contrôlant les entités `HumanID`, `iFay`, `coFay` et `OrganizationID` |
| `EGO_PACKAGE_SIGNING` | `ifay.ego.package-signing.v1` | Sous-clé de signature Ed25519 dédiée exclusivement aux paquets `.ego` sortants de persona et d'état |
| `DYNAMIC_CODE` | `ifay.fayid.dynamic-code.v1` | Dérive le matériel de clé symétrique pour les contextes d'émission et de vérification de Dynamic Codes (`dyn_`) |
| `AUTH_EXCHANGE` | `ifay.fayid.auth-exchange.v1` | Dérive le matériel de clé de signature pour les Authorization Grants (`grt_`) et les reçus de vérification (`vrf_`) |
| `GMC_NATURAL_PERSON` | `ifay.gmc.natural-person.v1` | Dérive le matériel de clé pseudo-aléatoire pour les ancres aveugles de personne physique (`gmcref_`) sur `GMChain` |

Les implémentations `DOIVENT` faire respecter deux invariants stricts d'isolation :

1. **Séparation de domaine obligatoire** : Tout appel à la dérivation de sous-clé `DOIT` fournir des chaînes `domain` et `context` non vides où `domain` appartient à l'ensemble `SubkeyDomain` enregistré ; tout domaine absent ou non reconnu `DOIT` échouer avec `DOMAIN_SEPARATION_REQUIRED`.
2. **Absence totale d'exposition de clé racine dans les paquets Ego sortants** : Les paquets `.ego` sortants `DOIVENT` être signés exclusivement au moyen d'une sous-clé dérivée sous `ifay.ego.package-signing.v1`, produisant une enveloppe de signature contenant `version: "1.0"`, `domain: "ifay.ego.package-signing.v1"`, `signerFayId`, `keyId`, `signingPublicKeyHex`, `manifestDigestSha256`, `signedAt` et `signatureHex`. Les paquets sortants, les enregistrements publics d'entités et les reçus de vérification `NE DOIVENT PAS` contenir les champs `masterSeed`, `seed`, `privateKey`, `secretKey` ou `mnemonic` ; les vérificateurs `DOIVENT` rejeter toute enveloppe transportant du matériel de clé privée.

## 3.4 Règles de signature canonique JCS RFC 8785 (Normatif)

Toute charge utile structurée vérifiée entre implémentations (preuves de liaison de propriété, consentements hiérarchiques mutuels, charges utiles de signature de manifeste de paquet Ego et charges utiles de reçu de vérification `vrf_`) `DOIT` être sérialisée en octets UTF-8 déterministes selon RFC 8785 JCS avant toute signature/vérification Ed25519 ou tout hachage SHA-256 :

1. Les noms de propriétés d'objet sont triés par ordre lexicographique croissant selon leurs unités de code UTF-16, en omettant les propriétés dont la valeur est `undefined` ;
2. Les nombres finis utilisent la représentation décimale minimale ECMAScript (`-0` est sérialisé en `"0"`, et `NaN`/`Infinity` sont rejetés) ;
3. L'ordre des éléments de tableau est conservé tel quel, les chaînes utilisent l'échappement JSON minimal standard et aucun caractère d'espacement non significatif n'est émis entre les jetons.
