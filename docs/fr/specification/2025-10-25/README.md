---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: fr
canonical: false
---

# Spécification du protocole FayID 1.0

FayID est le protocole d'identité de responsabilité auto-souveraine (`Holder-of-Key`) de l'écosystème iFay. Sans dépendre d'aucune autorité de certification (CA) ni d'aucun fournisseur d'identité (IdP) centralisés, FayID lie chaque persona numérique individuel (`iFay`) de manière non transférable selon une relation un-à-plusieurs à un **Human Prime** unique (`hid_`), et lie directement chaque entité numérique à rôle partagé (`coFay`), en une seule couche de propriété, à un `HumanID` (`hid_`) ou à un `OrganizationID` (`org_`) responsable.

Ce répertoire contient l'édition française (`fr`) de la **Spécification finale FayID 1.0 (Édition `2025-10-25`)**. Tous les chapitres et toutes les clauses normatives correspondent terme à terme à la spécification canonique en chinois simplifié (`zh-CN`), qui constitue l'édition canonique faisant foi ; en cas de divergence d'interprétation entre les langues, l'édition `zh-CN` prévaut.

## Chapitres de la spécification

| Chapitre | Fichier | Périmètre normatif |
| --- | --- | --- |
| Chapitre 1 | [01-conventions-and-versioning.md](./01-conventions-and-versioning.md) | Périmètre, mots-clés normatifs RFC 2119 / RFC 8174, frontières terminologiques fondamentales et gestion de version et négociation à deux segments `1.0` du protocole |
| Chapitre 2 | [02-identifiers-and-encoding.md](./02-identifiers-and-encoding.md) | Huit préfixes canoniques, encodage Base32 RFC 4648 en minuscules sans bourrage, invariants de rejet strict et d'aller-retour, correspondance de `resourceRef` et passerelle patrimoniale à 64 caractères hexadécimaux |
| Chapitre 3 | [03-cryptography-and-subkeys.md](./03-cryptography-and-subkeys.md) | Modèle de confiance auto-souverain Ed25519 `Holder-of-Key`, entropie de la graine maîtresse, dérivation de sous-clés dédiées par finalité via HKDF-SHA256 (y compris `ifay.ego.package-signing.v1`) et signature canonique JCS RFC 8785 |
| Chapitre 4 | [04-entities-ownership-and-hierarchy.md](./04-entities-ownership-and-hierarchy.md) | Quatre classes d'entités, liaison `HumanID : iFayID = 1:N`, propriété de `coFay` à couche unique et délégation orthogonale `managers`, `Steward` personne physique et hiérarchie d'organisations acyclique à parent unique par consentement mutuel |
| Chapitre 5 | [05-dynamic-codes-and-auth-exchange.md](./05-dynamic-codes-and-auth-exchange.md) | Émission et vérification anti-rejeu de Dynamic Codes non corrélables (`dyn_`), liaison HMAC de sujets patrimoniaux, Authorization Grants à portée restreinte (`grt_`), reçus de vérification (`vrf_`) et révocation en cascade |
| Chapitre 6 | [06-privacy-gmc-and-conformance.md](./06-privacy-gmc-and-conformance.md) | Frontières de confidentialité des charges utiles sortantes et d'occultation des journaux, frontière `GMChain` en lecture seule et ancre aveugle de personne physique (`gmcref_`), registre normatif des 24 codes d'erreur et critères de conformité |

## Artefacts normatifs associés

| Chemin de l'artefact | Description |
| --- | --- |
| [schemas/fayid-1.0.json](../../../../schemas/fayid-1.0.json) | Schéma JSON FayID 1.0 figé (Draft 2020-12, imposant `version: "1.0"`) |
| [schema/2025-10-25/schema.json](../../../../schema/2025-10-25/schema.json) | Miroir d'édition synchronisé octet par octet de `schemas/fayid-1.0.json` |
| [schema/2025-10-25/schema.ts](../../../../schema/2025-10-25/schema.ts) | Miroir normatif des constantes et interfaces TypeScript |
| [src/fayid-toolkit.mjs](../../../../src/fayid-toolkit.mjs) | Implémentation de référence Node.js `node:crypto` sans dépendance externe |
| [vectors/](../../../../vectors/) | Vecteurs déterministes de conformité inter-implémentations (`account-hierarchy-vectors.json` et `crypto-and-revocation-vectors.json`) |
