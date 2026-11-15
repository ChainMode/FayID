---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: fr
canonical: false
chapter: 2
---

# Chapitre 2 : Syntaxe des identifiants, encodage Base32 et références de ressources

## 2.1 Préfixes d'identifiants canoniques (Normatif)

Chaque identifiant cryptographique FayID et chaque chaîne de justificatif dérivé `DOIVENT` respecter la syntaxe `<prefix>_<body>`. À l'exception de `org_`, qui autorise les caractères de slug en minuscules `[a-z0-9-]+`, le corps de chaque identifiant `DOIT` utiliser l'encodage **Base32 RFC 4648 en minuscules sans bourrage** (`[a-z2-7]+`) :

| Constante de type | Préfixe | Motif du corps | Taille typique de charge utile et sémantique de responsabilité |
| --- | --- | --- | --- |
| `HUMAN_ID` | `hid_` | `^[a-z2-7]+$` | `SHA-256(humanPublicKey)` (32 octets -> 52 caractères Base32) ; identité racine d'un `Human Prime` |
| `IFAY_ID` | `ifay_` | `^[a-z2-7]+$` | `SHA-256("ifay:" \|\| humanId \|\| ":" \|\| publicKey)` (32 octets) ; persona numérique individuel |
| `COFAY_ID` | `cofay_` | `^[a-z2-7]+$` | `SHA-256("cofay:" \|\| ownerId \|\| ":" \|\| publicKey)` (32 octets) ; entité numérique à rôle partagé |
| `ORGANIZATION_ID` | `org_` | `^[a-z0-9-]+$` | Identifiant d'organisation responsable (corps de condensat déterministe ou slug normalisé en minuscules) |
| `DYNAMIC_CODE` | `dyn_` | `^[a-z2-7]+$` | Étiquette HMAC tronquée à 20 octets (32 caractères Base32) ; jeton de présentation éphémère non corrélable |
| `VERIFICATION_CODE` | `vrf_` | `^[a-z2-7]+$` | Condensat de reçu de vérification sur 20 octets lié à un contrôle `grt_` ou `cofay_` vérifié |
| `AUTHORIZATION_GRANT` | `grt_` | `^[a-z2-7]+$` | Identifiant d'autorisation à portée restreinte sur 20 octets issu de l'échange d'un justificatif patrimonial |
| `OPAQUE_REF` | `gmcref_` | `^[a-z2-7]+$` | Ancre aveugle de personne physique sur 32 octets (52 caractères Base32) pour le dédoublonnage sur `GMChain` |

En outre, les enregistrements publics d'inscription d'`iFay` et les lots hors ligne représentent l'engagement unidirectionnel salé vers leur `HumanID` propriétaire sous la forme `hidproof_<lowercase-base32-nopad>` (`^hidproof_[a-z2-7]{16,}$`), de sorte que `hid_` en clair n'apparaisse jamais dans les enregistrements publics.

## 2.2 Règles de normalisation et de rejet strict (Normatif)

`normalizeFayID(input)` `DOIT` appliquer les règles déterministes suivantes :

1. **Vérification du type et de la non-vacuité** : Les entrées qui ne sont pas des chaînes de caractères ainsi que les chaînes vides `DOIVENT` échouer immédiatement avec `MALFORMED_FAYID_STRING`.
2. **Conversion de casse ASCII** : L'analyseur `DOIT` convertir les lettres majuscules ASCII en minuscules (`input.toLowerCase()`) avant de rechercher une correspondance parmi les huit préfixes canoniques.
3. **Rejet strict sans réparation silencieuse** : Un analyseur `NE DOIT PAS` supprimer les espaces de début ou de fin, retirer les traits d'union (en dehors des corps `org_` valides), retirer les caractères de bourrage `=` ni substituer des chiffres visuellement proches (tels que la conversion de `0`, `1`, `8` ou `9` en lettres Base32). Toute entrée contenant des caractères d'espacement, un bourrage `=`, un préfixe inconnu, un corps vide ou des caractères hors alphabet `DOIT` échouer avec `MALFORMED_FAYID_STRING`.
4. **Invariants d'aller-retour** : Pour tout identifiant canonique valide `x`, un nouvel appel à `normalizeFayID(x)` `DOIT` renvoyer `ok: true` avec `value.canonical === x`. L'encodage de tout tableau d'octets `b` en Base32 minuscules sans bourrage suivi de son décodage `DOIT` restituer `b` octet par octet, et tout bit résiduel de fin non nul lors du décodage Base32 `DOIT` être rejeté.

## 2.3 Syntaxe de `resourceRef` et correspondance de portée (Normatif)

Dans Auth Exchange, les ressources cibles sont désignées par `resourceRef`. `normalizeResourceRef(input)` et `matchesResourceRef(grantedResourceRef, requestedResourceRef, scopeMode)` `DOIVENT` appliquer les règles suivantes :

1. **Grammaire** : `resourceRef` suit la forme `<namespace>:<path>` :
   - `<namespace>`, après conversion en minuscules, `DOIT` correspondre à `^[a-z][a-z0-9+.-]*$` ;
   - `<path>`, à droite de `:`, `DOIT` être non vide, ne contenir aucun caractère d'espacement, ne pas se terminer par `/` (sauf si le chemin est `/` seul) et `NE DOIT PAS` contenir de segments vides (`//`) ni de segments de traversée par points (`.` ou `..`).
   - Toute violation `DOIT` renvoyer `MALFORMED_FAYID_STRING`.
2. **Sensibilité à la casse** : `<namespace>` est normalisé en minuscules, tandis que `<path>` `DOIT` conserver sa casse exacte.
3. **Correspondance de portée (`scopeMode`)** :
   - `EXACT` (par défaut) : Correspond si et seulement si, après normalisation, `requestedResourceRef === grantedResourceRef`.
   - `PREFIX` : Correspond si et seulement si, après normalisation, `requestedResourceRef` est égal à `grantedResourceRef` ou commence par `grantedResourceRef + "/"` sur une frontière explicite de segment `/`. Par exemple, une autorisation `PREFIX` accordée sur `cap:repo/fayid` correspond à `cap:repo/fayid/issues` et `NE DOIT PAS` correspondre au chemin voisin `cap:repo/fayid-ext`.

## 2.4 Passerelle pour les clés publiques patrimoniales à 64 caractères hexadécimaux (Normatif)

Afin de migrer les premiers enregistrements stockant des clés publiques Ed25519 brutes de 32 octets sous forme de 64 caractères hexadécimaux, les implémentations fournissent `adaptLegacyHexIdentifier(hex64, prefix)` :

1. Après suppression des espaces externes, `hex64` `DOIT` correspondre à `^[0-9a-fA-F]{64}$`, et `prefix` `DOIT` être l'une des valeurs `hid_`, `ifay_` ou `cofay_` ; dans le cas contraire, l'appel `DOIT` échouer avec `MALFORMED_FAYID_STRING`.
2. L'adaptateur calcule `SHA-256` sur la clé publique décodée de 32 octets et encode le condensat sous la forme `<prefix><base32-nopad>`, conformément à la dérivation native des identifiants racines.
3. Les charges utiles filaires conformes à FayID 1.0 `NE DOIVENT PAS` transmettre de chaînes brutes de 64 caractères hexadécimaux en lieu et place d'identifiants FayID canoniques ; la conversion `DOIT` s'effectuer explicitement à la frontière d'ingestion.
