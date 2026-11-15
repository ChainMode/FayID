---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: fr
canonical: false
chapter: 6
---

# Chapitre 6 : Frontières de confidentialité, interface `GMChain`, codes d'erreur et conformité

## 6.1 Frontières des charges utiles sortantes et d'occultation des journaux (Normatif)

Toute implémentation conforme `DOIT` appliquer les règles de confidentialité incontournables suivantes aussi bien lors de la sérialisation filaire que dans la journalisation d'observabilité :

1. **`hid_` en clair ne quitte jamais la frontière locale et n'entre jamais dans les journaux** : Les charges utiles réseau, les instantanés d'annuaires publics, les paquets d'exportation `.ego`, les reçus de vérification inter-parties (`vrf_`), les vidages sur incident (crash dumps) et les journaux d'audit `NE DOIVENT PAS` contenir de chaînes `hid_<base32>` en clair. Les interactions externes `DOIVENT` utiliser `ifay_`, `cofay_`, `dyn_`, `hidproof_` ou des ancres aveugles `gmcref_`.
2. **Absence totale de graine ou de matériel de clé privée sortant** : Les graines maîtresses (`masterSeed`), les phrases mnémoniques, les clés privées brutes (`privateKey` / `secretKey`) et les valeurs `userBlindSalt` `DOIVENT` demeurer confinées dans le stockage sécurisé local du `Holder Agent` et `NE DOIVENT PAS` figurer dans des enregistrements publics sérialisés ni dans des charges utiles sortantes.
3. **Non-corrélabilité inter-espaces de noms** : Les domaines de consommation externes distincts `DOIVENT` appliquer des chaînes de séparation de domaine ou des sels distincts afin que des observateurs externes ne puissent pas corréler des identifiants entre espaces de noms pour profiler un `Human Prime`.

## 6.2 Frontière `GMChain` en lecture seule et ancre aveugle `gmcref_` (Normatif)

`GMChain` normalise le poids de gouvernance par personne physique ainsi que la résistance aux attaques Sybil de sorte qu'une même personne physique compte comme une unique ancre de personne physique, quel que soit le nombre de personas `iFay` qu'elle exploite, sans jamais connaître `hid_` en clair. FayID 1.0 dérive l'ancre aveugle déterministe `gmcref_<base32>` comme suit :

```text
prk    = HKDF-SHA256(ikm = userBlindSalt, salt = SHA-256("fayid.gmc.salt.v1"), info = "ifay.gmc.natural-person.v1:" || namespace, len = 32)
digest = HMAC-SHA256(key = prk, data = UTF8("gmcref:" || canonicalHumanId))
gmcref = "gmcref_" || base32EncodeNoPad(digest)
```

Invariants normatifs :

1. **Déterminisme et irréversibilité** : Pour un même `HumanID` canonique, un même `userBlindSalt` (`>= 32` octets) et un même `namespace` (`"gmchain.main"` par défaut), `deriveBlindGmcRef` produit une chaîne `gmcref_` identique. Sans `userBlindSalt`, les parties externes (y compris les nœuds `GMChain`) ne peuvent ni inverser `gmcref_` pour retrouver `hid_`, ni le corréler aux enregistrements publics `ifay_` détenus par ce `Human Prime`.
2. **Frontière stricte en lecture seule vis-à-vis du registre** : FayID fournit uniquement la dérivation unidirectionnelle d'ancre et les entrées de statut de révocation à `GMChain` ; FayID ne modifie pas l'état du registre `GMChain` et ne calcule, n'émet ni ne distribue de `MeriToken`. `MeriToken` est un indicateur non monétaire de contribution sociale ; ce n'est ni une cryptomonnaie, ni un actif échangeable contre une monnaie fiduciaire, ni un rail de règlement financier, ni un actif spéculatif.
3. **Portée restreinte aux seules personnes physiques** : `deriveBlindGmcRef` accepte uniquement un `HumanID` (`hid_`) valide ; lui transmettre un identifiant `ifay_`, `cofay_` ou `org_` `DOIT` échouer avec `MALFORMED_FAYID_STRING`.

## 6.3 Registre normatif des codes d'erreur (Normatif)

Les implémentations conformes à FayID 1.0 `DOIVENT` préserver les 24 constantes stables de codes d'erreur suivantes (14 codes de base du protocole ainsi que 10 codes relatifs aux comptes, à la séparation de domaine et à la gouvernance en cascade) :

| Constante de code d'erreur | Condition de déclenchement |
| --- | --- |
| `INSUFFICIENT_ENTROPY` | La graine maîtresse, le sel aveugle ou l'entropie aléatoire est inférieure à 256 bits (32 octets) |
| `HUMAN_ID_OWNERSHIP_NOT_PROVEN` | La signature `Holder-of-Key` requise du `HumanID` est absente ou échoue à la vérification |
| `OWNERSHIP_NOT_PROVEN` | Le contrôle de l'entité ou le transfert de propriété ne comporte pas de signature valide du propriétaire actuel |
| `TARGET_OWNERSHIP_NOT_PROVEN` | L'émission de `grt_` ne comporte pas de preuve `Holder-of-Key` valide pour `targetFayId` (renvoyé en priorité maximale afin d'empêcher le sondage de liaisons) |
| `LEGACY_SUBJECT_MISMATCH` | Le HMAC du sujet canonisé du justificatif patrimonial ne correspond pas au `LegacySubjectRef` lié |
| `DYNAMIC_CODE_EXPIRED` | L'horodatage de vérification de `dyn_` dépasse `expiresAt` |
| `DYNAMIC_CODE_INVALID` | La syntaxe ou le HMAC de `dyn_` est invalide, `audience` ne correspond pas ou le TTL demandé dépasse 600 secondes |
| `VERIFICATION_RATE_LIMITED` | Les échecs consécutifs de vérification atteignent le seuil de limitation de débit (5 échecs en 600 s déclenchent un recul exponentiel) |
| `IDENTITY_REVOKED` | Indicateur de base du statut de révocation d'identité |
| `LEGACY_AUTH_FAILED` | L'authentification en amont du justificatif patrimonial (mot de passe, certificat, jeton, contrat intelligent) a échoué |
| `GRANT_EXPIRED` | L'horodatage de vérification de `grt_` dépasse `expiresAt` |
| `GRANT_REVOKED` | L'autorisation individuelle `grt_` a été explicitement révoquée |
| `GRANT_INVALID` | L'autorisation `grt_` est inconnue, mal formée, cible un type d'entité invalide ou `requestedResourceRef` sort de la portée accordée |
| `MALFORMED_FAYID_STRING` | Le préfixe ou le corps Base32 de l'identifiant est invalide, la syntaxe de `resourceRef` échoue à la validation ou un type de préfixe inattendu a été fourni |
| `OWNER_TYPE_NOT_ALLOWED` | Tentative d'attribution d'un `iFay` ou d'un `coFay` comme propriétaire d'un `coFay` (en violation de la propriété à couche unique) |
| `HIERARCHY_CONSENT_MISSING` | Le rattachement d'organisation ne comporte pas de signature valide de l'organisation fille ou de l'organisation parente |
| `HIERARCHY_CYCLE_CONFLICT` | Le rattachement d'organisation pointe vers l'organisation elle-même ou vers un descendant existant, créant un cycle |
| `AUTHORITY_GRANT_UNAUTHORIZED` | Un non-propriétaire (tel qu'une entrée de `coFay.managers`) a tenté de modifier ou de sous-déléguer `managers` |
| `STEWARD_TYPE_NOT_ALLOWED` | Le `Steward` de l'organisation n'est pas un `HumanID` (`hid_`) valide et non révoqué d'une personne physique |
| `ENTITY_REVOKED` | L'entité cible ou son `HumanID` / `OrganizationID` propriétaire en amont a été révoqué directement ou en cascade |
| `DYNAMIC_CODE_REPLAYED` | Un jeton `dyn_` à usage unique a été présenté plus d'une fois |
| `DYNAMIC_CODE_TARGET_NOT_ALLOWED` | Tentative d'émission d'un jeton `dyn_` pour un type de cible interdit tel que `OrganizationID` |
| `DOMAIN_SEPARATION_REQUIRED` | La dérivation de sous-clé HKDF a omis un `SubkeyDomain` valide ou une chaîne de contexte non vide |
| `RECEIPT_INVALID` | Le reçu de vérification `vrf_` est mal formé ou échoue à la vérification de signature Ed25519 |

## 6.4 Critères de conformité (Normatif)

Une implémentation, bibliothèque ou instance de `Holder Agent` revendiquant la conformité à **FayID 1.0** `DOIT` satisfaire aux cinq conditions vérifiables ci-dessous :

1. **Conformité de version et de schéma** : Chaque enregistrement public d'entité et chaque enveloppe de justificatif émis portent `version: "1.0"` et sont valides au regard de [schemas/fayid-1.0.json](../../../../schemas/fayid-1.0.json).
2. **Conformité des identifiants et de la correspondance de ressources** : Implémente la normalisation des huit préfixes du chapitre 2, le rejet strict sans réparation silencieuse des entrées et la correspondance `EXACT` / `PREFIX` sûre par segment sur `resourceRef`.
3. **Conformité cryptographique et d'isolation des clés racines** : Implémente Ed25519, SHA-256, les cinq domaines de sous-clés dédiées par finalité HKDF-SHA256 et la signature canonique JCS RFC 8785 du chapitre 3, en réservant exclusivement `ifay.ego.package-signing.v1` aux signatures de paquets `.ego`, sans aucune fuite de graine ni de clé privée.
4. **Conformité de la hiérarchie de comptes et de la révocation en cascade** : Applique la propriété de `coFay` à couche unique, le `Steward` personne physique et les arbres d'organisations acycliques à parent unique par consentement mutuel du chapitre 4, ainsi que la vérification anti-rejeu de `dyn_`, l'échange à portée restreinte `grt_` / `vrf_` et la révocation déterministe en cascade sur les quatre classes d'entités du chapitre 5.
5. **Taux de réussite de 100 % sur les vecteurs de conformité** : Réussit l'intégralité des scénarios de test positifs et négatifs de [vectors/account-hierarchy-vectors.json](../../../../vectors/account-hierarchy-vectors.json) et [vectors/crypto-and-revocation-vectors.json](../../../../vectors/crypto-and-revocation-vectors.json).
