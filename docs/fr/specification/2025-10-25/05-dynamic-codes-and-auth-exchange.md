---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: fr
canonical: false
chapter: 5
---

# Chapitre 5 : Dynamic Codes non corrélables, Auth Exchange et révocation en cascade

## 5.1 Émission et vérification des Dynamic Codes (`dyn_`) non corrélables (Normatif)

Étant donné que `hid_` en clair ne franchit jamais la frontière de confiance locale, un `Human Prime` ainsi que ses entités `iFay` ou `coFay` présentent des Dynamic Codes éphémères salés par nonce (`dyn_<base32>`) à travers les frontières de confiance :

1. **Entités cibles autorisées** : Les Dynamic Codes `PEUVENT` être émis uniquement pour des sujets `HumanID` (`hid_`), `iFayID` (`ifay_`) ou `coFayID` (`cofay_`) non révoqués. Toute demande de Dynamic Code pour un `OrganizationID` (`org_`) `DOIT` échouer avec `DYNAMIC_CODE_TARGET_NOT_ALLOWED` (les identifiants d'organisation étant publics par conception).
2. **Construction non corrélable salée par nonce** : Chaque émission génère au moins 16 octets de `nonce` aléatoire cryptographique, calcule un HMAC-SHA256 sous la clé de domaine `ifay.fayid.dynamic-code.v1` sur la charge utile JCS canonique `{audience, expiresAt, issuedAt, nonceHex, targetId, version: "1.0"}` et encode les 20 premiers octets sous la forme `dyn_<base32>`. Les observateurs passifs dépourvus du contexte de clé de vérification ne peuvent pas corréler deux jetons `dyn_` présentés par un même sujet.
3. **Plafond strict de durée de vie (TTL)** : `expiresAt - issuedAt` `DOIT` être strictement positif et `NE DOIT PAS` dépasser **`600` secondes (`DYNAMIC_CODE_MAX_TTL_SECONDS = 600`)** ; toute demande de TTL hors plage `DOIT` échouer avec `DYNAMIC_CODE_INVALID`.
4. **Vérification anti-rejeu à usage unique** : Lors de la vérification d'un jeton `dyn_` :
   - Si le sujet sous-jacent ou son propriétaire en amont a été révoqué, la vérification `DOIT` échouer avec `ENTITY_REVOKED` ;
   - Si la vérification intervient après `expiresAt`, la vérification `DOIT` échouer avec `DYNAMIC_CODE_EXPIRED` ;
   - Si `audience` ne correspond pas (lorsque le jeton est lié à une audience cible) ou si le jeton est inconnu, la vérification `DOIT` échouer avec `DYNAMIC_CODE_INVALID` ;
   - Chaque nonce `dyn_` `DOIT` réussir au plus **une seule fois** ; toute deuxième présentation ou présentation ultérieure du même jeton `dyn_` `DOIT` échouer avec `DYNAMIC_CODE_REPLAYED`.
5. **Résolution préservant la vie privée pour `HumanID`** : Lorsque le sujet sous-jacent d'un jeton `dyn_` vérifié est un `HumanID`, la réponse de vérification `NE DOIT PAS` divulguer `hid_` en clair ; elle `DOIT` renvoyer à la place le type de sujet `"HUMAN"` accompagné de l'ancre aveugle déterministe `gmcref_<base32>`.

## 5.2 Liaison de justificatifs patrimoniaux et Auth Exchange (`grt_` / `vrf_`) (Normatif)

Auth Exchange assure la passerelle entre des justificatifs patrimoniaux externes et des Authorization Grants FayID à portée restreinte (`grt_<base32>`), et produit des reçus de vérification vérifiables hors ligne (`vrf_<base32>`) :

1. **`LegacySubjectRef` haché par HMAC** : Les identifiants de sujets externes `DOIVENT` être canonisés et hachés via un HMAC à clé sous la forme `<legacySourceKind>:<issuerOrAuthority>:<subjectHash>`, où `subjectHash = base32NoPad(HMAC-SHA256(legacySecret, canonicalSubject))`. `LegacySubjectRef` `NE DOIT PAS` incorporer en clair d'adresses électroniques, de numéros de téléphone, de noms distinctifs (Distinguished Names) X.509, de jetons OAuth bruts ni d'adresses de portefeuille de chaîne de blocs en clair.
2. **Correspondance par défaut de `LegacyTrustLevel`** :
   - `PASSWORD` -> `LOW` (plafond de TTL de l'autorisation : **`900` secondes**, `LOW_TRUST_GRANT_MAX_TTL_SECONDS`) ;
   - `ACCESS_TOKEN`, `AUTHORIZATION` -> `MEDIUM` (plafond de TTL de l'autorisation : **`3600` secondes**, `GRANT_MAX_TTL_SECONDS`) ;
   - `CERTIFICATE`, `SMART_CONTRACT` -> `HIGH` (plafond de TTL de l'autorisation : **`3600` secondes**).
   Les implémentations `PEUVENT` abaisser les niveaux de confiance ou raccourcir les TTL selon leur politique locale de risque, et `NE DOIVENT PAS` élever les niveaux de confiance sans preuve additionnelle multi-facteur du détenteur.
3. **Priorité de la preuve de propriété de la cible (anti-sondage)** : Les autorisations `grt_` `PEUVENT` cibler uniquement des entités `iFayID` ou `coFayID` non révoquées, et l'émission `DOIT` vérifier une signature `Holder-of-Key` prouvant le contrôle sur `targetFayId`. Si la preuve de propriété de la cible est absente ou invalide, l'émission `DOIT` renvoyer `TARGET_OWNERSHIP_NOT_PROVEN` avant d'évaluer les liaisons de sujets patrimoniaux, empêchant ainsi un attaquant de sonder si un compte patrimonial est lié à un FayID donné.
4. **Vérification des autorisations à portée restreinte et reçus `vrf_`** : `verifyAuthGrant` évalue, dans l'ordre :
   - L'existence et la validité syntaxique de l'autorisation (sinon `GRANT_INVALID`) ;
   - Le statut de révocation de `targetFayId` et de son propriétaire en amont (renvoyant `ENTITY_REVOKED` en cas de révocation) ;
   - Le statut de révocation explicite de l'autorisation (sinon `GRANT_REVOKED`) ;
   - L'expiration par rapport à `expiresAt` (sinon `GRANT_EXPIRED`) ;
   - La correspondance de portée entre `requestedResourceRef` et `resourceRef` selon le `scopeMode` de la section 2.3 (`EXACT` ou `PREFIX`, renvoyant `GRANT_INVALID` en cas de non-correspondance).
   En cas de succès, le vérificateur signe la charge utile canonique du reçu avec la clé Ed25519 `ifay.fayid.auth-exchange.v1` et renvoie un reçu `vrf_<base32>`. Toute partie utilisatrice peut appeler `verifyAuthReceipt(receipt)` afin de valider hors ligne la signature Ed25519 et la structure ; tout champ altéré `DOIT` échouer avec `RECEIPT_INVALID`.

## 5.3 Révocation déterministe en cascade (Normatif)

La révocation est monotone et irréversible. La révocation de toute entité `DOIT` se propager de manière synchrone en cascade vers l'ensemble des entités en aval et des justificatifs actifs sans laisser d'enregistrements actifs orphelins :

| Entité déclencheuse révoquée | Entités en aval révoquées en cascade | Nettoyage collatéral obligatoire sur les gestionnaires et justificatifs |
| --- | --- | --- |
| **`HumanID` (`hid_`)** | Chaque `iFay` (`ifay_`) lié à ce `hid_`, ainsi que chaque `coFay` (`cofay_`) directement détenu par ce `hid_` | Retirer tous les identifiants `ifay_` révoqués en cascade de chaque liste `coFay.managers` survivante ; révoquer toutes les autorisations `grt_` actives et tous les jetons `dyn_` non consommés ciblant tout `ifay_` ou `cofay_` révoqué en cascade |
| **`OrganizationID` (`org_`)** | L'organisation elle-même, l'intégralité de son sous-arbre d'organisations descendantes (récursivement), ainsi que chaque `coFay` directement détenu par l'organisation ou par toute organisation descendante | Révoquer toutes les autorisations `grt_` actives et tous les jetons `dyn_` non consommés ciblant tout `cofay_` révoqué en cascade |
| **`iFayID` (`ifay_`)** | Cette instance d'`iFay` | Retirer immédiatement cet `ifay_` de chaque liste `coFay.managers` survivante ; révoquer toutes les autorisations `grt_` actives et tous les jetons `dyn_` non consommés ciblant cet `ifay_` |
| **`coFayID` (`cofay_`)** | Cette instance de `coFay` | Révoquer toutes les autorisations `grt_` actives et tous les jetons `dyn_` non consommés ciblant ce `cofay_` |

Une fois la révocation achevée :
1. L'émission de nouveaux jetons `dyn_`, l'émission de nouvelles autorisations `grt_`, l'inscription d'entités subordonnées ou la vérification de justificatifs existants auprès de toute entité révoquée directement ou en cascade `DOIVENT` échouer de manière déterministe avec `ENTITY_REVOKED` (tandis que la révocation individuelle d'une autorisation isolée dont l'entité cible demeure active renvoie `GRANT_REVOKED`).
2. Les justificatifs liés à une entité révoquée deviennent invalides **immédiatement**, même lorsque leur horodatage d'expiration initial `expiresAt` n'est pas encore écoulé.
