---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: fr
canonical: false
chapter: 4
---

# Chapitre 4 : Entités d'identité, propriété à couche unique et hiérarchie organisationnelle

## 4.1 Liaison un-à-plusieurs de `HumanID` vers `iFay` (Normatif)

1. **Dérivation de l'identité racine** : Un `Human Prime` génère ou dérive une clé publique Ed25519 `pk_human` au sein d'un `Holder Agent` local et calcule `hid_ || base32NoPad(SHA-256(pk_human))` comme son `HumanID`.
2. **Liaison `1:N` non transférable** : Un même `HumanID` `PEUT` inscrire et détenir un nombre arbitraire d'instances `iFay` (`HumanID : iFayID = 1:N`). L'inscription d'un `iFay` `DOIT` inclure des signatures Ed25519 conjointes émises à la fois par la clé privée du `HumanID` propriétaire et par la clé privée du nouvel `iFay` sur la charge utile canonique de liaison ; toute preuve absente ou invalide `DOIT` échouer avec `HUMAN_ID_OWNERSHIP_NOT_PROVEN`.
3. **Non-corrélabilité inter-`iFay` par défaut** : Les objets publics `IFayRecord` stockent uniquement l'engagement unidirectionnel salé `humanIdProofRef` (`hidproof_<base32>`) et `NE DOIVENT PAS` exposer `hid_` en clair. Sans preuve conjointe présentée volontairement par le `Human Prime`, les observateurs externes ne peuvent pas déterminer si deux enregistrements publics `ifay_` appartiennent au même `Human Prime`.
4. **Non-transférabilité permanente** : Une fois lié à un `HumanID`, un `iFay` `NE DOIT PAS` être transféré vers un autre `HumanID` ni vers un quelconque `OrganizationID`.

## 4.2 Propriété de `coFay` à couche unique et délégation orthogonale `managers` (Normatif)

Afin de garantir une responsabilité directe et opposable pour chaque entité à rôle partagé, FayID 1.0 impose une **propriété à couche unique** pour `coFay` :

1. **Types de propriétaires autorisés** : `coFay.ownerId` `DOIT` être soit un `HumanID` (`hid_`), soit un `OrganizationID` (`org_`), avec `ownerKind` fixé à `"HUMAN"` ou `"ORGANIZATION"`. Toute tentative visant à inscrire ou transférer un `coFay` sous un `iFay` (`ifay_`) ou sous un autre `coFay` (`cofay_`) `DOIT` échouer immédiatement avec `OWNER_TYPE_NOT_ALLOWED` (les chaînes de propriété imbriquées de `coFay` sont interdites).
2. **Transfert de propriété** : Le propriétaire direct courant (`hid_` ou `org_`) `PEUT` transférer un `coFay` à un nouveau propriétaire valide (`hid_` ou `org_`) au moyen d'une preuve de transfert signée, tout en conservant `version: "1.0"` et en mettant à jour la liaison de propriété.
3. **Gestionnaires opérationnels orthogonaux (`managers: iFayID[]`)** :
   - Le propriétaire direct (`hid_` ou `org_`) d'un `coFay` `PEUT` autoriser zéro ou plusieurs identifiants `iFayID` dans `managers` afin d'assurer l'administration opérationnelle courante.
   - Seul le propriétaire direct est habilité à ajouter ou retirer des entrées dans `managers` ; un `iFay` inscrit dans `managers` `NE DOIT PAS` ajouter, retirer ni sous-déléguer d'autres gestionnaires. Toute tentative de délégation non autorisée `DOIT` échouer avec `AUTHORITY_GRANT_UNAUTHORIZED` (délégation à un seul saut sans sous-délégation).
   - L'appartenance opérationnelle à `managers` ne modifie jamais la propriété juridique ou de gouvernance du `coFay`.

## 4.3 `OrganizationID` et `Steward` personne physique (Normatif)

1. **`Steward` personne physique obligatoire** : Chaque `OrganizationRecord` inscrit `DOIT` désigner un représentant de gouvernance personne physique `stewardHumanId` référençant un `HumanID` (`hid_`) inscrit et non révoqué. Toute tentative visant à attribuer le rôle de `Steward` à un `ifay_`, un `cofay_` ou un `org_` `DOIT` échouer avec `STEWARD_TYPE_NOT_ALLOWED`.
2. **Rotation du `Steward`** : Une organisation `PEUT` effectuer la rotation de `stewardHumanId` au moyen d'une commande signée par la paire de clés de contrôle de l'organisation, à condition que le remplaçant soit également un `HumanID` valide et non révoqué.

## 4.4 Hiérarchie organisationnelle autonome acyclique à parent unique (Normatif)

FayID 1.0 définit la hiérarchie inter-organisationnelle directement au sein de la présente spécification :

1. **Topologie arborescente à parent unique** : Chaque `OrganizationRecord` porte `parentOrgId: OrganizationID | null`. Chaque organisation fille possède au plus une organisation parente directe à tout instant, formant une forêt d'arbres orientés acycliques. Le protocole n'impose **aucune limite fixe artificielle de profondeur** (telle que 16 niveaux).
2. **Consentement mutuel bipartite** : Le rattachement ou le changement de parent `childOrg.parentOrgId = parentOrgId` `DOIT` comporter des signatures Ed25519 de consentement valides émises à la fois par la clé de contrôle de l'organisation fille et par la clé de contrôle de l'organisation parente cible. Tout consentement absent ou invalide de l'une ou l'autre des parties `DOIT` échouer avec `HIERARCHY_CONSENT_MISSING`.
3. **Rejet déterministe des cycles** : Tout rattachement définissant `parentOrgId` sur l'organisation elle-même ou sur l'un quelconque de ses descendants actuels `DOIT` échouer de manière déterministe avec `HIERARCHY_CYCLE_CONFLICT`.
4. **Absence de remontée implicite de la propriété des `coFay`** : Un `coFay` détenu par une organisation fille conserve cet identifiant `org_` enfant comme son `ownerId` direct ; le rattachement d'une organisation à un arbre parent ne transfère ni ne remonte implicitement la propriété directe des enregistrements `coFay` de l'organisation fille.
