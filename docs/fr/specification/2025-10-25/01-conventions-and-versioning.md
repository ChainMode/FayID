---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: fr
canonical: false
chapter: 1
---

# Chapitre 1 : Conventions normatives, terminologie fondamentale et gouvernance des versions

## 1.1 Périmètre et hors-périmètre

FayID 1.0 définit les identifiants d'identité auto-souveraine, la dérivation de sous-clés liées à une finalité, les invariants de propriété des entités et de hiérarchie organisationnelle, les codes dynamiques non corrélables, l'échange d'autorisation à partir de justificatifs patrimoniaux, la révocation en cascade et les ancres de personne physique préservant la vie privée pour `GMChain` à travers l'écosystème iFay.

Les préoccupations suivantes sont explicitement exclues du périmètre de FayID 1.0 :

1. **Encapsulation de transport et négociations de session** : Le cadrage des messages inter-agents et la sécurité du transport relèvent de la suite protocolaire Faying ; FayID fournit les primitives d'identité, les enveloppes de signature et les reçus de vérification.
2. **Ordonnancement des processus d'exécution** : L'orchestration des processus des instances `iFay` et `coFay` sur les terminaux est régie par l'environnement d'exécution FayGer.
3. **Comptabilisation de la réputation et calcul du poids de gouvernance** : L'accumulation et la pondération de gouvernance du `MeriToken` sont définies de manière indépendante par `GMChain`. FayID maintient une frontière en lecture seule vis-à-vis de `GMChain` et produit uniquement l'ancre aveugle `gmcref_`.
4. **Vérification centralisée d'identité civile (KYC)** : FayID 1.0 ne suppose aucun registre centralisé ni aucune autorité de certification racine.

## 1.2 Mots-clés normatifs (Normatif)

Les mots-clés normatifs français `DOIT` / `DOIVENT`, `REQUIS`, `NE DOIT PAS` / `NE DOIVENT PAS`, `DEVRAIT` / `DEVRAIENT`, `RECOMMANDÉ`, `NE DEVRAIT PAS` / `NE DEVRAIENT PAS`, `DÉCONSEILLÉ`, `PEUT` / `PEUVENT` et `OPTIONNEL` (ainsi que leurs équivalents anglais `MUST`, `MUST NOT`, `REQUIRED`, `SHALL`, `SHALL NOT`, `SHOULD`, `SHOULD NOT`, `RECOMMENDED`, `NOT RECOMMENDED`, `MAY` et `OPTIONAL`) dans le présent document doivent être interprétés conformément aux [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) et [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) lorsqu'ils apparaissent, et uniquement lorsqu'ils apparaissent, entièrement en majuscules, comme résumé ci-dessous :

| Mot-clé normatif français | Mot-clé RFC 2119 / RFC 8174 | Signification normative |
| --- | --- | --- |
| `DOIT` / `DOIVENT` / `REQUIS` | `MUST` / `SHALL` / `REQUIRED` | Exigence absolue du protocole ; toute violation rend l'implémentation non conforme |
| `NE DOIT PAS` / `NE DOIVENT PAS` | `MUST NOT` / `SHALL NOT` | Interdiction absolue du protocole ; toute violation rend l'implémentation non conforme |
| `DEVRAIT` / `DEVRAIENT` / `RECOMMANDÉ` | `SHOULD` / `RECOMMENDED` | Exigence par défaut forte qu'il convient de respecter sauf justification d'ingénierie documentée |
| `NE DEVRAIT PAS` / `NE DEVRAIENT PAS` / `DÉCONSEILLÉ` | `SHOULD NOT` / `NOT RECOMMENDED` | Comportement qu'il convient d'éviter sauf justification d'ingénierie documentée |
| `PEUT` / `PEUVENT` / `OPTIONNEL` | `MAY` / `OPTIONAL` | Fonctionnalité véritablement discrétionnaire ; les pairs interopérables doivent prendre en charge aussi bien sa présence que son omission |

## 1.3 Terminologie fondamentale (Normatif)

L'ensemble des implémentations, schémas et documents dérivés `DOIVENT` respecter strictement les frontières terminologiques suivantes :

- **`Human Prime`** : La personne physique réelle identifiée par un `HumanID` (`hid_`) qui possède et contrôle ses personas numériques individuels. Les spécifications, commentaires de code et champs d'API `DOIVENT` employer systématiquement `Human Prime` lorsqu'ils désignent la personne physique.
- **`Hôte` (`Host`)** : Désigne **exclusivement** un terminal, un environnement de système d'exploitation ou une application cliente sur lesquels une instance de `Fay` s'exécute ou est montée. Les implémentations et la documentation `NE DOIVENT PAS` employer `Hôte` ou `Host` pour désigner une personne physique ou un `Human Prime`.
- **`Fay` (`Fay = iFay + coFay`)** : Le terme collectif désignant l'ensemble des entités numériques responsables dotées d'une identité vérifiable dans l'écosystème iFay, réparties en deux sous-ensembles mutuellement exclusifs :
  - **`iFay` (`Individual Fay`, `ifay_`)** : Un persona numérique personnel lié de manière non transférable selon une relation `1:N` à un unique `HumanID` (`HumanID : iFayID = 1:N`).
  - **`coFay` (`Shared-Role Fay`, `cofay_`)** : Une entité numérique collaborative, de service ou à rôle partagé liée directement à un unique `HumanID` ou à un unique `OrganizationID`, prenant en charge le transfert de propriété ainsi qu'une délégation orthogonale de gestion opérationnelle.
- **`OrganizationID` (`org_`)** : Une entité juridique ou de gouvernance responsable d'actifs organisationnels, représentée par un `Steward` personne physique et apte à s'inscrire dans un arbre d'organisations acyclique à parent unique.
- **`Holder Agent`** : Un composant logiciel local de gestion de clés et d'auto-émission contrôlé par un `Human Prime` ou une organisation et s'exécutant sur un `Hôte` (`Host`) contrôlé (terminal ou application cliente), par opposition à une autorité distante centralisée.
- **`GMChain` et `MeriToken`** : `GMChain` est le registre public de réputation consignant les contributions sociales au sein de l'écosystème ; `MeriToken` (mesuré en `Merit Unit`) est un indicateur non monétaire de contribution sociale ; ce n'est ni une cryptomonnaie, ni un actif échangeable contre une monnaie fiduciaire, ni un jeton produit par minage, ni un rail de règlement financier, ni un actif spéculatif.

## 1.4 Gestion des versions et négociation du protocole (Normatif)

### 1.4.1 Trois axes orthogonaux

FayID sépare trois axes distincts qui `NE DOIVENT PAS` être confondus :

1. **Version filaire du protocole (`MAJOR.MINOR`)** : Utilise une chaîne à deux segments `MAJOR.MINOR` (`"1.0"` pour FayID 1.0) **sans segment `PATCH`**. Seule la valeur `"1.0"` `DOIT` apparaître dans les champs d'enveloppe `version` au format filaire et dans les contraintes `const` du schéma JSON.
2. **Statut du document** : Indique la maturité de la spécification (par exemple `Draft` ou `Final`). Le statut du document figure uniquement dans l'en-tête documentaire (front matter) de la spécification et `NE DOIT PAS` apparaître dans les charges utiles filaires.
3. **Date d'édition** : Utilise une date ISO `YYYY-MM-DD` (`2025-10-25` pour la présente édition) afin d'identifier les répertoires d'archives de spécification et les chemins d'instantanés de schéma, et `NE DOIT PAS` apparaître dans les charges utiles filaires.

### 1.4.2 Critères d'évolution majeure et mineure

- **Incrément mineur (`MINOR`)** : Limité aux extensions additives rétrocompatibles (telles que des champs d'enveloppe facultatifs, de nouvelles constantes de domaine de sous-clés dédiées par finalité ou des métadonnées facultatives de justificatifs). Les pairs implémentant une version mineure `1.x` antérieure demeurent capables de valider les signatures et les invariants fondamentaux tout en ignorant les champs facultatifs inconnus.
- **Incrément majeur (`MAJOR`)** : Tout changement cassant la compatibilité (modification des expressions régulières d'identifiants, remplacement des primitives cryptographiques de base de hachage ou de signature, altération des chaînes de domaine HKDF, durcissement de champs obligatoires existants ou modification des effets de la révocation en cascade) `DOIT` incrémenter `MAJOR`.
- **Révisions éditoriales** : Les mises à jour d'édition au sein d'une même version `MAJOR.MINOR` sont strictement réservées aux clarifications non normatives et `NE DOIVENT PAS` modifier les résultats de conformité.

### 1.4.3 Négociation de version et compatibilité ascendante

1. Les pairs échangeant des enregistrements, enveloppes ou reçus FayID `DOIVENT` valider le champ `version`. Les enregistrements conformes à FayID 1.0 `DOIVENT` fixer `version` exactement à `"1.0"` (`"1"`, `"1.0.0"` et `"v1.0"` sont invalides).
2. Les implémentations prenant en charge plusieurs versions mineures au sein de `MAJOR = 1` `DOIVENT` négocier la version `1.x` la plus élevée mutuellement prise en charge et maintenir la rétrocompatibilité jusqu'à `"1.0"`.
3. Face à une version `MAJOR` inconnue ou non prise en charge, un vérificateur `DOIT` rejeter immédiatement la charge utile et `NE DOIT PAS` tenter de repli silencieux ni contourner la vérification de signature.
4. Les vérificateurs analysant des charges utiles relevant de la même version `MAJOR` `DOIVENT` ignorer les champs d'extension facultatifs non reconnus lors de la validation métier, tout en conservant l'intégralité des champs présents dans un objet signé lors du calcul des octets canoniques JCS RFC 8785 destinés à la vérification de signature.
5. Les mises à niveau progressives entre versions mineures `1.x` `NE DOIVENT PAS` invalider prématurément les justificatifs `dyn_`, `grt_` ou `vrf_` non expirés émis antérieurement.
