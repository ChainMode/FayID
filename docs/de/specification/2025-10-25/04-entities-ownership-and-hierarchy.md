---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: de
canonical: false
chapter: 4
---

# Kapitel 4: Identitätsentitäten, einstufige Eigentümerschaft und Organisationshierarchie

## 4.1 Eins-zu-viele-Bindung von `HumanID` zu `iFay` (Normativ)

1. **Ableitung der Wurzelidentität**: Ein `Human Prime` erzeugt oder leitet in einem lokalen `Holder Agent` einen öffentlichen Ed25519-Schlüssel `pk_human` ab und berechnet daraus `hid_ || base32NoPad(SHA-256(pk_human))` als seine `HumanID`.
2. **Nicht übertragbare `1:N`-Bindung**: Eine einzelne `HumanID` `DARF` beliebig viele `iFay`-Instanzen registrieren und besitzen (`HumanID : iFayID = 1:N`). Die Registrierung eines `iFay` `MUSS` gemeinsame Ed25519-Signaturen sowohl des privaten Schlüssels der besitzenden `HumanID` als auch des privaten Schlüssels des neuen `iFay` über die kanonische Bindungs-Payload enthalten; fehlende oder ungültige Nachweise `MÜSSEN` mit `HUMAN_ID_OWNERSHIP_NOT_PROVEN` fehlschlagen.
3. **Standardmäßige Nichtverkettbarkeit zwischen `iFay`-Instanzen**: Öffentliche `IFayRecord`-Objekte speichern lediglich das gesalzene Einweg-Commitment `humanIdProofRef` (`hidproof_<base32>`); `hid_` im Klartext `DARF NICHT` offengelegt werden. Ohne einen vom `Human Prime` freiwillig vorgelegten gemeinsamen Nachweis können externe Beobachter nicht feststellen, ob zwei öffentliche `ifay_`-Datensätze demselben `Human Prime` gehören.
4. **Dauerhafte Nichtübertragbarkeit**: Ein einmal an eine `HumanID` gebundenes `iFay` `DARF NICHT` auf eine andere `HumanID` oder auf eine `OrganizationID` übertragen werden.

## 4.2 Einstufige `coFay`-Eigentümerschaft und orthogonale `managers`-Delegation (Normativ)

Um für jede Entität mit geteilter Rolle eine unmittelbare, durchgreifende Rechenschaftspflicht sicherzustellen, setzt FayID 1.0 für `coFay` eine **einstufige Eigentümerschaft** (Single-Layer Ownership) durch:

1. **Zulässige Eigentümertypen**: `coFay.ownerId` `MUSS` entweder eine `HumanID` (`hid_`) oder eine `OrganizationID` (`org_`) sein, wobei `ownerKind` auf `"HUMAN"` oder `"ORGANIZATION"` gesetzt ist. Jeder Versuch, ein `coFay` unter einem `iFay` (`ifay_`) oder einem anderen `coFay` (`cofay_`) zu registrieren oder dorthin zu übertragen, `MUSS` sofort mit `OWNER_TYPE_NOT_ALLOWED` fehlschlagen (verschachtelte `coFay`-Eigentümerketten sind unzulässig).
2. **Eigentumsübertragung**: Der aktuelle unmittelbare Eigentümer (`hid_` oder `org_`) `DARF` ein `coFay` mittels eines signierten Übertragungsnachweises auf einen neuen zulässigen Eigentümer (`hid_` oder `org_`) übertragen; dabei bleibt `version: "1.0"` erhalten und die Eigentumsbindung wird aktualisiert.
3. **Orthogonale Betriebsverwalter (`managers: iFayID[]`)**:
   - Der unmittelbare Eigentümer (`hid_` oder `org_`) eines `coFay` `DARF` null oder mehr `iFayID`-Bezeichner in `managers` für die laufende Betriebsverwaltung autorisieren.
   - Ausschließlich der unmittelbare Eigentümer ist befugt, Einträge in `managers` hinzuzufügen oder zu entfernen; ein in `managers` aufgeführtes `iFay` `DARF NICHT` weitere Manager hinzufügen, entfernen oder weiterdelegieren. Jeder unbefugte Delegationsversuch `MUSS` mit `AUTHORITY_GRANT_UNAUTHORIZED` fehlschlagen (einstufige Delegation ohne Unterdelegation).
   - Die operative Aufnahme in `managers` ändert zu keinem Zeitpunkt das rechtliche oder organisatorische Eigentum am `coFay`.

## 4.3 `OrganizationID` und natürliche Person als `Steward` (Normativ)

1. **Verbindlicher `Steward` als natürliche Person**: Jeder registrierte `OrganizationRecord` `MUSS` mit `stewardHumanId` eine natürliche Person als Governance-Vertreter benennen, die auf eine registrierte, nicht widerrufene `HumanID` (`hid_`) verweist. Jeder Versuch, `ifay_`, `cofay_` oder `org_` als `Steward` einzutragen, `MUSS` mit `STEWARD_TYPE_NOT_ALLOWED` fehlschlagen.
2. **Rotation des Stewards**: Eine Organisation `DARF` `stewardHumanId` über einen mit dem kontrollierenden Schlüsselpaar der Organisation signierten Befehl rotieren, sofern der Nachfolger ebenfalls eine gültige, nicht widerrufene `HumanID` ist.

## 4.4 Eigenständige zyklenfreie Organisationshierarchie mit Einzel-Elternknoten (Normativ)

FayID 1.0 definiert die organisationsübergreifende Hierarchie unmittelbar innerhalb dieser Spezifikation:

1. **Baumtopologie mit höchstens einem Elternknoten**: Jeder `OrganizationRecord` führt `parentOrgId: OrganizationID | null`. Jede Unterorganisation hat zu jedem Zeitpunkt höchstens eine direkte übergeordnete Organisation, sodass ein Wald gerichteter zyklenfreier Bäume entsteht. Das Protokoll gibt **keine künstliche feste Tiefenbegrenzung** (etwa 16 Ebenen) vor.
2. **Gegenseitige Zustimmung beider Parteien**: Das Einhängen oder Umhängen von `childOrg.parentOrgId = parentOrgId` `MUSS` gültige Ed25519-Zustimmungssignaturen sowohl des kontrollierenden Schlüssels der Unterorganisation als auch des kontrollierenden Schlüssels der angestrebten übergeordneten Organisation tragen. Fehlt die Zustimmung einer Seite oder ist sie ungültig, `MUSS` der Vorgang mit `HIERARCHY_CONSENT_MISSING` fehlschlagen.
3. **Deterministische Zyklenabweisung**: Jede Zuordnung, die `parentOrgId` auf die Organisation selbst oder auf einen ihrer bestehenden Nachfahren setzt, `MUSS` deterministisch mit `HIERARCHY_CYCLE_CONFLICT` fehlschlagen.
4. **Keine implizite Hochreichung des `coFay`-Eigentums**: Ein `coFay` im Eigentum einer Unterorganisation behält diese `org_` als unmittelbare `ownerId`; das Einhängen einer Organisation in einen übergeordneten Baum überträgt oder bündelt das unmittelbare Eigentum an deren `coFay`-Datensätzen nicht implizit nach oben.
