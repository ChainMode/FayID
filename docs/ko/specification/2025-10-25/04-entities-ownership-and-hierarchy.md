---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: ko
canonical: false
chapter: 4
---

# 제4장 신원 엔티티, 단일 계층 소유권 및 조직 계층 트리

## 4.1 `HumanID`와 `iFay`의 일대다 바인딩 (Normative)

1. **루트 신원 생성**: **인간 프라임**은 로컬 보유자 에이전트를 통해 Ed25519 공개 키 `pk_human`을 생성하거나 파생하고, `hid_ || base32NoPad(SHA-256(pk_human))`을 계산하여 `HumanID`를 얻는다.
2. **`1:N` 양도 불가 바인딩**: 동일한 `HumanID`는 임의 개수의 `iFay`를 등록하고 소유**할 수 있다**(`HumanID : iFayID = 1:N`). `iFay`를 등록할 때는 동일한 바인딩 메시지에 대해 해당 `HumanID` 개인 키와 신규 `iFay` 개인 키로 함께 생성한 공동 서명 증명을 **반드시 제출해야 한다**. 둘 중 하나라도 유효한 증명이 누락되면 **반드시** 요청을 거부하고 `HUMAN_ID_OWNERSHIP_NOT_PROVEN`을 반환해야 한다.
3. **기본 `iFay` 간 비연관성**: 공개되는 `IFayRecord`는 솔트가 적용된 단방향 커밋먼트 `humanIdProofRef`(`hidproof_<base32>`)만 저장하며 평문 `hid_`를 포함하지 않는다. **인간 프라임**이 직접 공동 증명을 제시하지 않는 한, 제3자는 두 개의 `ifay_` 공개 레코드만으로 두 개체가 동일한 **인간 프라임**에 속하는지 판별할 수 없다.
4. **양도 불가능성**: `iFay`가 일단 `HumanID`에 바인딩되면 그 귀속 관계는 영구히 고정되며, 다른 `HumanID`나 어떠한 `OrganizationID`로도 **절대 변경해서는 안 된다**.

## 4.2 `coFay` 단일 계층 직결 소유권 및 `managers` 직교 권한 부여 (Normative)

모든 공유 역할 디지털 엔티티가 명확히 책임을 물을 수 있는 유일한 최종 책임 주체를 갖도록 보장하기 위해, FayID 1.0은 `coFay`에 대해 **단일 계층 직결 소유권(Single-Layer Ownership)** 모델을 강제한다:

1. **적법한 소유자 유형 제한**: `coFay`의 `ownerId`는 **반드시** `HumanID`(`hid_`) 또는 `OrganizationID`(`org_`)만이어야 하며, 이에 대응하는 `ownerKind`는 `"HUMAN"` 또는 `"ORGANIZATION"`이다. `iFay`(`ifay_`)나 다른 `coFay`(`cofay_`)를 `coFay`의 소유자로 지정하려는 모든 요청은 **반드시** 즉시 거부하고 `OWNER_TYPE_NOT_ALLOWED`를 반환해야 한다(다계층 중첩 `coFay` 소유권 체인 금지).
2. **소유권 이전**: 현재 소유자(`hid_` 또는 `org_`)는 소유권 변경 증명에 서명하여 `coFay`를 새로운 적법 소유자(`hid_` 또는 `org_`)에게 이전**할 수 있다**. 이전 후에도 `version`은 `"1.0"`을 유지하며 소유자 바인딩 레코드를 갱신한다.
3. **직교 운영 관리 목록(`managers: iFayID[]`)**:
   - `coFay`의 소유자(`hid_` 또는 `org_`)는 일상적인 구성 및 운영 관리 직무를 수행하도록 0개 이상의 `iFayID`에 권한을 부여하여 `managers` 목록에 등재**할 수 있다**.
   - 오직 현재의 직접 소유자만 `managers`를 추가하거나 삭제할 권한을 가진다. 이미 `manager`로 등재된 `iFay`가 임의로 다른 `manager`를 추가, 제거 또는 재위임하는 행위는 **절대 허용해서는 안 되며**, 권한을 넘어선 모든 재위임 시도는 **반드시** 거부하고 `AUTHORITY_GRANT_UNAUTHORIZED`를 반환해야 한다(단일 홉 재위임 금지 원칙).
   - `managers` 목록에 포함된 `iFay`는 운영 조작 권한만 보유하며, `coFay`의 법적·거버넌스적 소유권 귀속을 변경하지 않는다.

## 4.3 조직 엔티티(`OrganizationID`) 및 자연인 `Steward` (Normative)

1. **자연인 거버넌스 대표(`Steward`) 필수 지정**: 등록된 모든 `OrganizationRecord`는 **반드시** 자연인 거버넌스 대표 `stewardHumanId` 1인을 지정해야 하며, 그 값은 **반드시** 이미 등록되어 있고 폐기되지 않은 `HumanID`(`hid_`)여야 한다. `ifay_`, `cofay_` 또는 `org_`를 `Steward`로 지정하려는 모든 작업은 **반드시** 거부하고 `STEWARD_TYPE_NOT_ALLOWED`를 반환해야 한다.
2. **대표 변경**: 조직은 조직 통제 키로 변경 명령에 서명하여 `stewardHumanId`를 교체할 수 있으며, 새 대표 역시 **반드시** 유효하고 폐기되지 않은 `HumanID`여야 한다.

## 4.4 자체 완결적 단일 상위 무순환 조직 계층 트리 (Normative)

FayID 1.0은 본 저장소 사양 내에서 조직 간 계층 거버넌스 관계를 자체 완결적으로 정의한다:

1. **단일 상위 트리 토폴로지**: 모든 `OrganizationRecord`는 `parentOrgId: OrganizationID | null`을 포함한다. 각 하위 조직은 동일 시점에 최대 하나의 직접 상위 조직만 가질 수 있으며, 전체 구조는 여러 개의 방향성 무순환 트리(포리스트)를 이룬다. 프로토콜은 16단계와 같은 인위적인 고정 깊이 상한을 **두지 않는다**.
2. **양방향 합의 강제(Mutual Two-Party Consent)**: `childOrg.parentOrgId = parentOrgId`를 설정하거나 변경할 때는 하위 조직 통제 키로 서명한 마운트 요청 서명과 대상 상위 조직 통제 키로 서명한 수락 동의 서명을 **반드시 동시에 첨부해야 한다**. 어느 한쪽의 동의라도 누락되거나 서명 검증에 실패하면 **반드시** 거부하고 `HIERARCHY_CONSENT_MISSING`을 반환해야 한다.
3. **순환 참조 검출(Cycle Rejection)**: `parentOrgId`가 조직 자신을 가리키거나 해당 조직의 현재 하위 자손 조직을 가리켜 순환 구조를 형성하는 마운트 요청은 **반드시** 결정론적으로 거부하고 `HIERARCHY_CYCLE_CONFLICT`를 반환해야 한다.
4. **조직 트리를 따른 소유권 자동 승계 없음**: 하위 조직 명의로 직접 소유한 `coFay`는 여전히 해당 하위 조직 `org_`를 직접 소유자로 유지한다. 상위 조직은 조직 계층 마운트를 이유로 하위 조직 산하 `coFay`의 직접 소유권을 자동 취득하거나 단일 계층 소유권 레코드를 우회하지 않는다.
