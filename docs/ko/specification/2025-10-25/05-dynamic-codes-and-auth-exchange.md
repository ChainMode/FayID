---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: ko
canonical: false
chapter: 5
---

# 제5장 비연관 동적 코드, 인증 교환 및 연쇄 폐기

## 5.1 비연관 동적 코드(`dyn_`) 발급 및 검증 (Normative)

평문 `hid_`는 결코 외부로 유출되지 않으므로, **인간 프라임** 및 그 산하 `iFay`, `coFay`는 경계를 넘어 신원을 제시할 때 짧은 유효 기간과 솔트 기반 비연관성을 갖춘 동적 코드(`dyn_<base32>`)를 사용한다:

1. **적법한 대상 주체**: 동적 코드는 폐기되지 않은 `HumanID`(`hid_`), `iFayID`(`ifay_`) 또는 `coFayID`(`cofay_`)에 대해서만 발급할 수 있다. `OrganizationID`(`org_`)를 대상으로 동적 코드 발급을 요청하면 **반드시** 거부하고 `DYNAMIC_CODE_TARGET_NOT_ALLOWED`를 반환해야 한다(조직 식별자는 본래 공개 주체이므로 가명 동적 코드가 필요하지 않다).
2. **솔트 기반 비연관 생성 구조**: 발급할 때마다 최소 16바이트 이상의 암호학적 난수 `nonce`를 생성하고, `ifay.fayid.dynamic-code.v1` 도메인 키 아래에서 정규화된 페이로드 `{audience, expiresAt, issuedAt, nonceHex, targetId, version: "1.0"}`에 대해 HMAC-SHA256을 계산한 뒤 앞의 20바이트를 절단하여 `dyn_<base32>`로 인코딩한다. 수동적 도청자는 검증 컨텍스트 키가 없는 한 두 번 제시된 `dyn_` 문자열을 관찰하더라도 두 문자열이 동일 주체에서 유래했는지 판별할 수 없다.
3. **엄격한 유효 시간 창 상한**: `expiresAt - issuedAt`은 **반드시** `0`보다 크고 **`600`초(`DYNAMIC_CODE_MAX_TTL_SECONDS = 600`)** 이하여야 한다. 상한을 초과하는 발급 요청은 **반드시** 거부하고 `DYNAMIC_CODE_INVALID`를 반환해야 한다.
4. **단일 소비 및 재전송 방지**: 검증자가 `dyn_`을 검증할 때는 다음 규칙을 따른다:
   - 주체 자체 또는 그 상위 귀속 주체가 이미 폐기된 경우 **반드시** 거부하고 `ENTITY_REVOKED`를 반환해야 한다.
   - 검증 시각이 `expiresAt` 이후인 경우 **반드시** 거부하고 `DYNAMIC_CODE_EXPIRED`를 반환해야 한다.
   - 토큰에 예상 수신 대상이 바인딩되어 있으나 `audience`가 일치하지 않거나 알 수 없는 토큰인 경우 **반드시** `DYNAMIC_CODE_INVALID`를 반환해야 한다.
   - 각 `dyn_`의 난수 `nonce`는 **단 한 번**만 검증 소비에 성공할 수 있다. 동일한 `dyn_`을 두 번째 이후 반복 제출하면 **반드시** 거부하고 `DYNAMIC_CODE_REPLAYED`를 반환해야 한다.
5. **검증 결과 프라이버시 보호**: `dyn_`에 바인딩된 기저 주체가 `HumanID`인 경우, 검증 성공 응답에서 호출자에게 평문 `hid_`를 반환해서는 **절대 안 되며**, **반드시** 주체 분류 `"HUMAN"`과 블라인드 솔트로부터 결정론적으로 파생된 `gmcref_<base32>` 앵커를 반환해야 한다.

## 5.2 레거시 자격 증명 바인딩 및 인증 교환 권한 부여(`grt_` / `vrf_`) (Normative)

Auth Exchange는 보유자가 외부 기존 시스템의 자격 증명을 범위가 제한된 FayID 권한 부여 자격 증명(`grt_<base32>`)으로 안전하게 브리징하고, 리소스 접근 시 오프라인 서명 검증이 가능한 검증 영수증(`vrf_<base32>`)을 생성할 수 있게 한다:

1. **레거시 주체 프라이버시 해시(`LegacySubjectRef`)**: 외부 자격 증명 주체는 **반드시** 정규화한 뒤 비밀 키 기반 HMAC을 거쳐 `<legacySourceKind>:<issuerOrAuthority>:<subjectHash>` 형식으로 변환해야 한다. 여기서 `subjectHash = base32NoPad(HMAC-SHA256(legacySecret, canonicalSubject))`이다. `LegacySubjectRef`에 평문 이메일 주소, 전화번호, X.509 DN, OAuth 원시 토큰 또는 블록체인 평문 지갑 주소를 직접 이어 붙이는 행위는 **절대 허용해서는 안 된다**.
2. **기본 신뢰 등급 매핑(`LegacyTrustLevel`)**:
   - `PASSWORD` → `LOW`(권한 부여 TTL 상한 **`900`초**, `LOW_TRUST_GRANT_MAX_TTL_SECONDS`)
   - `ACCESS_TOKEN`, `AUTHORIZATION` → `MEDIUM`(권한 부여 TTL 상한 **`3600`초**, `GRANT_MAX_TTL_SECONDS`)
   - `CERTIFICATE`, `SMART_CONTRACT` → `HIGH`(권한 부여 TTL 상한 **`3600`초**)
   구현체는 위험 정책에 따라 신뢰 등급을 낮추거나 TTL을 단축**할 수 있지만**, 추가적인 다중 요소 보유자 증명 없이 등급을 임의로 상향해서는 **절대 안 된다**.
3. **대상 보유 증명 우선 검사(탐지 방지)**: `grt_`를 발급할 때 대상 주체는 폐기되지 않은 `iFayID` 또는 `coFayID`로 제한하며, 요청자는 **반드시** 대상 주체의 보유자 서명 증명을 제시해야 한다. 대상 보유 증명이 누락되었거나 유효하지 않으면 시스템은 공격자가 오류 코드 차이를 악용해 특정 레거시 계정이 특정 FayID와 바인딩되어 있는지 탐지하지 못하도록 **반드시** `TARGET_OWNERSHIP_NOT_PROVEN`을 최우선으로 반환해야 한다.
4. **범위 지정 검증 및 `vrf_` 영수증 발급**: `verifyAuthGrant`를 호출해 `grt_`를 검증할 때 시스템은 다음 순서로 확인한다:
   - 권한 부여 레코드가 존재하고 형식이 적법한지 확인한다(그렇지 않으면 `GRANT_INVALID` 반환).
   - 대상 엔티티 및 그 상위 소유자가 폐기되었는지 확인한다(엔티티가 폐기된 경우 `ENTITY_REVOKED`를 우선 반환).
   - 권한 부여 자체가 명시적으로 폐기되었는지 확인한다(폐기된 경우 `GRANT_REVOKED` 반환).
   - 현재 시각이 `expiresAt`을 초과했는지 확인한다(초과한 경우 `GRANT_EXPIRED` 반환).
   - 요청된 `requestedResourceRef`가 제2.3절의 `scopeMode`(`EXACT` / `PREFIX`)에 따라 권한이 부여된 `resourceRef`와 매칭되는지 확인한다(불일치 시 `GRANT_INVALID` 반환).
   모든 검사를 통과하면 시스템은 `ifay.fayid.auth-exchange.v1` 도메인 Ed25519 키로 정규화된 검증 결론에 서명하여 `vrf_<base32>` 영수증을 반환한다. 제3자는 누구나 `verifyAuthReceipt(receipt)`를 호출해 영수증 서명과 구조적 무결성을 독립적으로 검증할 수 있으며, 어느 한 필드라도 위변조된 경우 **반드시** `RECEIPT_INVALID`를 반환해야 한다.

## 5.3 결정론적 연쇄 폐기(Cascading Revocation) (Normative)

폐기는 단조적이며 되돌릴 수 없는 종단 상태 작업이다. 어느 엔티티가 폐기되면 시스템은 **반드시** 즉시 귀속 및 계층 관계에 따라 결정론적으로 연쇄 무효화를 수행해야 하며, 고립된 활성 하위 엔티티나 활성 권한 부여 자격 증명을 남겨 두어서는 **절대 안 된다**:

| 폐기된 루트 트리거 엔티티 | 연쇄 무효화되는 하위 엔티티 범위 | 운영 권한 부여 및 활성 자격 증명에 대한 강제 연대 조치 |
| --- | --- | --- |
| **`HumanID`(`hid_`)** | 해당 **인간 프라임** 명의의 모든 `iFay`(`ifay_`) 및 해당 `hid_`에 직접 귀속된 모든 `coFay`(`cofay_`) | 폐기되지 않은 모든 `coFay.managers`에서 위 연쇄 폐기된 `ifay_`를 제거하고, 위 `ifay_` / `cofay_`를 가리키는 모든 활성 `grt_`와 미소비 `dyn_`을 폐기한다 |
| **`OrganizationID`(`org_`)** | 해당 조직 자체, 조직 계층 트리 내 모든 하위 자손 조직(재귀 서브트리), 그리고 해당 조직 또는 임의의 하위 자손 조직에 직접 귀속된 모든 `coFay` | 위 연쇄 폐기된 `cofay_`를 가리키는 모든 활성 `grt_`와 미소비 `dyn_`을 폐기한다 |
| **`iFayID`(`ifay_`)** | 해당 `iFay` 자체 | 폐기되지 않은 모든 `coFay.managers` 목록에서 해당 `ifay_`를 즉시 제거하고, 해당 `ifay_`를 `targetFayId`로 삼는 모든 활성 `grt_`와 미소비 `dyn_`을 폐기한다 |
| **`coFayID`(`cofay_`)** | 해당 `coFay` 자체 | 해당 `cofay_`를 `targetFayId`로 삼는 모든 활성 `grt_`와 미소비 `dyn_`을 폐기한다 |

연쇄 폐기가 완료된 이후에는 다음 규칙을 적용한다:
1. 직접 폐기되었거나 연쇄 폐기된 엔티티에 대해 신규 `dyn_`이나 `grt_`를 발급하거나, 신규 하위 엔티티를 등록하거나, 기존 자격 증명을 검증하려 할 때는 **반드시** 결정론적으로 거부하고 `ENTITY_REVOKED`를 반환해야 한다(대상 엔티티는 여전히 유효하지만 개별적으로 수동 폐기된 권한 부여에 대해서는 `GRANT_REVOKED`를 반환한다).
2. 폐기된 엔티티의 자격 증명은 원래 설정된 TTL 시간 창 안에 남아 있더라도 **즉시 무효화**되며, 더 이상 검증을 통과할 수 **없다**.
