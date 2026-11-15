---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: ko
canonical: false
chapter: 2
---

# 제2장 식별자 문법, 인코딩 및 리소스 참조 사양

## 2.1 8종 규범 식별자 접두사 표 (Normative)

모든 FayID 암호학적 식별자와 파생 자격 증명 문자열은 **반드시** `<prefix>_<body>` 구조를 따라야 한다. 가독성 있는 소문자 조직 식별자 문자 집합 `[a-z0-9-]+`을 허용하는 `org_`를 제외한 나머지 7종 식별자의 본문은 **반드시** **`=` 패딩 없는 소문자 RFC 4648 Base32** 문자 집합(`[a-z2-7]+`)을 사용해야 한다:

| 타입 상수 | 문자열 접두사 | 본문 정규식 | 표준 바이트 길이 및 의미 |
| --- | --- | --- | --- |
| `HUMAN_ID` | `hid_` | `^[a-z2-7]+$` | `SHA-256(humanPublicKey)`(32바이트 → Base32 52자), **인간 프라임** 루트 신원 식별자 |
| `IFAY_ID` | `ifay_` | `^[a-z2-7]+$` | `SHA-256("ifay:" \|\| humanId \|\| ":" \|\| publicKey)`(32바이트), 개인 디지털 분신 식별자 |
| `COFAY_ID` | `cofay_` | `^[a-z2-7]+$` | `SHA-256("cofay:" \|\| ownerId \|\| ":" \|\| publicKey)`(32바이트), 공유 역할 디지털 엔티티 식별자 |
| `ORGANIZATION_ID` | `org_` | `^[a-z0-9-]+$` | 조직 주체 식별자(결정론적 해시 본문 또는 정규화된 조직 단축명 지원) |
| `DYNAMIC_CODE` | `dyn_` | `^[a-z2-7]+$` | 20바이트 HMAC 절단 태그(Base32 32자), 단기 비연관 제시 토큰 |
| `VERIFICATION_CODE` | `vrf_` | `^[a-z2-7]+$` | 20바이트 검증 영수증 다이제스트, `grt_` 또는 `cofay_` 상태 검증 결과에 바인딩 |
| `AUTHORIZATION_GRANT` | `grt_` | `^[a-z2-7]+$` | 20바이트 범위 지정 레거시 자격 증명 교환 권한 부여 식별자 |
| `OPAQUE_REF` | `gmcref_` | `^[a-z2-7]+$` | 32바이트 블라인드 자연인 앵커(Base32 52자), `GMChain` 거버넌스 중복 제거 전용 |

이 밖에 `iFay` 등록 레코드와 오프라인 패키지에서 평문 `hid_`를 대체하는 단방향 커밋먼트는 `hidproof_<lowercase-base32-nopad>` 형식(정규식 `^hidproof_[a-z2-7]{16,}$`)을 사용한다.

## 2.2 정규화 및 엄격 거부 규칙 (Normative)

파싱 함수 `normalizeFayID(input)`은 **반드시** 다음 결정론적 규칙을 충족해야 한다:

1. **타입 및 비어 있지 않음 검사**: 문자열이 아닌 입력이나 빈 문자열은 **반드시** 즉시 오류 코드 `MALFORMED_FAYID_STRING`을 반환해야 한다.
2. **대소문자 폴딩**: 파서는 **반드시** ASCII 대문자를 소문자로 변환(`input.toLowerCase()`)한 뒤 위 표의 8종 접두사와 대조해야 한다.
3. **엄격 거부 및 자동 보정 절대 금지**: 파서는 앞뒤 공백 문자를 자동으로 잘라내거나, 하이픈(`org_` 본문의 적법한 하이픈 제외)을 제거하거나, `=` 패딩 문자를 떼어내거나, 혼동하기 쉬운 문자(예: `0`/`1`/`8`/`9`를 Base32 알파벳으로 치환)를 임의로 보정해서는 **절대 안 된다**. 공백, `=`, 알 수 없는 접두사, 빈 본문 또는 허용 범위를 벗어난 문자(예: `hid_` 본문에 `0`, `1`, `8`, `9` 등장)를 포함한 문자열은 **반드시** 일괄 거부하고 `MALFORMED_FAYID_STRING`을 반환해야 한다.
4. **왕복 불변성(Round-Trip Invariant)**: 적법하게 정규화된 임의의 식별자 `x`에 대해 `normalizeFayID(x)`를 다시 실행하면 **반드시** `ok: true` 및 `value.canonical === x`를 반환해야 한다. 또한 임의의 바이트 배열 `b`를 무패딩 소문자 Base32로 인코딩한 뒤 다시 디코딩하면 **반드시** 바이트 단위로 `b`가 정확히 복원되어야 하며, 마지막 잔여 패딩 비트는 **반드시** 모두 `0`이어야 한다(0이 아닌 잔여 비트가 있으면 **반드시** 디코딩을 거부해야 한다).

## 2.3 `resourceRef` 리소스 네임스페이스 및 범위 매칭 (Normative)

인증 교환에서 대상 리소스는 `resourceRef`로 식별한다. `normalizeResourceRef(input)`과 `matchesResourceRef(grantedResourceRef, requestedResourceRef, scopeMode)`는 **반드시** 다음 규칙을 준수해야 한다:

1. **문법 구조**: `resourceRef`는 `<namespace>:<path>` 구조를 따른다:
   - `<namespace>`는 소문자로 변환한 뒤 **반드시** `^[a-z][a-z0-9+.-]*$`와 일치해야 한다.
   - `:` 오른쪽의 `<path>`는 **반드시** 비어 있지 않아야 하며, 공백 문자를 포함하지 않고, `/`로 끝나지 않아야 한다(단일 문자 루트 경로 제외). 또한 빈 경로 세그먼트(`//`)나 상대 탐색 세그먼트(`.` 또는 `..`)를 **절대 포함해서는 안 된다**.
   - 위 조건 중 하나라도 위반하면 **반드시** `MALFORMED_FAYID_STRING`을 반환해야 한다.
2. **대소문자 구분**: `<namespace>` 부분은 소문자로 정규화하며, `:` 오른쪽의 `<path>`는 **반드시** 원래의 대소문자를 유지해야 한다.
3. **범위 매칭 모드(`scopeMode`)**:
   - `EXACT`(기본값): 정규화된 `requestedResourceRef === grantedResourceRef`일 때만 매칭에 성공한다.
   - `PREFIX`: 정규화된 요청 리소스가 부여된 리소스 자체와 같거나, `/` 경로 세그먼트 경계 위에서 해당 리소스를 접두사로 가질 때(즉 `requested.startsWith(granted + "/")`)만 매칭에 성공한다. 예를 들어 권한이 부여된 `cap:repo/fayid`는 `PREFIX` 모드에서 `cap:repo/fayid/issues`와 매칭되지만, 형제 경로인 `cap:repo/fayid-ext`와는 **절대 매칭되지 않는다**(단순 문자열 접두사 일치를 통한 권한 우회 방지).

## 2.4 레거시 64자리 16진수 공개 키 식별자 브리징 (Normative)

32바이트 원시 Ed25519 공개 키의 16진수 문자열(16진수 64자)만 보유한 초기 기존 레코드와의 호환을 위해, 툴킷은 명시적 브리징 함수 `adaptLegacyHexIdentifier(hex64, prefix)`를 제공한다:

1. 공백을 제거한 입력 `hex64`는 **반드시** `^[0-9a-fA-F]{64}$`와 정확히 일치해야 하며, 대상 `prefix`는 `hid_`, `ifay_` 또는 `cofay_`만 허용한다. 그렇지 않으면 `MALFORMED_FAYID_STRING`을 반환한다.
2. 브리징 과정은 디코딩된 32바이트 원시 공개 키에 대해 `SHA-256`을 계산한 뒤 `<prefix><base32-nopad>`로 인코딩하며, 이는 네이티브 루트 신원 산출 공식과 완전히 동일하다.
3. 프로토콜의 정식 와이어 포맷 페이로드에서는 원시 64자리 16진수 문자열을 FayID 대신 직접 전송할 수 **없다**. 브리징은 프로토콜 경계에 진입하기 전에 **반드시** 명시적으로 완료해야 한다.
