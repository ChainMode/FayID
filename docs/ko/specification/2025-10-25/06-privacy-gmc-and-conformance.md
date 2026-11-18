---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: ko
canonical: false
chapter: 6
---

# 제6장 프라이버시 금지선, `GMChain` 인터페이스, 오류 코드 및 적합성 판정

## 6.1 아웃바운드 페이로드 및 로그 비식별화 절대 금지선 (Normative)

모든 구현체는 프로토콜 직렬화 계층과 관측 가능성 로그 계층 양쪽에서 우회 불가능한 다음 프라이버시 금지선을 **반드시** 동시에 집행해야 한다:

1. **평문 `hid_` 외부 전송 영구 금지 및 로그 기록 영구 금지**: 어떠한 네트워크 아웃바운드 요청, 공개 디렉터리 스냅샷, `.ego` 내보내기 패키지, 주체 간 검증 영수증(`vrf_`), 크래시 덤프 및 감사 로그에도 평문 `hid_<base32>` 문자열을 **절대 기록해서는 안 된다**. 외부 상호작용에는 일괄적으로 `ifay_`, `cofay_`, `dyn_`, `hidproof_` 또는 블라인드 앵커 `gmcref_`를 사용한다.
2. **마스터 시드 및 개인 키 외부 유출 제로**: 마스터 시드(`masterSeed`), 니모닉, 원시 개인 키(`privateKey` / `secretKey`) 및 `userBlindSalt`는 **반드시** 통제된 로컬 보유자 에이전트의 보안 저장소 내부에만 엄격히 상주해야 하며, 어떠한 직렬화 공개 레코드나 네트워크 페이로드에도 **절대 진입해서는 안 된다**.
3. **네임스페이스 간 비연관성**: 서로 다른 외부 소비 도메인은 외부 관찰자가 식별자를 대조하여 동일한 **인간 프라임**의 전체 네트워크 행동 프로필을 조합하지 못하도록 각기 독립된 도메인 분리 상수나 솔트를 **반드시** 사용해야 한다.

## 6.2 `공예체인`(`GMChain`) 읽기 전용 경계 및 블라인드 앵커 `gmcref_` (Normative)

`공예체인`(`GMChain`)은 동일한 자연인이 아무리 많은 `iFay`를 생성하더라도 자연인 차원의 거버넌스 가중치 산정과 시빌 공격 방지 정규화에서는 단일 자연인 앵커로만 계산되도록 보장해야 하며, 동시에 해당 자연인의 평문 `hid_`는 알 수 없어야 한다. 이를 위해 FayID 1.0은 결정론적 블라인드 앵커 `gmcref_<base32>`를 정의한다:

```text
prk    = HKDF-SHA256(ikm = userBlindSalt, salt = SHA-256("fayid.gmc.salt.v1"), info = "ifay.gmc.natural-person.v1:" || namespace, len = 32)
digest = HMAC-SHA256(key = prk, data = UTF8("gmcref:" || canonicalHumanId))
gmcref = "gmcref_" || base32EncodeNoPad(digest)
```

규범적 경계는 다음과 같다:

1. **결정론성과 비가역성**: 동일한 적법 `HumanID`, 32바이트 이상의 동일한 `userBlindSalt`, 그리고 동일한 `namespace`(기본값 `"gmchain.main"`)가 주어지면 파생되는 `gmcref_`는 완전히 결정론적이며 항상 일정하다. 반면 `userBlindSalt`를 알지 못하는 제3자(`GMChain` 노드 포함)는 계산상 `gmcref_`로부터 `hid_`를 역추적할 수 없으며, 이를 해당 자연인 명의의 공개 `ifay_` 레코드와 직접 연관 지을 수도 없다.
2. **엄격한 읽기 전용 인터페이스 경계**: FayID는 `GMChain`에 대해 단방향 앵커 파생과 폐기 상태 검증 입력만 제공하며, `GMChain` 원장 상태를 **읽거나 쓰지 않고** `미예치`(`MeriToken`)의 산정, 증감 또는 배분에도 **참여하지 않는다**. `미예치`(`MeriToken`)는 법정화폐 환전, 채굴 발행, 금융 결제 또는 투기 거래 속성을 갖지 않는 비화폐적 사회적 기여 지표이며, 암호화폐나 금융 결제 수단 또는 법정화폐 환전 가능 자산이 아니다.
3. **자연인 전용 파생**: `deriveBlindGmcRef`의 주체 입력은 **반드시** 적법한 `HumanID`(`hid_`)여야 한다. `ifay_`, `cofay_` 또는 `org_`가 전달되면 **반드시** 거부하고 `MALFORMED_FAYID_STRING`을 반환해야 한다.

## 6.3 규범 오류 코드 레지스트리 (Normative)

FayID 1.0을 준수하는 구현체는 **반드시** 다음 24개 고정 오류 코드 상수(기초 프로토콜 오류 코드 14개 + 계정·암호학 도메인·연쇄 거버넌스 오류 코드 10개)를 유지해야 한다:

| 오류 코드 상수 | 발생 조건 요약 |
| --- | --- |
| `INSUFFICIENT_ENTROPY` | 마스터 시드, 블라인드 솔트 또는 난수 엔트로피 길이가 256비트(32바이트) 하한 미만임 |
| `HUMAN_ID_OWNERSHIP_NOT_PROVEN` | 등록 또는 작업에서 `HumanID` 보유자 서명 제시를 요구했으나 누락되었거나 서명 검증에 실패함 |
| `OWNERSHIP_NOT_PROVEN` | 엔티티 통제권 행사 또는 이전 작업에 현재 소유자의 유효한 서명 증명이 누락됨 |
| `TARGET_OWNERSHIP_NOT_PROVEN` | `grt_` 발급 등의 작업에서 대상 `iFay` / `coFay` 보유권을 증명하지 못함(바인딩 탐지 방지를 위해 최우선 반환) |
| `LEGACY_SUBJECT_MISMATCH` | 레거시 자격 증명의 정규화된 주체 해시가 바인딩된 `LegacySubjectRef`와 일치하지 않음 |
| `DYNAMIC_CODE_EXPIRED` | `dyn_` 검증 시각이 해당 코드의 `expiresAt` 만료 시각을 지남 |
| `DYNAMIC_CODE_INVALID` | `dyn_` 형식을 알 수 없거나, HMAC 검증에 실패했거나, 수신 대상이 불일치하거나, 요청 TTL이 600초 상한을 초과함 |
| `VERIFICATION_RATE_LIMITED` | 연속 검증 실패 횟수가 속도 제한 시간 창 임계치에 도달함(기본값: 600초 내 5회 실패 시 지수 백오프 작동) |
| `IDENTITY_REVOKED` | 기초 계층 공통 신원 폐기 상태 식별자 |
| `LEGACY_AUTH_FAILED` | 외부 레거시 자격 증명(비밀번호, 인증서, 토큰, 컨트랙트 증명 등)의 상위 인증이 통과하지 못함 |
| `GRANT_EXPIRED` | `grt_` 권한 부여 검증 시각이 해당 권한의 `expiresAt` 만료 시각을 지남 |
| `GRANT_REVOKED` | `grt_` 권한 부여가 개별적으로 폐기됨 |
| `GRANT_INVALID` | `grt_`가 존재하지 않거나, 구조가 부적법하거나, 대상 유형이 허용되지 않거나, 요청 `resourceRef`가 부여된 범위를 벗어남 |
| `MALFORMED_FAYID_STRING` | 식별자 접두사/Base32 본문이 부적법하거나, `resourceRef` 문법을 위반했거나, 예상하지 못한 접두사 유형이 전달됨 |
| `OWNER_TYPE_NOT_ALLOWED` | `iFay` 또는 `coFay`를 `coFay`의 소유자로 지정하려 시도함(단일 계층 소유권 불변성 위반) |
| `HIERARCHY_CONSENT_MISSING` | 조직 계층 마운트에 하위 조직 또는 상위 조직 중 어느 한쪽의 유효한 동의 서명이 누락됨 |
| `HIERARCHY_CYCLE_CONFLICT` | 조직 계층 마운트가 자기 자신 또는 하위 자손 노드를 가리켜 순환 경로를 형성함 |
| `AUTHORITY_GRANT_UNAUTHORIZED` | `coFay`의 직접 소유자가 아닌 주체(예: `managers` 구성원)가 `managers` 권한을 수정하거나 재위임하려 시도함 |
| `STEWARD_TYPE_NOT_ALLOWED` | 조직 `Steward`가 유효하고 폐기되지 않은 자연인 `HumanID`(`hid_`)로 지정되지 않음 |
| `ENTITY_REVOKED` | 대상 엔티티 또는 그 상위 귀속 `HumanID` / `OrganizationID`가 직접 폐기되었거나 연쇄 폐기됨 |
| `DYNAMIC_CODE_REPLAYED` | 동일한 일회용 `dyn_` 동적 코드가 반복 제출되어 검증 요청됨(재전송 방지 차단) |
| `DYNAMIC_CODE_TARGET_NOT_ALLOWED` | 동적 코드를 지원하지 않는 주체(예: `OrganizationID`)에 대해 `dyn_` 발급을 시도함 |
| `DOMAIN_SEPARATION_REQUIRED` | HKDF 서브키 파생에 적법한 `SubkeyDomain` 또는 비어 있지 않은 컨텍스트 식별자가 누락됨 |
| `RECEIPT_INVALID` | `vrf_` 검증 영수증 구조가 불완전하거나, 접두사가 부적법하거나, Ed25519 서명 검증에 실패함 |

## 6.4 적합성 판정 요건(Conformance) (Normative)

어떠한 소프트웨어 라이브러리, 서비스 또는 보유자 에이전트든 **FayID 1.0** 적합성을 선언하려면 검증 가능한 다음 조건을 **반드시** 모두 충족해야 한다:

1. **버전 및 Schema 적합성**: 생성하는 모든 공개 엔티티 레코드와 자격 증명 엔벨로프에 `version: "1.0"`을 포함하고, [schemas/fayid-1.0.json](../../../../schemas/fayid-1.0.json) 검증을 통과해야 한다.
2. **식별자 및 리소스 매칭 적합성**: 제2장의 8종 접두사 정규화, 입력 무보정 엄격 거부 규칙, 그리고 `resourceRef`의 `EXACT` / `PREFIX` 경계 매칭을 완전히 구현해야 한다.
3. **암호학 및 루트 키 격리 적합성**: 제3장의 Ed25519, SHA-256, HKDF-SHA256 5종 도메인 분리 서브키 파생 및 RFC 8785 JCS 서명을 완전히 구현하고, `.ego` 패키지를 비롯한 모든 아웃바운드 페이로드에서 `ifay.ego.package-signing.v1` 서브키만 엄격히 사용하여 루트 시드와 개인 키의 외부 유출 제로를 보장해야 한다.
4. **계정 모델 및 연쇄 폐기 적합성**: 제4장의 단일 계층 `coFay` 소유권, 자연인 `Steward`, 양방향 합의 기반 단일 상위 무순환 조직 트리와 제5장의 `dyn_` 재전송 방지, `grt_` / `vrf_` 범위 지정 교환, 4종 주체의 결정론적 연쇄 폐기를 빠짐없이 강제 집행해야 한다.
5. **공식 테스트 벡터 전수 통과**: 본 저장소의 [vectors/hierarchy/](../../../../vectors/hierarchy) 및 [vectors/crypto-and-revocation-vectors.json](../../../../vectors/crypto-and-revocation-vectors.json)에 수록된 모든 정상 케이스와 오류 케이스 적합성 테스트 벡터를 100% 통과해야 한다.
