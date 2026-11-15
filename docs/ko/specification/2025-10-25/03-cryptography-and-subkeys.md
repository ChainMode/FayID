---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: ko
canonical: false
chapter: 3
---

# 제3장 자기주권 암호학 스위트 및 목적별 서브키 파생

## 3.1 자기주권 보유자 증명 신뢰 모델 (Normative)

FayID 1.0은 순수 자기주권 보유자 증명(Self-Sovereign Holder-of-Key) 신뢰 모델을 채택한다:

1. 신원의 생성과 통제는 전적으로 대응하는 Ed25519 개인 키의 보유 증명에 달려 있으며, 어떠한 중앙 등록 기관의 서명에도 의존하지 않는다.
2. 특정 `HumanID`, `iFayID`, `coFayID` 또는 `OrganizationID`를 보유하거나 그에 귀속됨을 주장하는 모든 상태 변경 작업(등록, 위임, 계층 마운트, 소유권 이전, 폐기)에는 대응하는 통제 키로 생성한 유효한 암호학적 증명을 **반드시 첨부해야 한다**. 증명이 누락되거나 서명 검증에 실패하면 **반드시** 요청을 거부하고 `HUMAN_ID_OWNERSHIP_NOT_PROVEN`, `OWNERSHIP_NOT_PROVEN` 또는 `TARGET_OWNERSHIP_NOT_PROVEN`을 반환해야 한다.

## 3.2 필수 암호학 알고리즘 목록 (Normative)

FayID 1.0은 외부 블랙박스 의존성이 없는 다음 표준 암호학 프리미티브 조합을 고정 채택한다:

| 용도 | 필수 알고리즘 | 규범 출력 크기 |
| --- | --- | --- |
| 비대칭 서명 및 보유자 증명 | Ed25519(RFC 8032 PureEdDSA) | 32바이트 원시 공개 키, 64바이트 서명 |
| 식별자 다이제스트 및 커밋먼트 계산 | SHA-256(FIPS 180-4) | 32바이트 다이제스트 |
| 결정론적 서브키 파생 | HKDF-SHA256(RFC 5869) | 32바이트 목적별 시드 |
| 레거시 주체 해시 및 동적 코드 검증 | HMAC-SHA256(RFC 2104) | 32바이트 메시지 인증 코드(필요시 20바이트로 절단) |
| JSON 서명 페이로드 정규화 | JCS(RFC 8785 JSON Canonicalization Scheme) | UTF-8 결정론적 바이트 시퀀스 |

마스터 시드(`masterSeed`)와 블라인드 솔트(`userBlindSalt`)의 원시 엔트로피 길이는 **반드시 256비트(32바이트) 이상**이어야 한다. 32바이트 미만의 입력은 **반드시** 거부하고 `INSUFFICIENT_ENTROPY`를 반환해야 한다.

## 3.3 HKDF-SHA256 도메인 분리 목적별 서브키 파생 (Normative)

루트 개인 키와 마스터 시드가 고빈도 서명 작업이나 외부 프로토콜 패키징 절차에 직접 노출되지 않도록 보장하기 위해, 보유자 에이전트는 **반드시** 32바이트 이상의 마스터 시드로부터 HKDF-SHA256을 통해 암호학적으로 상호 격리된 32바이트 목적별 서브키를 파생해야 한다:

```text
subkeySeed32 = HKDF-SHA256(
  ikm  = masterSeedBytes,
  salt = SHA-256(UTF8("fayid.subkey.salt:" || domain)),
  info = UTF8(domain || ":" || context),
  len  = 32
)
```

사양은 보호되는 5종의 도메인 분리 상수(`SubkeyDomain`)를 정의한다:

| 상수명 | 도메인 분리 문자열(`domain`) | 용도 및 보안 경계 |
| --- | --- | --- |
| `ENTITY` | `ifay.fayid.entity.v1` | `HumanID`, `iFay`, `coFay`, `OrganizationID`의 엔티티 통제용 Ed25519 키 쌍 파생 |
| `EGO_PACKAGE_SIGNING` | `ifay.ego.package-signing.v1` | `.ego` 인격/상태 아웃바운드 파일 패키지 서명 전용 Ed25519 서명 서브키 |
| `DYNAMIC_CODE` | `ifay.fayid.dynamic-code.v1` | 동적 코드 발급 및 검증 컨텍스트용 대칭 키 자료 파생 |
| `AUTH_EXCHANGE` | `ifay.fayid.auth-exchange.v1` | 인증 교환 권한 부여(`grt_`) 및 검증 영수증(`vrf_`) 서명 키 자료 파생 |
| `GMC_NATURAL_PERSON` | `ifay.gmc.natural-person.v1` | `GMChain`용 자연인 블라인드 앵커 의사난수 키 자료 파생 |

구현체는 **반드시** 다음 두 가지 강제 격리 제약을 준수해야 한다:

1. **강제 도메인 검사**: 서브키 파생 인터페이스를 호출할 때 `domain`과 `context`는 **반드시** 비어 있지 않은 문자열이어야 하며, `domain`은 **반드시** 알려진 통제 도메인 집합에 속해야 한다. 적법한 도메인 분리 식별자를 제공하지 않은 호출은 **반드시** 거부하고 `DOMAIN_SEPARATION_REQUIRED`를 반환해야 한다.
2. **Ego 패키지 루트 키 외부 유출 제로(Root-Key Isolation)**: `.ego` 아웃바운드 패키지에 서명할 때 구현체는 **반드시** `ifay.ego.package-signing.v1`에서 파생된 서브키만 사용하여 서명 엔벨로프(`version: "1.0"`, `domain: "ifay.ego.package-signing.v1"`, `signerFayId`, `keyId`, `signingPublicKeyHex`, `manifestDigestSha256`, `signedAt`, `signatureHex` 포함)를 생성해야 한다. 어떠한 아웃바운드 패키지, 공개 엔티티 레코드 또는 검증 영수증에도 `masterSeed`, `seed`, `privateKey`, `secretKey` 또는 `mnemonic` 등의 개인 키 자료 필드가 **절대 포함되어서는 안 된다**. 검증자는 개인 키 자료가 담긴 아웃바운드 엔벨로프를 발견하면 **반드시** 규약 위반으로 판정하고 거부해야 한다.

## 3.4 RFC 8785 JCS 정규화 서명 규약 (Normative)

구현 간 검증이 이루어지는 모든 구조화된 서명 페이로드(소유권 바인딩 증명, 양방향 계층 합의서, Ego 패키지 매니페스트 서명 페이로드 및 `vrf_` 검증 영수증 서명 페이로드 포함)는 Ed25519 `sign` / `verify` 또는 SHA-256에 입력하기 전에 **반드시** RFC 8785 JCS를 거쳐 유일하게 결정되는 UTF-8 바이트열로 정규화해야 한다:

1. 객체 프로퍼티 키는 UTF-16 코드 유닛 사전순 오름차순으로 정렬하며, 값이 `undefined`인 선택적 키는 직렬화 전에 생략한다.
2. 숫자는 ECMAScript 사양의 최소 무모호성 10진수 표현을 따른다(`-0`은 `"0"`으로 정규화하며, `NaN`과 `Infinity`는 금지한다).
3. 배열 원소의 순서는 엄격히 유지하며, 문자 이스케이프는 표준 최소 JSON 이스케이프 규칙을 따르고 키 이름과 구분자 사이에 불필요한 공백을 일절 두지 않는다.
