---
protocol: fayid
version: "1.0"
status: Final
date: 2025-10-25
edition: 2025-10-25
language: ko
canonical: false
---

# FayID 1.0 프로토콜 사양

FayID는 iFay 생태계의 자기주권(Self-Sovereign / Holder-of-Key) 책임 신원 프로토콜이다. 본 프로토콜은 중앙화된 신원 발급 기관(CA / IdP)에 의존하지 않고 모든 개인 디지털 분신(`iFay`)을 유일한 **인간 프라임**(`Human Prime`, `hid_`)에 일대다 양도 불가 방식으로 바인딩하며, 모든 공유 역할 디지털 엔티티(`coFay`)를 책임을 물을 수 있는 단일 `HumanID`(`hid_`) 또는 `OrganizationID`(`org_`)에 단일 계층으로 직결 귀속한다.

본 디렉터리는 **FayID 1.0 정식판(Final, 편집 판본 `2025-10-25`)**의 한국어 번역 사양을 수록한다. 본 번역본은 정본인 중국어 간체(`zh-CN`) 사양과 장 및 조항 단위로 일대일 대응하며, 언어 간 의미 해석에 차이가 발생할 경우 중국어 간체 정본을 최종 기준으로 삼는다.

## 사양 장별 목차

| 장 | 파일 | 핵심 범위 |
| --- | --- | --- |
| 제1장 | [01-conventions-and-versioning.md](./01-conventions-and-versioning.md) | 적용 범위, RFC 2119 / RFC 8174 규범적 키워드와 한국어 서술어 매핑, 핵심 용어 정의, 2단계 `1.0` 프로토콜 버전 및 협상 규칙 |
| 제2장 | [02-identifiers-and-encoding.md](./02-identifiers-and-encoding.md) | 8종 규범 접두사와 무패딩 소문자 RFC 4648 Base32 인코딩, 엄격 거부 및 왕복 불변성, `resourceRef` 정규화와 매칭, 64자리 16진수 호환 브리징 |
| 제3장 | [03-cryptography-and-subkeys.md](./03-cryptography-and-subkeys.md) | 자기주권 Ed25519 보유자 증명 아키텍처, 마스터 시드 엔트로피 요건, HKDF-SHA256 도메인 분리 목적별 서브키 파생(`ifay.ego.package-signing.v1` 포함), RFC 8785 JCS 정규화 서명 |
| 제4장 | [04-entities-ownership-and-hierarchy.md](./04-entities-ownership-and-hierarchy.md) | 4종 주체, `HumanID : iFayID = 1:N` 바인딩, 단일 계층 `coFay` 소유권과 `managers` 직교 권한 부여, 자연인 `Steward`, 양방향 합의 기반 단일 상위 무순환 조직 계층 트리 |
| 제5장 | [05-dynamic-codes-and-auth-exchange.md](./05-dynamic-codes-and-auth-exchange.md) | 비연관 동적 코드(`dyn_`) 발급 및 재전송 방지 검증, 레거시 자격 증명 HMAC 주체 바인딩, 범위 지정 인증 권한 부여 자격 증명(`grt_`), 검증 영수증(`vrf_`) 및 연쇄 폐기 |
| 제6장 | [06-privacy-gmc-and-conformance.md](./06-privacy-gmc-and-conformance.md) | 아웃바운드 페이로드 및 로그 비식별화 절대 금지선, `공예체인`(`GMChain`) 읽기 전용 경계와 블라인드 자연인 앵커(`gmcref_`), 24개 규범 오류 코드 레지스트리 및 적합성 판정 요건 |

## 부속 규범 산출물

| 산출물 경로 | 설명 |
| --- | --- |
| [schemas/fayid-1.0.json](../../../../schemas/fayid-1.0.json) | FayID 1.0 동결판 JSON Schema(Draft 2020-12, `version: "1.0"` 강제) |
| [schema/2025-10-25/schema.json](../../../../schema/2025-10-25/schema.json) | `schemas/fayid-1.0.json`과 바이트 단위로 동기화된 버전별 Schema 미러 |
| [schema/2025-10-25/schema.ts](../../../../schema/2025-10-25/schema.ts) | TypeScript 규범 상수 및 타입 정의 미러 |
| [src/fayid-toolkit.mjs](../../../../src/fayid-toolkit.mjs) | 외부 런타임 의존성이 없는 Node.js `node:crypto` 참조 구현 |
| [vectors/](../../../../vectors/) | 구현 간 결정론적 적합성 테스트 벡터(`account-hierarchy-vectors.json` 및 `crypto-and-revocation-vectors.json`) |
