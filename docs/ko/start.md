# FayID 1.0 빠른 시작 가이드

**FayID 1.0**(`2025-10-25` 정식판)은 iFay 생태계의 자기주권(Holder-of-Key) 책임 귀속 신원 프로토콜입니다. 모든 개인 `iFay`는 고유한 **Human Prime**(인간 프라임)과 `1:N` 양도 불가 관계로 결합되며, 공유 역할 `coFay`는 단일 계층에서 `HumanID` 또는 `OrganizationID`에 귀속되고, 루트 개인키는 로컬 **Host**(호스트 기기) 보안 경계 내부에만 유지됩니다.

## 1. 실행 환경 및 검증

참조 구현 [`src/fayid-toolkit.mjs`](../../src/fayid-toolkit.mjs)는 외부 런타임 의존성 없이 Node.js 20+ 내장 `node:crypto`(`Ed25519`, `SHA-256`, `HKDF-SHA256`, RFC 8785 JCS)만으로 동작합니다. 저장소 루트에서 전체 단위 테스트 및 적합성 벡터를 실행합니다.

```bash
npm test
```

## 2. 정규 식별자 접두사 요약

모든 암호화 식별자는 `<prefix>_<lowercase-rfc4648-base32-nopad>` 형식을 따릅니다(`org_`는 소문자 슬러그 `[a-z0-9-]+` 추가 허용).

| 접두사 | 엔티티 / 토큰 | 책임 귀속 및 프라이버시 원칙 |
| --- | --- | --- |
| `hid_` | `HumanID` | `Human Prime`의 루트 식별자(`SHA-256(publicKey)`); **로컬 Host 외부로 전송하거나 공개 로그에 기록하는 행위 엄격 금지** |
| `ifay_` | `IFayID` | 소유 `hid_`와 `1:N` 양도 불가로 결합된 개인 `iFay` 식별자 |
| `cofay_` | `CoFayID` | `hid_` 또는 `org_`가 단일 계층으로 소유하는 공유 `coFay`(관리 권한 `managers: iFayID[]` 직교 분리) |
| `org_` | `OrganizationID` | 자연인 `Steward`(`hid_`)가 지정된 조직 식별자(상호 동의 기반 단일 부모 비순환 트리) |
| `dyn_` | `DynamicCode` | 짧은 수명(`<= 600s`), 일회용 재전송 방지 및 비연결성 제시 토큰 |
| `grt_` / `vrf_` | `AuthorizationGrant` / `VerificationCode` | 범위 제한(`EXACT` / `PREFIX`) 인증 교환 권한 부여 및 오프라인 검증 가능한 Ed25519 영수증 |
| `gmcref_` | `OpaqueRef` | 공예체인(`GMChain`) 자연인 가중치 정규화를 위한 블라인드 앵커(`ifay.gmc.natural-person.v1`) |

## 3. Holder-of-Key Ed25519 신원 생성 예제

```js
import { randomBytes } from "node:crypto";
import {
  AccountDirectory,
  deriveEntityKeypair,
  deriveHumanIdentityFromSeed,
} from "../../src/fayid-toolkit.mjs";

const rootSeed = randomBytes(32); // 로컬 Host 보안 저장소 내부에만 보관
const human = deriveHumanIdentityFromSeed(rootSeed); // human.humanId => "hid_..." (외부 유출 금지)
const ifay = deriveEntityKeypair(rootSeed, "ifay", 0).value; // ifay.entityId => "ifay_..."

const directory = new AccountDirectory();
directory.registerHuman(human.humanId);
directory.registerIFay(ifay.entityId, human.humanId);

const dyn = directory.issueDynamicCode({
  subjectId: ifay.entityId,
  ttlSec: 120,
});
console.log("Outbound unlinkable token:", dyn.value.code); // "dyn_..."
```

## 4. 다음 단계

- **아키텍처 블루프린트**: [`./blueprint/`](./blueprint/) — 소유권과 관리 권한의 분리, 자격증명 수명주기, 인증 교환 설계 배경을 다룹니다.
- **정식 프로토콜 명세(Final 1.0)**: [`./specification/2025-10-25/README.md`](./specification/2025-10-25/README.md) — 규범 조항 전문, [`schemas/fayid-1.0.json`](../../schemas/fayid-1.0.json) 및 적합성 검증 기준을 확인할 수 있습니다.
