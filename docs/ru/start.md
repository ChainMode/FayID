# Быстрый старт FayID 1.0

**FayID 1.0** (финальная редакция `2025-10-25`) — протокол суверенной подотчётной идентичности с владением ключом (*Holder-of-Key*) в экосистеме iFay. Каждый индивидуальный `iFay` неотчуждаемо связан в отношении `1:N` с единственным **Human Prime**, каждый ролевой `coFay` на одном уровне владения принадлежит `HumanID` или `OrganizationID`, а корневые закрытые ключи никогда не покидают защищённый контур локального устройства **Host**.

## 1. Требования и локальная проверка

Эталонная реализация в [`src/fayid-toolkit.mjs`](../../src/fayid-toolkit.mjs) использует только встроенный модуль `node:crypto` Node.js 20+ (`Ed25519`, `SHA-256`, `HKDF-SHA256`, RFC 8785 JCS) без внешних зависимостей времени выполнения. Запустите модульные тесты и векторы соответствия из корня репозитория:

```bash
npm test
```

## 2. Канонические префиксы идентификаторов

Все криптографические идентификаторы кодируются в формате `<prefix>_<lowercase-rfc4648-base32-nopad>` (для `org_` дополнительно допустимы строчные символы `[a-z0-9-]+`):

| Префикс | Сущность / токен | Правило подотчётности и приватности |
| --- | --- | --- |
| `hid_` | `HumanID` | Корневая идентичность `Human Prime` (`SHA-256(publicKey)`); **никогда не передаётся за пределы локального Host и не пишется в логи** |
| `ifay_` | `IFayID` | Индивидуальный `iFay`, неотчуждаемо привязанный `1:N` к своему `hid_` |
| `cofay_` | `CoFayID` | Общий ролевой `coFay` с одноуровневым владельцем (`hid_` или `org_`) и ортогональным списком управляющих `managers: iFayID[]` |
| `org_` | `OrganizationID` | Организация с представителем — физическим лицом `Steward` (`hid_`) в однородительском ациклическом дереве по взаимному согласию |
| `dyn_` | `DynamicCode` | Короткоживущий (`<= 600s`) одноразовый несвязываемый токен предъявления с защитой от повтора |
| `grt_` / `vrf_` | `AuthorizationGrant` / `VerificationCode` | Ограниченный по ресурсу (`EXACT` / `PREFIX`) мандат обмена учётных данных и автономно проверяемая квитанция Ed25519 |
| `gmcref_` | `OpaqueRef` | Слепой якорь физического лица (`ifay.gmc.natural-person.v1`) для нормализации веса в `GMChain` |

## 3. Создание идентичности Ed25519 «Holder-of-Key»

```js
import { randomBytes } from "node:crypto";
import {
  AccountDirectory,
  deriveEntityKeypair,
  deriveHumanIdentityFromSeed,
} from "../../src/fayid-toolkit.mjs";

const rootSeed = randomBytes(32); // Хранится исключительно внутри защищённого контура локального Host
const human = deriveHumanIdentityFromSeed(rootSeed); // human.humanId => "hid_..." (без внешней передачи)
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

## 4. Дальнейшее чтение

- **Архитектурный план**: [`./blueprint/`](./blueprint/) раскрывает разделение владения и полномочий, жизненный цикл учётных данных и протокол Auth Exchange.
- **Нормативная спецификация (Final 1.0)**: [`./specification/2025-10-25/README.md`](./specification/2025-10-25/README.md) содержит все нормативные главы, схему [`schemas/fayid-1.0.json`](../../schemas/fayid-1.0.json) и требования соответствия.
