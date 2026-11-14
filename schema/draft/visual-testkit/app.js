import { applyI18n, getLanguage, initI18n, languages, setLanguage, t } from "./i18n.js";

const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
const $ = (id) => document.getElementById(id);

const state = {
  scopeMode: "EXACT",
  lookup: "ifay",
  proofChallengeUsed: false,
  grantRevoked: false,
  grantIssued: false,
  dynamicIssuedAt: null,
  grantIssuedAt: null,
  verifierKey: "verifier.waiting",
  verifierMode: "neutral",
  attackOutput: null,
  steps: [],
};

const ids = {
  human: makeId("hid_", 52),
  ifay: makeId("ifay_", 40),
  cofay: makeId("cofay_", 40),
  org: "org_ifay-labs",
  verification: makeId("vrf_", 26),
  opaque: makeId("gmcref_", 52),
  dynamic: "",
  grant: "",
};

const refs = {
  baseResource: "https://api.ifay.example/app/read",
  wideResource: "https://api.ifay.example/application/admin",
};

function boot() {
  initLanguageControls();
  bindEvents();
  resetDemo();
}

function initLanguageControls() {
  const language = initI18n();
  $("language-select").innerHTML = languages
    .map((item) => `<option value="${item.code}">${item.name}</option>`)
    .join("");
  $("language-select").value = language || getLanguage();
  applyI18n();
}

function bindEvents() {
  $("language-select").addEventListener("change", (event) => {
    setLanguage(event.target.value);
    applyI18n();
    render();
    renderVerifierState();
    renderSteps();
    renderAttackOutput();
  });
  $("reset-demo").addEventListener("click", resetDemo);
  $("issue-dynamic").addEventListener("click", issueDynamicCode);
  $("exchange-grant").addEventListener("click", exchangeGrant);
  $("verify-grant").addEventListener("click", verifyGrant);
  $("verify-cofay").addEventListener("click", verifyCoFay);
  $("revoke-grant").addEventListener("click", revokeGrant);
  $("clear-log").addEventListener("click", () => ($("event-log").textContent = ""));
  $("scope-exact").addEventListener("click", () => setScope("EXACT"));
  $("scope-prefix").addEventListener("click", () => setScope("PREFIX"));
  $("lookup-ifay").addEventListener("click", () => setLookup("ifay"));
  $("lookup-cofay").addEventListener("click", () => setLookup("cofay"));
  $("lookup-org").addEventListener("click", () => setLookup("org"));
  document.querySelectorAll("[data-attack]").forEach((button) => {
    button.addEventListener("click", () => runAttack(button.dataset.attack));
  });
}

function resetDemo() {
  ids.dynamic = "";
  ids.grant = "";
  state.proofChallengeUsed = false;
  state.grantRevoked = false;
  state.grantIssued = false;
  state.dynamicIssuedAt = null;
  state.grantIssuedAt = null;
  state.verifierKey = "verifier.waiting";
  state.verifierMode = "neutral";
  state.attackOutput = null;
  state.steps = [];
  $("resource-ref").value = refs.baseResource;
  setScope("EXACT", false);
  render();
  setSteps([{ titleKey: "steps.waiting.title", bodyKey: "steps.waiting.body" }]);
  logEvent("demo.reset", { ifayID: ids.ifay, humanID: redact(ids.human) });
}

function issueDynamicCode() {
  ids.dynamic = makeId("dyn_", 28);
  state.dynamicIssuedAt = Date.now();
  state.proofChallengeUsed = true;
  render();
  setSteps([
    { titleKey: "steps.proofGenerated.title", bodyKey: "steps.proofGenerated.body" },
    { titleKey: "steps.proofAccepted.title", bodyKey: "steps.proofAccepted.body" },
    { titleKey: "steps.dynamicIssued.title", bodyKey: "steps.dynamicIssued.body" },
  ]);
  logEvent("dynamic.issued", {
    dynamicCodeHash: hashLabel(ids.dynamic),
    humanID: redact(ids.human),
  });
}

function exchangeGrant() {
  if (!ids.dynamic) {
    issueDynamicCode();
  }
  ids.grant = makeId("grt_", 30);
  state.grantIssued = true;
  state.grantRevoked = false;
  state.grantIssuedAt = Date.now();
  render();
  setSteps([
    { titleKey: "steps.legacyVerified.title", bodyKey: "steps.legacyVerified.body" },
    { titleKey: "steps.targetProof.title", bodyKey: "steps.targetProof.body" },
    { titleKey: "steps.bindingChecked.title", bodyKey: "steps.bindingChecked.body" },
    { titleKey: "steps.grantSigned.title", bodyKey: "steps.grantSigned.body" },
  ]);
  logEvent("grant.exchanged", {
    grantID: ids.grant,
    ifayID: ids.ifay,
    legacySubjectRef: "AUTHORIZATION:issuer:" + hashLabel("subject"),
    scopeMode: state.scopeMode,
  });
}

function verifyGrant() {
  if (!state.grantIssued) {
    setVerifier("verifier.blocked", "danger");
    setSteps([{ titleKey: "steps.noGrant.title", bodyKey: "steps.noGrant.body" }]);
    logEvent("grant.verify.denied", { reason: "missing_grant" });
    return;
  }

  if (state.grantRevoked) {
    setVerifier("verifier.revoked", "danger");
    setSteps([
      { titleKey: "steps.signatureValid.title", bodyKey: "steps.signatureValid.body" },
      { titleKey: "steps.stateLookup.title", bodyKey: "steps.stateRevoked.body" },
      { titleKey: "steps.accessDenied.title", body: "GRANT_REVOKED" },
    ]);
    logEvent("grant.verify.denied", { grantID: ids.grant, errorCode: "GRANT_REVOKED" });
    return;
  }

  const requestRef = $("resource-ref").value;
  const matches = matchResource(refs.baseResource, requestRef, state.scopeMode);
  if (!matches) {
    setVerifier("verifier.denied", "danger");
    setSteps([
      { titleKey: "steps.signatureValid.title", bodyKey: "steps.signaturePayload.body" },
      { titleKey: "steps.resourceFailed.title", bodyKey: "steps.resourceFailed.body", values: { scopeMode: state.scopeMode } },
      { titleKey: "steps.accessDenied.title", body: "GRANT_INVALID" },
    ]);
    logEvent("grant.verify.denied", { grantID: ids.grant, errorCode: "GRANT_INVALID" });
    return;
  }

  setVerifier("verifier.verified", "safe");
  setSteps([
    { titleKey: "steps.signatureValid.title", bodyKey: "steps.signatureCanonical.body" },
    { titleKey: "steps.stateLookup.title", bodyKey: "steps.stateActive.body" },
    { titleKey: "steps.resourceMatched.title", bodyKey: "steps.resourceMatched.body", values: { scopeMode: state.scopeMode } },
    { titleKey: "steps.accessAllowed.title", bodyKey: "steps.accessAllowed.body" },
  ]);
  logEvent("grant.verify.ok", { grantID: ids.grant, resourceRef: requestRef });
}

function verifyCoFay() {
  setVerifier("verifier.cofayOk", "safe");
  setSteps([
    { titleKey: "steps.cofayPresented.title", body: ids.cofay },
    { titleKey: "steps.verificationChecked.title", bodyKey: "steps.verificationChecked.body" },
    { titleKey: "steps.ownerReturned.title", bodyKey: "steps.ownerReturned.body" },
  ]);
  logEvent("cofay.verify.ok", {
    cofayID: ids.cofay,
    verificationCode: redact(ids.verification),
  });
}

function revokeGrant() {
  if (!state.grantIssued) return;
  state.grantRevoked = true;
  render();
  setVerifier("verifier.revoked", "danger");
  setSteps([
    { titleKey: "steps.revocationAccepted.title", bodyKey: "steps.revocationAccepted.body" },
    { titleKey: "steps.cacheCleared.title", bodyKey: "steps.cacheCleared.body" },
  ]);
  logEvent("grant.revoked", { grantID: ids.grant, state: "REVOKED" });
}

function runAttack(kind) {
  const attacks = {
    forgeGrant: ["attack.forge.title", "attack.forge.body"],
    replayProof: ["attack.replay.title", "attack.replay.body"],
    wideScope: ["attack.wide.title", "attack.wide.body"],
    leakHuman: ["attack.leak.title", "attack.leak.body"],
  };
  const [titleKey, bodyKey] = attacks[kind];
  state.attackOutput = { titleKey, bodyKey };
  renderAttackOutput();
  $("attack-state").textContent = t("attacks.blocked");
  logEvent("attack.blocked", { attack: kind, humanID: redact(ids.human) });
}

function setScope(mode, shouldRender = true) {
  state.scopeMode = mode;
  $("scope-exact").classList.toggle("selected", mode === "EXACT");
  $("scope-prefix").classList.toggle("selected", mode === "PREFIX");
  if (mode === "PREFIX") {
    $("resource-ref").value = "https://api.ifay.example/app/read/details";
  }
  if (shouldRender) render();
}

function setLookup(kind) {
  state.lookup = kind;
  $("lookup-ifay").classList.toggle("selected", kind === "ifay");
  $("lookup-cofay").classList.toggle("selected", kind === "cofay");
  $("lookup-org").classList.toggle("selected", kind === "org");
  renderDiscovery();
}

function render() {
  applyI18n();
  $("human-id").textContent = ids.human;
  $("ifay-id").textContent = ids.ifay;
  $("cofay-id").textContent = ids.cofay;
  $("org-id").textContent = ids.org;
  $("dynamic-code").textContent = ids.dynamic || t("artifact.notIssued");
  $("dynamic-ttl").textContent = ids.dynamic ? t("hint.dynamicTtl") : "";
  $("grant-id").textContent = ids.grant || t("artifact.notIssued");
  $("grant-state").textContent = state.grantIssued
    ? state.grantRevoked
      ? t("hint.grantRevoked")
      : t("hint.grantActive", { scopeMode: state.scopeMode })
    : "";
  renderVerifierState();
  renderSteps();
  renderDiscovery();
}

function renderDiscovery() {
  const input = state.lookup === "ifay" ? ids.ifay : state.lookup === "cofay" ? ids.cofay : ids.org;
  const owner =
    state.lookup === "org"
      ? ids.org
      : ids.opaque;
  $("lookup-input").textContent = input;
  $("owner-ref").textContent = owner;
  $("human-exposed").textContent = "0";
  $("secret-exposed").textContent = "0";
  $("opaque-count").textContent = state.lookup === "org" ? "0" : "1";
}

function setVerifier(key, mode) {
  state.verifierKey = key;
  state.verifierMode = mode;
  renderVerifierState();
}

function renderVerifierState() {
  const el = $("verifier-state");
  el.textContent = t(state.verifierKey);
  el.className = state.verifierMode === "safe" ? "badge safe" : state.verifierMode === "danger" ? "badge danger" : "badge";
}

function setSteps(steps) {
  state.steps = steps;
  renderSteps();
}

function renderSteps() {
  $("verify-steps").innerHTML = state.steps
    .map((step) => `<li><strong>${translateStepPart(step, "title")}</strong><span>${translateStepPart(step, "body")}</span></li>`)
    .join("");
}

function translateStepPart(step, part) {
  const key = step[`${part}Key`];
  return key ? t(key, step.values) : step[part] || "";
}

function renderAttackOutput() {
  if (!state.attackOutput) {
    $("attack-output").textContent = "";
    return;
  }
  $("attack-output").innerHTML = `<strong>${t(state.attackOutput.titleKey)}</strong><p>${t(state.attackOutput.bodyKey)}</p>`;
}

function logEvent(type, payload) {
  const safePayload = JSON.stringify(redactPayload(payload));
  $("event-log").textContent += `${new Date().toISOString()} ${type} ${safePayload}\n`;
  $("event-log").scrollTop = $("event-log").scrollHeight;
}

function redactPayload(payload) {
  return Object.fromEntries(
    Object.entries(payload).map(([key, value]) => {
      if (/human|mnemonic|private|verification|opaque|dynamiccode$/i.test(key)) {
        return [key, redact(String(value))];
      }
      return [key, value];
    }),
  );
}

function redact(value) {
  if (!value) return "[redacted]";
  return `${value.slice(0, 6)}…redacted`;
}

function hashLabel(value) {
  let hash = 0;
  for (const ch of value) hash = (hash * 31 + ch.charCodeAt(0)) >>> 0;
  return `h_${hash.toString(16).padStart(8, "0")}`;
}

function makeId(prefix, length) {
  let out = prefix;
  for (let i = 0; i < length; i += 1) {
    out += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  return out;
}

function matchResource(grantRef, requestRef, scopeMode) {
  const grant = normalizeUrl(grantRef);
  const request = normalizeUrl(requestRef);
  if (!grant || !request) return false;
  if (scopeMode === "EXACT") return grant.href === request.href;
  if (grant.origin !== request.origin) return false;
  const base = stripSlash(grant.pathname);
  const path = stripSlash(request.pathname);
  return path === base || path.startsWith(`${base}/`);
}

function normalizeUrl(value) {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function stripSlash(value) {
  return value.length > 1 ? value.replace(/\/+$/u, "") : value;
}

boot();
