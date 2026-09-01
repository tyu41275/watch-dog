const MAX_ITEMS = 16;
const GOOGLE_ADVISORY = "https://transparencyreport.google.com/safe-browsing/search";
const text = (value, maximum = 2048) => String(value ?? "").slice(0, maximum);
const record = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
const exactKeys = (value, expected) => {
  const keys = Object.keys(value).sort(); return keys.length === expected.length &&
    keys.every((key, index) => key === expected[index]);
};
const literal = (value, allowed) => typeof value === "string" && allowed.includes(value);
const bounded = (value, maximum = 2048) => typeof value === "string" && value.length <= maximum;
const timestamp = (value, nullable = false) => (nullable && value === null) ||
  (bounded(value, 32) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value);
function canonical(value) {
  if (!bounded(value)) return false;
  try { const url = new URL(value); return ["http:", "https:"].includes(url.protocol) &&
    url.username === "" && url.password === "" && url.port === "" && url.hash === "" && url.href === value; }
  catch { return false; }
}
const resultKeys = ["analysis_state", "canonical_target", "confidence", "contradicting_evidence",
  "limitations", "mode", "provider_observations", "risk_label", "scan_id", "supporting_evidence"];
const evidenceKey = (item) => [item.source, item.target, item.category, item.observed_at,
  item.freshness, item.reference ?? ""].join("\u0000");
export function validScanResult(value, scanId = value?.scan_id) {
  const categories = ["malware", "social_engineering", "unwanted_software", "potentially_harmful_application"];
  if (!record(value) || !exactKeys(value, resultKeys) || value.scan_id !== scanId ||
    !/^[a-f0-9]{32}$/u.test(value.scan_id) || !literal(value.mode, ["paste_url", "paste_html", "live_page"]) ||
    !literal(value.risk_label, ["known_malicious", "suspicious", "no_known_match", "unknown"]) ||
    !literal(value.analysis_state, ["complete", "unknown", "unscannable", "provider_error", "stale", "conflicting"]) ||
    !literal(value.confidence, ["high", "medium", "low"]) || !Array.isArray(value.supporting_evidence) ||
    !Array.isArray(value.contradicting_evidence) || !Array.isArray(value.provider_observations) ||
    !Array.isArray(value.limitations) || [value.supporting_evidence, value.contradicting_evidence,
      value.provider_observations, value.limitations].some((items) => items.length > MAX_ITEMS) ||
    !value.limitations.every((item) => bounded(item, 512) &&
      !/\b(?:safe|secure|clean|harmless|trustworthy|no threats?)\b/iu.test(item))) return false;
  const provider = (item) => {
    if (!record(item) || !exactKeys(item, ["category", "confidence", "error", "expires_at", "freshness",
      "observed_at", "provider", "queried_target", "reference", "source", "state"]) ||
      item.provider !== "google_safe_browsing" || !literal(item.source, ["live", "fixture"]) ||
      item.queried_target !== value.canonical_target || !canonical(item.queried_target) ||
      !timestamp(item.observed_at) || !timestamp(item.expires_at, true) ||
      !literal(item.freshness, ["fresh", "stale", "unknown"]) ||
      !literal(item.state, ["match", "no_match", "error", "not_configured"]) ||
      (item.reference !== null && !bounded(item.reference))) return false;
    if (item.state === "match" || item.state === "no_match") return item.error === null &&
      (item.state === "match" ? literal(item.category, categories) : item.category === null) &&
      (item.source !== "live" || (item.state === "match" ? item.reference === GOOGLE_ADVISORY : item.reference === null)) &&
      (item.expires_at === null ? item.freshness === "unknown" :
        Date.parse(item.expires_at) >= Date.parse(item.observed_at) && item.freshness !== "unknown") &&
      item.confidence === (item.freshness === "fresh" ? "medium" : "low");
    return item.category === null && item.expires_at === null && item.freshness === "unknown" &&
      item.confidence === "low" && item.reference === null &&
      (item.state === "not_configured" ? item.error === "not_configured" :
        literal(item.error, ["timeout", "quota", "unavailable", "malformed_response"]));
  };
  if (!value.provider_observations.every(provider)) return false;
  const providerEvidence = value.provider_observations.filter(({ state }) => ["match", "no_match"].includes(state))
    .map((item) => ({ source: `${item.source}:${item.provider}`, target: item.queried_target,
      category: item.state === "match" ? item.category : "no_known_match", observed_at: item.observed_at,
      freshness: item.freshness, reference: item.reference }));
  const evidence = (item) => record(item) && exactKeys(item,
    ["category", "freshness", "observed_at", "reference", "source", "target"]) &&
    item.target === value.canonical_target && canonical(item.target) && timestamp(item.observed_at) &&
    literal(item.freshness, ["fresh", "stale", "unknown"]) && (item.reference === null || bounded(item.reference)) &&
    (item.source === `candidate:${value.mode}` ? item.category === "misleading_url_like_text" &&
      item.freshness === "fresh" && bounded(item.reference) :
      providerEvidence.some((expected) => evidenceKey(expected) === evidenceKey(item)));
  const supporting = value.supporting_evidence; const contradicting = value.contradicting_evidence;
  if (![...supporting, ...contradicting].every(evidence) ||
    contradicting.some(({ source }) => source.startsWith("candidate:"))) return false;
  const candidates = supporting.filter(({ source }) => source.startsWith("candidate:"));
  const freshMatches = value.provider_observations.filter((item) => item.state === "match" && item.freshness === "fresh");
  const freshNoMatches = value.provider_observations.filter((item) => item.state === "no_match" && item.freshness === "fresh");
  const stale = value.provider_observations.filter((item) => ["match", "no_match"].includes(item.state) && item.freshness !== "fresh");
  const errors = value.provider_observations.filter((item) => ["error", "not_configured"].includes(item.state));
  const risk = freshMatches.length ? "known_malicious" : candidates.length ? "suspicious" :
    freshNoMatches.length ? "no_known_match" : "unknown";
  const state = freshMatches.length && freshNoMatches.length ? "conflicting" :
    freshMatches.length || freshNoMatches.length ? "complete" : stale.length ? "stale" :
      errors.length ? "provider_error" : "unknown";
  const contradiction = risk === "no_known_match" ? value.provider_observations.some(({ state }) => state === "match") :
    value.provider_observations.some(({ state }) => state === "no_match");
  const confidence = state !== "conflicting" && !errors.length && !contradiction && risk === "known_malicious"
    ? (candidates.length ? "high" : "medium") : state !== "conflicting" && !errors.length &&
      !contradiction && risk === "no_known_match" ? "medium" : "low";
  const expectedSupporting = risk === "no_known_match" ? providerEvidence.filter(({ category }) => category === "no_known_match") :
    [...candidates, ...providerEvidence.filter(({ category }) => category !== "no_known_match")];
  const expectedContradicting = risk === "no_known_match" ? providerEvidence.filter(({ category }) => category !== "no_known_match") :
    providerEvidence.filter(({ category }) => category === "no_known_match");
  const same = (actual, expected) => actual.length === expected.length && new Set(actual.map(evidenceKey)).size === actual.length &&
    actual.every((item) => expected.some((wanted) => evidenceKey(wanted) === evidenceKey(item)));
  if (value.canonical_target === null) return value.analysis_state === "unscannable" && value.risk_label === "unknown" &&
    value.confidence === "low" && supporting.length === 0 && contradicting.length === 0 && value.provider_observations.length === 0;
  return canonical(value.canonical_target) && value.analysis_state !== "unscannable" && value.risk_label === risk &&
    value.analysis_state === state && value.confidence === confidence && same(supporting, expectedSupporting) &&
    same(contradicting, expectedContradicting);
}
export function validResultEnvelope(value, scanId) {
  return record(value) && exactKeys(value, ["result", "status"]) && value.status === "ok" &&
    validScanResult(value.result, scanId);
}
function element(tag, className, value) {
  const node = document.createElement(tag); if (className) node.className = className;
  if (value !== undefined) node.textContent = text(value);
  return node;
}
function evidenceList(title, items) {
  const section = element("section", "evidence-group"); section.append(element("h4", "", title));
  const list = element("ul", "evidence");
  for (const item of Array.isArray(items) ? items.slice(0, MAX_ITEMS) : []) {
    const description = [item?.source, item?.category, item?.freshness, item?.target]
      .filter((part) => typeof part === "string").map((part) => text(part, 512)).join(" · ");
    list.append(element("li", "", description || "Unavailable evidence detail"));
  }
  if (!list.childNodes.length) list.append(element("li", "", "None recorded.")); section.append(list);
  return section;
}
function verdicts(result) {
  const list = element("dl", "verdicts");
  for (const [label, value] of [
    ["Risk", result.risk_label], ["State", result.analysis_state], ["Confidence", result.confidence],
  ]) {
    const group = element("div"); group.append(element("dt", "", label), element("dd", "", value));
    list.append(group);
  }
  return list;
}
function providerList(observations) {
  const section = element("section"); section.append(element("h4", "", "Provider observations"));
  const list = element("ul", "evidence");
  for (const item of Array.isArray(observations) ? observations.slice(0, MAX_ITEMS) : []) {
    list.append(element("li", "", [item?.provider, item?.state, item?.freshness,
      item?.category, item?.error, item?.reference,
      item?.provider === "google_safe_browsing" && item?.source === "live" && item?.state === "match" && item?.reference === GOOGLE_ADVISORY
        ? "Advisory provided by Google" : null]
      .filter(Boolean).map((value) => text(value, 2048)).join(" · ")));
  }
  if (!list.childNodes.length) list.append(element("li", "", "No provider observation."));
  section.append(list);
  return section;
}
export function renderResults(container, results) {
  if (!Array.isArray(results) || results.some((result) => !validScanResult(result))) {
    container.hidden = true; throw new Error("malformed_response");
  }
  for (const old of container.querySelectorAll(".result-grid, .trust-note")) old.remove();
  const note = element("p", "trust-note", "Page, URL, and provider strings below are untrusted evidence rendered as inert text.");
  const grid = element("div", "result-grid");
  for (const result of Array.isArray(results) ? results.slice(0, MAX_ITEMS) : []) {
    const card = element("article", "result-card");
    card.dataset.scanId = text(result?.scan_id, 64);
    card.append(element("h3", "break", result?.canonical_target || "Unscannable input"), verdicts(result ?? {}),
      evidenceList("Supporting evidence", result?.supporting_evidence),
      evidenceList("Contradicting evidence", result?.contradicting_evidence), providerList(result?.provider_observations));
    card.append(evidenceList("Limitations", (result?.limitations ?? []).map((category) => ({ category }))));
    grid.append(card);
  }
  if (!grid.childNodes.length) grid.append(element("p", "", "No result records were returned."));
  container.append(note, grid);
  container.hidden = false;
}
