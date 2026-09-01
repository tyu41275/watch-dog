const MODES = ["paste_url", "paste_html", "live_page"]; const ERRORS = ["timeout", "quota", "unavailable", "malformed_response", "not_configured"];
const BASIC = ["empty_input", "missing_base_url", "invalid_url", "unsupported_scheme", "credentials_not_allowed", "disallowed_port"];
const FETCH = ["url_too_long", "unsafe_address", "dns_failure", "mixed_address", "redirect_missing_location", "redirect_loop", "redirect_limit", "timeout", "response_too_large", "unsupported_content_type", "unsupported_content_encoding", "fetch_failed", "invalid_response", "input_too_large", "no_candidates"];
const LIMITS = Object.freeze({ confidence_basis: "Confidence describes evidence completeness, independence, freshness, and agreement—not likelihood of harm.", misleading_display_text: "URL-like displayed text resolves to a different target than the link destination.", provider_no_match_scope: "A current no-match means only that the provider returned no known match; it does not assess all risks.", provider_match_scope: "A recognized provider match is qualified evidence for its category, not a complete risk inventory.",
  stale_observation: "Expired or freshness-unknown observations are shown but are not treated as current evidence.", provider_unavailable: "At least one provider lookup did not return usable evidence.", no_provider_observation: "No provider observation was available.", conflicting_observations: "Current provider observations materially disagree.", results_truncated: "Only the first 16 bounded results were retained." });
const OUTCOMES = Object.freeze({ unscannable: ["unknown", "unscannable", "low"], unknown: ["unknown", "unknown", "low"], unknown_stale: ["unknown", "stale", "low"], unknown_provider_error: ["unknown", "provider_error", "low"], suspicious: ["suspicious", "unknown", "low"], suspicious_stale: ["suspicious", "stale", "low"], suspicious_provider_error: ["suspicious", "provider_error", "low"], suspicious_complete: ["suspicious", "complete", "low"],
  known_malicious_high: ["known_malicious", "complete", "high"], known_malicious_medium: ["known_malicious", "complete", "medium"], known_malicious_low: ["known_malicious", "complete", "low"], known_malicious_conflicting: ["known_malicious", "conflicting", "low"], no_known_match_medium: ["no_known_match", "complete", "medium"], no_known_match_low: ["no_known_match", "complete", "low"] });
const rec = (v) => typeof v === "object" && v !== null && !Array.isArray(v), exact = (v, keys) => rec(v) && Object.keys(v).sort().join() === [...keys].sort().join();
const integer = (v) => Number.isSafeInteger(v) && v >= 0, scanId = (v) => typeof v === "string" && /^[a-f0-9]{32}$/u.test(v), time = (v) => typeof v === "string" && Number.isFinite(Date.parse(v)), fail = () => { throw new Error("malformed_response"); };
function canonical(v) { if (typeof v !== "string" || v.length > 2048) return false; try { const u = new URL(v); return ["http:", "https:"].includes(u.protocol) && !u.username && !u.password && !u.port && !u.hash && u.href === v; } catch { return false; } }
export function decodeSession(v) { if (!exact(v, ["authenticated", "csrf_token", "expires_at"]) || v.authenticated !== true || typeof v.csrf_token !== "string" || !/^[A-Za-z0-9_-]{32}$/u.test(v.csrf_token) || !time(v.expires_at)) fail(); return { csrf: v.csrf_token, expiresAt: v.expires_at }; }
function receiptBase(d, v, targets = [], rejections = []) { if (!Array.isArray(v.scan_ids) || v.scan_ids.length > 16 || !v.scan_ids.every(scanId) || new Set(v.scan_ids).size !== v.scan_ids.length ||
  !integer(v.accepted_targets) || !integer(v.rejected_candidates) || typeof v.truncated !== "boolean") fail(); const count = Math.max(1, v.accepted_targets + v.rejected_candidates);
  if (v.scan_ids.length !== Math.min(count, 16) || v.truncated !== (count > 16)) fail(); return { request: { ...d }, mode: v.mode, scanIds: [...v.scan_ids],
    acceptedTargets: v.accepted_targets, rejectedCandidates: v.rejected_candidates, truncated: v.truncated, unscannableReason: v.unscannable_reason ?? null, targets, rejections }; }
function trace(v, requested, completed) { if (!exact(v, ["requested_url", "final_url", "redirect_chain", "validated_hops"]) || !(v.requested_url === "" || canonical(v.requested_url)) ||
  !(v.final_url === "" || canonical(v.final_url)) || !Array.isArray(v.redirect_chain) || v.redirect_chain.length > 5 || !v.redirect_chain.every(canonical) || !Array.isArray(v.validated_hops)) fail();
  let expected = ""; try { const u = new URL(requested); u.hash = ""; if (["http:", "https:"].includes(u.protocol) && !u.username && !u.password && !u.port) expected = u.href; } catch {} const urls = [v.requested_url, ...v.redirect_chain];
  if (v.requested_url !== expected || v.final_url !== urls.at(-1) || v.validated_hops.length > urls.length || completed && v.validated_hops.length !== urls.length ||
    !v.validated_hops.every((hop, i) => exact(hop, ["hostname", "address_count"]) && typeof hop.hostname === "string" && integer(hop.address_count) && hop.address_count > 0 && urls[i] && new URL(urls[i]).hostname === hop.hostname)) fail(); }
export function decodeReceipt(d, v) { if (!rec(d) || !rec(v) || v.mode !== d.kind || d.kind === "paste_url" && !exact(d, ["kind", "requestedUrl"]) ||
  d.kind === "paste_html" && !exact(d, ["kind"]) || d.kind === "live_page" && (!exact(d, ["kind", "observedCandidates"]) || !integer(d.observedCandidates) || d.observedCandidates > 32)) fail();
  const common = ["accepted_targets", "mode", "rejected_candidates", "scan_ids", "truncated", "unscannable_reason"];
  if (d.kind === "paste_url") { if (!exact(v, [...common, "fetch_evidence"]) || typeof d.requestedUrl !== "string") fail(); trace(v.fetch_evidence, d.requestedUrl, v.accepted_targets + v.rejected_candidates > 0 || v.unscannable_reason === "no_candidates"); }
  else if (d.kind === "paste_html") { if (!exact(v, common)) fail(); } else if (d.kind === "live_page") { if (!exact(v, ["mode", "scan_ids", "observed_candidates", "accepted_targets", "rejected_candidates", "truncated", "page_evidence_trust", "targets", "rejections"]) ||
    v.page_evidence_trust !== "untrusted" || v.observed_candidates !== d.observedCandidates || !Array.isArray(v.targets) || !Array.isArray(v.rejections)) fail(); const indices = [];
    for (const t of v.targets) { if (!exact(t, ["canonical_url", "occurrence_indices", "anchor_text_variants"]) || !canonical(t.canonical_url) ||
      !Array.isArray(t.occurrence_indices) || !t.occurrence_indices.length || !t.occurrence_indices.every(integer) || !Array.isArray(t.anchor_text_variants) ||
      t.anchor_text_variants.length > t.occurrence_indices.length || new Set(t.anchor_text_variants).size !== t.anchor_text_variants.length ||
      !t.anchor_text_variants.every((x) => typeof x === "string" && x.trim() === x && x.length <= 512)) fail(); indices.push(...t.occurrence_indices); }
    for (const r of v.rejections) { if (!exact(r, ["occurrence_index", "reason"]) || !integer(r.occurrence_index) || ![...BASIC.filter((x) => x !== "missing_base_url"), "url_too_long"].includes(r.reason)) fail(); indices.push(r.occurrence_index); }
    if (v.targets.length !== Math.min(v.accepted_targets, 16) || v.rejections.length !== Math.min(v.rejected_candidates, 16) ||
      v.accepted_targets + v.rejected_candidates > v.observed_candidates || new Set(indices).size !== indices.length ||
      indices.some((x) => x >= v.observed_candidates) || !v.truncated && indices.length !== v.observed_candidates || !v.truncated &&
      indices.sort((a, b) => a - b).some((x, i) => x !== i) || new Set(v.targets.map((t) => t.canonical_url)).size !== v.targets.length) fail();
    return receiptBase(d, v, v.targets.map((t) => t.canonical_url), v.rejections.map((r) => r.reason)); }
  else fail(); const reasons = d.kind === "paste_html" ? [...BASIC.filter((x) => x !== "missing_base_url"), "url_too_long", "input_too_large", "no_candidates"] : [...BASIC, ...FETCH.filter((x) => x !== "input_too_large")];
  if (v.accepted_targets + v.rejected_candidates > 256 || v.unscannable_reason !== null && !reasons.includes(v.unscannable_reason) ||
    (v.unscannable_reason !== null) !== (v.accepted_targets === 0 && v.rejected_candidates <= 1)) fail(); return receiptBase(d, v); }
function observation(v, target) { if (!exact(v, ["provider", "source", "queried_target", "observed_at", "expires_at", "freshness", "state",
  "category", "confidence", "reference", "error"]) || v.provider !== "google_safe_browsing" || !["live", "fixture"].includes(v.source) ||
  v.queried_target !== target || !time(v.observed_at) || !["fresh", "stale", "unknown"].includes(v.freshness) ||
  !["match", "no_match", "error", "not_configured"].includes(v.state)) fail(); const resolved = ["match", "no_match"].includes(v.state);
  if (v.error !== null && !ERRORS.includes(v.error) || resolved !== (v.error === null) || (v.state === "match") !== ["malware", "social_engineering", "unwanted_software", "potentially_harmful_application"].includes(v.category) ||
    v.state !== "match" && v.category !== null || (v.state === "not_configured") !== (v.error === "not_configured") || !resolved &&
    (v.expires_at !== null || v.freshness !== "unknown" || v.confidence !== "low" || v.reference !== null) || resolved && (v.expires_at === null ?
      v.freshness !== "unknown" || v.confidence !== "low" : !time(v.expires_at) || Date.parse(v.expires_at) < Date.parse(v.observed_at) ||
      !["fresh", "stale"].includes(v.freshness) || v.confidence !== (v.freshness === "fresh" ? "medium" : "low")) || v.source === "live" &&
    (v.state === "match" ? v.reference !== "https://transparencyreport.google.com/safe-browsing/search" : v.state === "no_match" && v.reference !== null)) fail(); return v; }
function derived(r, obs) { if (r.kind === "unscannable") return "unscannable"; const candidate = r.supporting_evidence.some((e) => e.source.startsWith("candidate:"));
  const match = obs.some((o) => o.state === "match" && o.freshness === "fresh"), no = obs.some((o) => o.state === "no_match" && o.freshness === "fresh");
  const errors = obs.some((o) => ["error", "not_configured"].includes(o.state)); const stale = obs.some((o) => ["match", "no_match"].includes(o.state) && o.freshness !== "fresh");
  if (match && no) return "known_malicious_conflicting"; if (match) return errors || obs.some((o) => o.state === "no_match") ? "known_malicious_low" :
    candidate ? "known_malicious_high" : "known_malicious_medium"; if (no) return errors || obs.some((o) => o.state === "match") ?
    "no_known_match_low" : candidate ? "suspicious_complete" : "no_known_match_medium";
  return `${candidate ? "suspicious" : "unknown"}${stale ? "_stale" : errors ? "_provider_error" : ""}`; }
export function decodeResult(d, v) { if (!exact(v, ["status", "result"]) || v.status !== "ok") fail(); const r = v.result;
  if (!exact(r, ["kind", "scan_id", "mode", "canonical_target", "unscannable_reason", "outcome", "risk_label", "analysis_state", "confidence",
    "supporting_evidence", "contradicting_evidence", "provider_observations", "limitation_codes"]) || r.scan_id !== d.scanId || !scanId(r.scan_id) || !MODES.includes(r.mode) ||
    d.mode && r.mode !== d.mode || !OUTCOMES[r.outcome] || !Array.isArray(r.supporting_evidence) || !Array.isArray(r.contradicting_evidence) ||
    !Array.isArray(r.provider_observations) || !Array.isArray(r.limitation_codes) || [r.supporting_evidence, r.contradicting_evidence,
      r.provider_observations, r.limitation_codes].some((items) => items.length > 16) || r.limitation_codes.some((x) => !LIMITS[x]) ||
    new Set(r.limitation_codes).size !== r.limitation_codes.length) fail(); const relation = d.receipt; let expectedKind; let expectedReason; let expectedTarget;
  if (relation === undefined && !exact(d, d.mode === undefined ? ["scanId"] : d.truncated === undefined ? ["scanId", "mode"] : ["scanId", "mode", "truncated"])) fail();
  if (relation !== undefined) { if (!exact(d, ["scanId", "receipt", "resultIndex"]) || !exact(relation, ["request", "mode", "scanIds", "acceptedTargets", "rejectedCandidates", "truncated",
    "unscannableReason", "targets", "rejections"]) || !integer(d.resultIndex) || relation.scanIds[d.resultIndex] !== d.scanId) fail();
    const accepted = Math.min(relation.acceptedTargets, 16); expectedKind = d.resultIndex < accepted ? "analyzed" : "unscannable"; expectedTarget = relation.mode === "live_page" && expectedKind === "analyzed" ? relation.targets[d.resultIndex] : undefined;
    expectedReason = expectedKind === "unscannable" ? relation.mode === "live_page" ? relation.rejections[d.resultIndex - accepted] ?? "no_candidates" : relation.unscannableReason ?? undefined : undefined; }
  const tuple = OUTCOMES[r.outcome]; if (tuple[0] !== r.risk_label || tuple[1] !== r.analysis_state || tuple[2] !== r.confidence) fail(); const target = r.kind === "analyzed" &&
    canonical(r.canonical_target) && r.unscannable_reason === null ? r.canonical_target : null; const reasonDomain = r.mode === "paste_url" ? [...BASIC, ...FETCH.filter((x) => x !== "input_too_large")] :
    r.mode === "paste_html" ? [...BASIC.filter((x) => x !== "missing_base_url"), "url_too_long", "input_too_large", "no_candidates"] : [...BASIC.filter((x) => x !== "missing_base_url"), "url_too_long", "no_candidates"];
  if (target === null && !(r.kind === "unscannable" && r.canonical_target === null && reasonDomain.includes(r.unscannable_reason) && r.outcome === "unscannable") || relation && (r.mode !== relation.mode || r.kind !== expectedKind || expectedTarget !== undefined && target !== expectedTarget || expectedReason !== undefined && r.unscannable_reason !== expectedReason)) fail();
  const obs = r.provider_observations.map((o) => observation(o, target)), evidence = [...r.supporting_evidence.map((e) => ["supporting", e]), ...r.contradicting_evidence.map((e) => ["contradicting", e])], links = [];
  for (const [polarity, e] of evidence) { if (!exact(e, ["source", "target", "category", "observed_at", "freshness", "reference", "provider_observation_index"]) ||
    e.target !== target || !time(e.observed_at)) fail(); if (e.source.startsWith("candidate:")) { if (polarity !== "supporting" || e.source !== `candidate:${r.mode}` ||
      e.category !== "misleading_url_like_text" || e.freshness !== "fresh" || e.provider_observation_index !== null || typeof e.reference !== "string" || e.reference.length > 2048) fail(); }
    else { const i = e.provider_observation_index; const o = obs[i]; if (!integer(i) || !o || e.source !== `${o.source}:${o.provider}` || e.category !== (o.state === "match" ? o.category : "no_known_match") ||
      e.observed_at !== o.observed_at || e.freshness !== o.freshness || e.reference !== o.reference) fail(); links.push(`${polarity}:${i}`); } }
  if (derived(r, obs) !== r.outcome || r.kind === "unscannable" && evidence.length) fail(); const risk = r.risk_label, expected = obs.flatMap((o, i) => ["match", "no_match"].includes(o.state) ? [`${(risk === "no_known_match") === (o.state === "no_match") ?
    "supporting" : "contradicting"}:${i}`] : []).sort(); const truncated = relation?.truncated ?? d.truncated;
  if (links.sort().join() !== expected.join() || truncated !== undefined && r.limitation_codes.includes("results_truncated") !== truncated) fail(); const core = [evidence.some(([, e]) => e.source.startsWith("candidate:")) && "misleading_display_text",
    obs.some((o) => o.state === "no_match" && o.freshness === "fresh") && "provider_no_match_scope", obs.some((o) => o.state === "match" && o.freshness === "fresh") &&
    "provider_match_scope", obs.some((o) => ["match", "no_match"].includes(o.state) && o.freshness !== "fresh") && "stale_observation",
    obs.some((o) => ["error", "not_configured"].includes(o.state)) && "provider_unavailable", !obs.length && r.kind === "analyzed" && "no_provider_observation",
    r.outcome === "known_malicious_conflicting" && "conflicting_observations", "confidence_basis"].filter(Boolean);
  if (core.some((x) => !r.limitation_codes.includes(x)) || r.limitation_codes.some((x) => x !== "results_truncated" && !core.includes(x))) fail(); return { scanId: r.scan_id, target: target ?? `Unscannable: ${r.unscannable_reason}`, risk, state: r.analysis_state, confidence: r.confidence, evidence: evidence.map(([polarity, e]) => ({ polarity, source: e.source, category: e.category, target: e.target })), providers: obs.map((o) =>
      ({ provider: o.provider, state: o.state, freshness: o.freshness, category: o.category, error: o.error, reference: o.reference })),
    limitations: r.limitation_codes.map((x) => LIMITS[x]) }; }
