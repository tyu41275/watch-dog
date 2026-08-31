# Watch Dog vision brief

Status: Approved for planning
Approved: 2026-08-31
Deadline: 2026-09-03 13:00 PDT / 20:00 UTC

## Product intent

Watch Dog is an evidence-first URL risk inspector and a moderated community threat-sighting corpus. Its two-sided audience is:

- everyday users who need understandable warnings before following questionable links; and
- agents that can invoke bounded WebMCP tools, compare structured observations, explain ambiguity, and prepare a sighting for human confirmation.

Watch Dog does not guarantee that a page is safe. Its promise is narrower: extract link targets transparently, normalize and analyze them consistently, show what supports and contradicts a risk label, expose uncertainty plainly, and keep consequential actions under human control.

## Must-win journey

### 1. Paste Scan

The user supplies a webpage URL. Watch Dog validates it and, when allowed, performs a bounded server-side fetch that is resistant to SSRF and redirect bypasses. As a fail-closed alternative, the user may paste HTML with a base URL; that HTML is parsed locally and must not load images, scripts, styles, frames, or other embedded resources.

### 2. Live Page Scan Demo

The user opens a fixed, safe, Watch Dog-owned same-origin reference page and invokes `inspect_current_page`. The tool queries the rendered DOM at invocation time for anchors with `href` attributes. The reference document includes absolute and relative URLs, duplicate targets, a non-HTTP target, misleading anchor text, and at least one anchor inserted after load. The tool resolves relative URLs against `document.baseURI`, filters non-HTTP(S) targets, retains occurrence-level anchor evidence, and visibly proves that the dynamically inserted anchor was observed.

This is a genuine live-DOM scan of the Watch Dog reference document, not a prerecorded result or hard-coded target array. Product copy, tool descriptions, README, and demo narration must all say that arbitrary third-party active-tab scanning requires future extension permissions.

## Shared pipeline

Both entry modes emit the same bounded `ExtractedLinkCandidate` contract and then use exactly the same stages:

1. canonicalize and validate the target;
2. compute deterministic lexical, scheme, anchor-text, duplicate, and redirect evidence;
3. query provider adapters under explicit disclosure and configured limits;
4. aggregate supporting and contradicting observations with provenance and freshness;
5. derive a deterministic risk label, analysis state, and separate confidence assessment; and
6. render the same result components and optional human actions.

No mode owns a parallel verdict path. Extraction provenance differs; analysis semantics do not.

## Result contract

The aggregate contract keeps these dimensions separate:

- `risk_label`: `known_malicious`, `suspicious`, `no_known_match`, or `unknown`;
- `analysis_state`: `complete`, `unknown`, `unscannable`, `provider_error`, `stale`, or `conflicting`;
- `confidence`: `high`, `medium`, or `low`, describing evidence completeness, independence, freshness, and agreement—not likelihood of harm;
- supporting and contradicting evidence arrays with source, observed time, freshness, target, category, and reference; and
- extraction provenance, canonical target, redirect chain, provider statuses, and user-facing limitations.

`no_known_match` is not a safe verdict. Provider failure, missing coverage, stale data, or conflicting observations must remain visible and must reduce confidence or change the analysis state deterministically.

## WebMCP role

The protected tool is:

- `inspect_current_page`: no target URL input; read-only; operates only on the current Watch Dog-owned reference page; performs live DOM extraction on every invocation; returns a bounded scan identifier and concise structured summary; marks external/page-derived material as untrusted.

Supporting read-only tools may be:

- `scan_url`: starts the Paste Scan pipeline for an explicit HTTP(S) URL and optional bounded pasted HTML; and
- `get_scan_result`: returns a bounded ephemeral result for an opaque scan identifier owned by the current session.

Tool names, descriptions, schemas, results, selection, parameter handling, and execution are tested deterministically and with agent evals. There is no WebMCP navigation, persistence, promotion, or admin tool in the MVP. Warnings and Continue Anyway remain normal UI interactions.

## Trust, storage, and moderation

- Fetched pages, DOM strings, pasted HTML, provider payloads, and reports are untrusted content. They are never executed and are never treated as agent instructions.
- Scans are ephemeral and raw bodies, DOM dumps, and full provider payloads do not enter durable storage or ordinary logs.
- Before provider lookup, the user is told which target data leaves Watch Dog and which provider receives it.
- Only an explicit human confirmation can create a sighting. Persistence removes URL fragments, redacts sensitive query values, omits page snippets/form data, keeps minimal provenance, and records the decision actor/time.
- A community sighting stays quarantined. Counts and duplicate reports are evidence, not votes. Known-malicious promotion requires recognized-provider corroboration or administrator approval.
- The agent may summarize deterministic evidence and recommend next steps. It owns neither official state transitions nor persistence.

## Authentication

Authentication is intentionally a deadline-limited deployment gate, not an account system. A single username and password are supplied as server-side environment secrets, compared server-side without default credentials, and exchanged for a signed, Secure, HttpOnly, SameSite cookie with a short expiry. Add request throttling, generic failures, CSRF protection for state-changing admin actions, and documented judge credentials. There is no signup, OAuth, password reset, user profile, or role-management system.

## Provider boundary

Implement a provider-adapter interface and one live adapter, with Google Safe Browsing and URLhaus as candidates. Each adapter returns normalized observations and typed errors; it cannot directly label the aggregate result. Google Safe Browsing is non-commercial and imposes warning/attribution requirements. URLhaus requires an auth key and its community API is subject to fair-use/commercial-use terms. Terms, configured provider, positive-match meaning, quotas, timeouts, attribution, and failure behavior must be documented and feature-gated. Fixtures remain the reliable demo backstop.

## Success evidence

The MVP succeeds only if a judge can:

1. invoke a real registered WebMCP tool on the live reference page and see the post-load anchor included;
2. perform Paste Scan and see both modes produce identical downstream semantics for equivalent candidates; and
3. understand the risk label, separate confidence, provenance, contradictions, limitations, and human-controlled next action without being told an unverified URL is safe.

## Explicit deferrals

- arbitrary third-party active-tab scanning and the Chrome extension;
- automatic navigation or hard blocking;
- STIX/TAXII;
- reputation-weighted voting or community-driven promotion;
- account lifecycle and multi-user authorization;
- production-grade malware retrieval or content execution;
- a second live provider when it threatens the protected modes, secure fetch path, deployment, or submission; and
- claims of production-grade protection.

## Sources

- [Official WebMCP Challenge rules](https://webmcp.devpost.com/rules)
- [WebMCP Challenge resources](https://webmcp.devpost.com/resources)
- [WebMCP specification/explainer](https://github.com/webmachinelearning/webmcp)
- [Chrome WebMCP security guidance](https://developer.chrome.com/docs/ai/webmcp/secure-tools)
- [Chrome WebMCP eval guidance](https://developer.chrome.com/docs/ai/webmcp/evals)
- [Google Safe Browsing appropriate use](https://developers.google.com/safe-browsing/reference/Appropriate.Usage)
- [URLhaus Community API](https://urlhaus.abuse.ch/api/)
