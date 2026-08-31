# ADR 0001: Two protected scan modes and one evidence pipeline

Status: Accepted
Date: 2026-08-31

## Context

Watch Dog must provide useful WebMCP behavior while handling hostile URL and page data honestly. The long-term vision includes arbitrary active-tab inspection, but a normal page cannot read unrelated third-party tabs. A server fetch also cannot reproduce a browser's rendered or authenticated state and creates an SSRF boundary.

The product requires both paste analysis and rendered-DOM inspection as first-class initial-release features. Independent review rejected language that implied browser-wide inspection and identified missing typed states, SSRF controls, prompt-injection handling, and provider semantics.

## Decision

### Equal entry modes

Paste Scan and Live Page Scan Demo are protected P0 features with equal standing. Neither may be cut in favor of a second provider, corpus polish, warning UI, or extension work.

- Paste Scan accepts an explicit URL through a bounded SSRF-aware fetcher, or bounded pasted HTML for local-only parsing.
- Live Page Scan Demo operates on one fixed, safe, Watch Dog-owned same-origin reference page. Its `inspect_current_page` WebMCP callback performs real rendered-DOM extraction at invocation time. It must observe an anchor inserted after load and must not use a hard-coded URL array or prerecorded extraction result.

Both produce the same extracted-candidate contract and enter one canonicalization, deterministic-analysis, provider-adapter, evidence-aggregation, and result-UI pipeline.

### Extraction semantics

For each anchor occurrence, retain raw `href`, visible anchor text, DOM provenance, and base URL only within the ephemeral scan. Resolve relatives with the platform URL parser against the effective base URL. Admit only `http:` and `https:`. Reject or count without analyzing `javascript:`, `data:`, `file:`, `blob:`, `mailto:`, `tel:`, invalid, credential-bearing, and disallowed-port targets.

Canonicalization lowercases scheme/host, normalizes IDNs for comparison while showing safe ASCII and Unicode representations, removes default ports and fragments, and preserves meaningful path/query semantics. Deduplicate provider work by canonical target while preserving every occurrence and anchor-text variant as evidence. Detect misleading anchor text when displayed URL-like text resolves to a materially different host/target.

### Result ownership

Deterministic code owns state transitions and aggregation. Provider adapters own normalized observations, not aggregate verdicts. The agent consumes explicitly untrusted evidence and may explain it, but cannot create or change verdicts, persist scans, approve sightings, or navigate.

Every adapter returns the same bounded observation fields: provider, queried canonical target, observed time, freshness/expiry, match state, category, observation confidence, provider reference, and typed error. Raw provider payloads remain behind the adapter and out of the model/UI/log contract.

The UI separates categorical risk from evidence confidence and typed analysis state. A no-match can produce `no_known_match`; it can never produce “safe.” Unknown, unscannable, provider-error, stale, and conflicting states are normal rendered outcomes, not generic exceptions.

### Security and persistence

The server fetch path validates scheme, ports, every resolved IP, and every redirect hop; blocks private, loopback, link-local, multicast, reserved, and metadata destinations; pins/validates connections against approved DNS results; and enforces redirect, byte, decompression, time, and content-type bounds. When it cannot establish safety, it fails closed and offers pasted HTML or the reference page.

Fetched/DOM/pasted content is inert data: no script execution, subresource loading, raw HTML rendering, or instruction following. Scan bodies and DOM dumps are ephemeral. Only explicit human confirmation can persist a sanitized sighting, and malicious promotion requires a recognized-provider match or administrator approval.

### WebMCP and navigation

The reference page registers `inspect_current_page` with a bounded schema/output plus read-only and untrusted-content annotations. `scan_url` and `get_scan_result` may support the same pipeline. There is no WebMCP navigation tool. Watch Dog-mediated navigation remains a normal UI action and a risk warning is a normal Continue Anyway interstitial, not a hard block.

### Authentication

Use one static username/password pair held only in server environment secrets and a signed Secure/HttpOnly/SameSite short-lived cookie. Add throttling and CSRF protection where state can change. Do not build accounts, OAuth, reset flows, or user administration.

## Consequences

- The demo truthfully proves rendered-DOM inspection while avoiding false claims about arbitrary active tabs.
- Both modes remain comparable because they share all post-extraction logic.
- The fixed reference page is safe and deterministic, but the post-load anchor proves the extraction is not source-only.
- Secure fetching is expensive, so its fail-closed fallback is part of the product rather than an error to hide.
- One live provider plus fixtures is more valuable than a fragile two-provider claim.
- The Chrome extension, STIX/TAXII, sophisticated reputation, and production auth remain future work.

## Rejected alternatives

- **Paste-only MVP:** rejected because it underuses WebMCP and cannot demonstrate rendered DOM.
- **Arbitrary active-tab MVP:** rejected because it requires extension permissions and cannot be honestly delivered as page-only WebMCP.
- **Hard-coded reference results:** rejected because it does not prove invocation-time DOM inspection.
- **Separate pipelines per mode:** rejected because results would drift and could not be compared.
- **LLM-owned verdicts or persistence:** rejected because untrusted page/provider text can influence the model and because official state must be reproducible.
- **No-match means safe:** rejected as false assurance.

## Revisit triggers

Revisit active-tab scanning only with an extension threat model, explicit host-permission UX, Chrome Web Store/deployment plan, and per-origin consent. Revisit auth and provider choices before any production or commercial use. Revisit STIX/TAXII only after a real interoperability consumer exists.
