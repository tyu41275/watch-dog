# Watch Dog vision brief

Status: **Approved for planning**
Version: 1.0.1
Date: 2026-08-31

## Product intent

Watch Dog is a WebMCP-powered, evidence-first URL risk inspector and community threat-sighting corpus. It helps an everyday user make a safer navigation decision while letting an agent do the laborious work of collecting, comparing, and explaining structured observations in the same visible browser experience.

The product is deliberately two-sided:

- **People** receive plain-language risk labels, uncertainty, evidence, and a reversible navigation choice.
- **Agents** invoke bounded WebMCP tools to inspect a pasted URL, analyze links in the Watch Dog demo page's live DOM, compare evidence, recommend next steps, and prepare—but not silently persist—a sighting.

## User promise

“Before you follow a questionable link, see what Watch Dog knows, what it does not know, and why.”

Watch Dog never equates “not listed” with “safe.” Every result separates:

1. a categorical official risk label;
2. confidence in that label;
3. supporting evidence;
4. contradicting or uncertainty-increasing evidence; and
5. practical next steps.

## Must-win MVP journey

1. The authenticated user opens the deployed Watch Dog app and sees a disclosure explaining server retrieval and optional full-URL provider sharing.
2. The user or browser agent supplies a webpage URL.
3. The server validates the destination, applies tested SSRF protections, fetches bounded HTML without executing it, normalizes links, runs deterministic rules, and consults at least one live recognized-provider adapter. Redirects are off unless every hop can be validated and connected to a pinned public address.
4. The page shows `known malicious`, `suspicious`, `no known threat`, or `unknown`, plus separate confidence and supporting/contradicting evidence. Provider failure produces uncertainty, not a reassuring result.
5. On the same-origin DOM demonstration page, a WebMCP tool uses `document.querySelectorAll('a[href]')` to extract visible page links and can inspect a selected link through the same pipeline.
6. The agent explains ambiguity and may prepare a structured sighting. Nothing is stored until a person reviews and explicitly confirms it.
7. A Watch Dog-mediated attempt to open a high-risk URL first shows a warning interstitial with **Back to safety** and **Continue Anyway**. Watch Dog does not hard-block.

## WebMCP surface

The MVP registers narrow, inspectable tools in the page:

- `inspect_url`: validate and inspect a pasted URL through the canonical server pipeline;
- `extract_demo_page_links`: read links from the current same-origin demo DOM using `document.querySelectorAll('a[href]')` and return normalized structured candidates;
- `prepare_sighting`: assemble observations, evidence references, and provenance into a draft shown in the UI.

`prepare_sighting` is non-mutating. Persistence remains a distinct authenticated human-confirmation action protected by CSRF validation and a fresh one-time server nonce. Tools reuse the same application logic and update the visible UI so human and agent share context. The long-term `inspect_active_tab` capability belongs in a browser extension and is explicitly post-readiness.

“AI investigator” means the user's browser agent using these bounded tools; the MVP adds no embedded generative-model dependency. Watch Dog itself returns deterministic result fields and explanation templates.

## Official result and evidence policy

The official result is a pure, deterministic function of normalized observations. Provider matches and rules map to a label and confidence according to a versioned policy. Any browser-agent explanation is non-authoritative, is not persisted as part of the result, and cannot mutate official fields.

- `known malicious`: requires a current positive match from a provider in the versioned allowlist or explicit audited approval by the single authenticated MVP administrator.
- `suspicious`: deterministic heuristics or non-authoritative evidence indicate meaningful risk without sufficient corroboration for `known malicious`.
- `no known threat`: checks completed without a recognized malicious signal; this is not a safety guarantee.
- `unknown`: evidence is missing, stale, conflicting, or provider checks failed enough that a more specific claim is not justified.

Community reports are evidence but never independently promote a URL to `known malicious` in the MVP.

## Trust, privacy, and abuse boundaries

- Scans are ephemeral and excluded from persistence, raw logs, analytics, traces, and error bodies by default. The MVP uses no third-party analytics and sends `Referrer-Policy: no-referrer`.
- Confirmed sightings are private and quarantined pending corroboration or administrator review; the MVP has no public corpus browser.
- Before persistence, fragments are removed and sensitive query parameter values are replaced with a redaction marker; provenance and normalization version are retained.
- Before any full URL leaves Watch Dog for a provider, the UI names the provider and discloses that transmission. Provider calls are server-side and secrets never reach the browser.
- Fetched pages are treated as hostile data: no script execution or subresource loading; strict scheme/address/port/content/decompression/size/time bounds; and no redirects unless the connection can be pinned to each independently validated public destination.
- UI text, fetched metadata, community observations, and provider content are untrusted evidence, never agent instructions.
- Persist a keyed HMAC fingerprint instead of a guessable plain URL hash, and retain only normalized provider facts permitted by provider terms.
- Navigation is never automatic. High-risk Watch Dog-mediated navigation requires an interstitial and explicit user choice.

## Success evidence

The MVP is ready only when:

- a judge can open the deployed URL in a supported WebMCP browser, authenticate using supplied test credentials, and complete the documented path;
- the video visibly invokes WebMCP and shows shared page state, not just a REST call or mocked chat;
- deterministic fixtures reproduce known-malicious, suspicious, no-known-threat, unknown/provider-failure, and conflicting-evidence states;
- at least one real provider adapter works in production while the demo can fall back to clearly labeled deterministic fixtures;
- the public repository contains all functional source, setup/test instructions, and an Apache-2.0 license visible to GitHub.

## Deadline boundary

Build in this order: (1) deployed WebMCP app/public licensed repo/submission materials; (2) pasted-page extraction and same-origin DOM demo; (3) labels/confidence/evidence; (4) quarantined sightings/provenance; (5) warning interstitial; (6) second live adapter; (7) arbitrary-tab extension.

STIX/TAXII, community reputation scoring, public corpus federation, automated takedown, background crawling, and guarantees of safety are out of MVP.
