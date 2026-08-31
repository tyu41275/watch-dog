# Watch Dog independent critic input packet

Packet version: **1.0.0-public**
Original packet frozen: 2026-08-31
Public record: environment metadata sanitized; substantive product decisions unchanged
Review mode: independent, read-only critique of this frozen packet
Edit policy: the reviewer must not edit project files

## Review objective

Independently challenge whether this vision is internally coherent, safe enough for a public demo, compliant with the official WebMCP Challenge requirements, and achievable before 2026-09-03 1:00 PM PDT. Prefer concrete corrections and deadline cuts over feature suggestions.

## Authoritative product decisions

- Watch Dog is a WebMCP-powered, evidence-first URL risk inspector and community threat-sighting corpus.
- Everyday users receive understandable warnings; agents contribute structured observations.
- Long-term target: scan the active arbitrary browser tab.
- Deadline MVP: pasted webpage URL fetched server-side plus a same-origin live-DOM page demonstrating `document.querySelectorAll('a[href]')` extraction.
- Chrome extension: stretch-only after submission readiness.
- High-risk Watch Dog-mediated navigation: warning/Continue Anyway interstitial, never hard blocking.
- Results: categorical risk label plus separate confidence and supporting/contradicting evidence.
- Community reports cannot independently create `known malicious`; MVP promotion requires recognized-provider corroboration or administrator approval. Reputation-weighted consensus is future work.
- Scans are ephemeral. Only explicitly confirmed sightings persist, after fragment removal and sensitive-query-value redaction, with provenance retained.
- Disclose before a full URL is sent to an external provider.
- AI is an investigator: deterministic rules/providers own the official result; AI compares evidence, explains ambiguity, recommends next steps, and prepares sightings for human confirmation.
- Provider-adapter interface; Google Safe Browsing and URLhaus initial targets; at least one live adapter; deterministic demo fixtures.
- One static environment-supplied username/password, server check, simple session cookie; no account system/OAuth/reset/user management.
- Apache-2.0. STIX/TAXII explicitly out of MVP.
- Cut order: deployment/repo/submission; pasted extraction/same-origin demo; labels/confidence/evidence; quarantined sightings/provenance; warning interstitial; second adapter; arbitrary-tab extension.

## Proposed architecture

- One TypeScript web application with browser UI/WebMCP registration, server routes, and a small relational store. Deadline-default hosting is Cloudflare Worker + D1, portable if access favors another allowed host.
- WebMCP tools: `inspect_url`, `extract_demo_page_links`, and `prepare_sighting`; human UI confirmation is the persistence gate.
- Server fetch: HTTP(S) only; reject URL credentials, disallowed ports, and local/private/special-use destinations; revalidate DNS and every redirect; enforce time/byte/redirect/content-type limits; no JS or subresources; no raw URL/page-body logs.
- Pure versioned policy engine returns one of `known malicious`, `suspicious`, `no known threat`, `unknown`, with separate confidence and supporting/contradicting evidence.
- Provider adapters normalize live/fixture status, timeouts, errors, and provenance. Provider failure increases uncertainty and cannot yield reassurance.
- Confirmed sightings persist a redacted canonical URL/hash, evidence, provenance, policy version, timestamp, confirmer, and quarantine/promotion state.
- Static login issues a signed, short-lived, Secure/HttpOnly/SameSite cookie; rate-limit login/mutations.
- Watch Dog-mediated high-risk links route through a same-origin interstitial with **Back to safety** and **Continue Anyway**.

## Verified official requirements (2026-08-31)

Sources: [official rules](https://webmcp.devpost.com/rules), [overview](https://webmcp.devpost.com/), [resources](https://webmcp.devpost.com/resources).

- Deadline: Sep 3, 2026 at 1:00 PM PDT.
- Working live URL accessible in ChatGPT's in-app browser or Chrome 149+ with WebMCP enabled.
- Public repository with all functional source/assets/instructions and a detectable open-source license.
- Repository should contain actual `document.modelContext.registerTool(...)` registration.
- Text must explain WebMCP fit, UX improvement, new human-agent collaboration, and implementation.
- Public YouTube demo under three minutes, with audio, clearly showing the working app and WebMCP.
- Auth is allowed if testing credentials are supplied.
- Third-party SDK/API/data usage must be authorized under applicable terms.
- New project or a clearly documented meaningful WebMCP extension during Aug 25–Sep 3.
- Stage-one theme/API viability; then equal weights for WebMCP leverage, execution, potential impact, and creativity/ambition.
- Keep the free testing target available through judging; do not modify the submitted project after the deadline.

Provider facts checked against primary documentation: Google Safe Browsing is described for non-commercial use (commercial detection points to Web Risk), and URLhaus Community API requires an Auth-Key and is governed by fair-use/commercial conditions. Credential availability and final terms fit are unresolved delivery gates.

## Deadline plan and known unknowns

Day 1 deploys authenticated WebMCP spine, safe fetch, provider contract/fixtures, and one live adapter. Day 2 adds live-DOM demo, policy/evidence, disclosure, and confirmed quarantined sightings. Day 3 adds interstitial, security/clean-room tests, records the video, completes materials, submits, tags, and freezes.

External delivery unknowns at the time of review: deployment access, at least one acceptable provider credential, static testing credentials, entrant eligibility and registration, voice recording, and final launch submission.

## Required critic response

Return an unedited Markdown critique with:

1. verdict: `go`, `conditional-go`, or `no-go`;
2. the five highest-severity findings, each with impact and smallest corrective action;
3. contradictions or underspecified authority/data flows;
4. WebMCP/Devpost compliance gaps;
5. security/privacy/abuse risks, especially SSRF, redirect/DNS validation, prompt injection, credential/session handling, URL disclosure/redaction, and fixture truthfulness;
6. three-day feasibility and exact cuts/triggers;
7. demo failure modes;
8. a final list of non-negotiable release gates;
9. explicit confirmation that you did not inspect another critic output or edit shared files.

Do not propose implementation issue structure. Do not broaden the MVP unless a change is required for compliance or safety.
