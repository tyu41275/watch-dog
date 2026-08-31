# MVP acceptance criteria

Status: Approved planning gate
Deadline: 2026-09-03 20:00 UTC

## Shared pipeline and result semantics

- Paste Scan and Live Page Scan Demo emit the same extracted-candidate schema and invoke the exact same canonicalization, deterministic rule, provider adapter, aggregation, and result rendering code.
- An equivalence test proves equal candidates from both modes produce equal post-extraction results.
- Risk label, analysis state, confidence, provider status/freshness, supporting evidence, and contradicting evidence are separately rendered.
- Positive, no-match, timeout/quota/error, stale, malformed, and conflicting provider fixtures produce deterministic expected states.
- No no-match path, missing provider, stale observation, exception, or empty result renders “safe.”
- The agent explains only supplied deterministic evidence and cannot modify the official result, persist a scan/sighting, promote a report, or navigate.

## Paste Scan

- An HTTP(S) URL uses the bounded server fetch path only after validation and disclosure; every redirect hop is revalidated.
- Private/special IP, DNS rebinding, invalid scheme/port, credentials, timeout, redirect loop/private redirect, oversized/decompression, and disallowed content fixtures fail closed as typed unscannable results.
- Optional pasted HTML is bounded and parsed without fetching or executing scripts, frames, styles, images, media, forms, event handlers, or other embedded content.
- A fetch refusal visibly offers pasted HTML and the reference-page demo; it never silently weakens policy.

## Live Page Scan Demo and WebMCP

- The static reference page is Watch Dog-owned, same-origin, fixed, safe, and disclosed as such in UI/tool/docs.
- `inspect_current_page` is registered with `document.modelContext.registerTool(...)`, is discoverable/callable in a supported browser, and carries read-only/untrusted-content annotations where supported.
- Each invocation queries the current rendered DOM for `a[href]`; deleting the delayed insertion or invoking before/after it changes the observed result.
- No hard-coded URL array, source-only parse, fixture extraction, or prerecorded result can satisfy the live-DOM test.
- Relative targets resolve against `document.baseURI`; only HTTP(S) targets proceed; invalid/non-HTTP(S) targets are counted with bounded reasons.
- Duplicate canonical targets are analyzed once while every occurrence/anchor text remains visible evidence.
- URL-like anchor text pointing at a materially different target yields misleading-anchor evidence.
- At least one link inserted after page load appears in the result and in the recorded demo.
- Copy states that arbitrary third-party active-tab scanning requires a future extension with permissions. No Chrome extension is in MVP.
- There is no WebMCP navigation tool. Any warning/Continue Anyway action is normal UI.

## Privacy, persistence, and auth

- Raw HTML, DOM dumps, full query values, provider payloads, credentials, cookies, and form/storage data are absent from durable storage and ordinary logs.
- Only explicit human confirmation can persist a sighting; fragments and sensitive query values are removed/redacted; minimal provenance remains.
- Community reports remain quarantined and duplicates do not inflate malicious status; promotion requires a recognized-provider match or administrator approval.
- Static credentials exist only in server environment variables, have no defaults, are checked server-side, and create a signed Secure HttpOnly SameSite short-lived cookie.
- Wrong/missing credentials are throttled with generic errors; state-changing admin actions have CSRF protection; no account/OAuth/reset/user-management UI exists.

## Security and fixture matrix

- Tests cover IPv4/IPv6 special ranges, metadata addresses, redirects, DNS rebinding/mixed answers, response bounds, inert parsing, XSS, prompt injection, IDN display, misleading anchors, duplicates, provider states, sanitization/logging, auth/session/CSRF, and WebMCP schemas/selection/parameters/results/UI effects.
- External content is always rendered as text and marked untrusted for the agent; injection strings cannot change tool selection, result state, persistence, or navigation.
- One permitted live provider succeeds in the deployed environment. All other provider/error branches have labeled deterministic fixtures.

## Deployment and submission

- A fresh clone can install, test, build, and run from committed instructions without private source or committed secrets.
- Public HTTPS deployment works in ChatGPT's in-app browser or Chrome 149+ with WebMCP enabled; clean-session judge credentials/instructions work.
- Public repository contains all necessary source/assets/instructions and a visible Apache-2.0 license.
- Devpost description explains WebMCP fit, user experience, human-agent collaboration, and implementation without overstating tab access or safety.
- Public YouTube video is in English, includes audio and a functioning demo of both modes/WebMCP, uses permitted assets, and is under three minutes.
- Live app, repository default branch, description, testing instructions, and video describe the same final revision and remain unchanged after the deadline through judging.

## Deadline verdict

P0 passes only when every criterion above that is necessary to the two protected modes, secure shared pipeline, one live provider, deployment, and submission has evidence. P1/P2 completion cannot compensate for a P0 failure. If a P0 criterion fails near deadline, cut lower-priority work according to [three-day-plan.md](three-day-plan.md); do not relabel the failure as a limitation and submit a misleading claim.
