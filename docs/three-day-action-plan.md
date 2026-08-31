# Watch Dog three-day action plan

Status: **Execution-ready from approved vision v1.0.1**
Deadline: 2026-09-03 1:00 PM PDT / 20:00 UTC

This is a deadline sequence, not the final `worker:needs-plan` issue. Every cut follows the user-authorized order.

## Day 1 — deploy the spine (Aug 31)

**Exit condition:** a public licensed repo drives a live authenticated WebMCP page with a production URL.

1. Scaffold the single TypeScript app and deploy immediately.
2. Configure static username/password and session-signing secrets only in the deployment environment; add `.env.example` names without values.
3. Register one minimal `inspect_url` WebMCP tool and show its invocation/result in visible UI state.
4. Implement canonical URL parsing and the server fetch safety envelope: HTTP(S) only, no credentials, alternate/private/special-use address rejection, no redirects unless every hop can be pinned, compressed/decompressed byte/time/content limits, no code/subresources, and no raw-URL leakage through logs/traces/analytics/referrers.
5. Add provider interface, deterministic fixtures, and one live adapter. Prefer the credential/terms path that can be verified first; do not let the second adapter block deployment.
6. Expand README with local run, deployment, test credentials, browser enablement, and fixture/live-mode instructions.
7. Smoke-test login, actual WebMCP registration/invocation, safe fetch, and live result in the exact judging browser target; switch hosting/simplify immediately if this is not green. Draft the Devpost project entry early with live URL and repo URL.

**Hard gate:** at least one provider credential and terms fit must be documented by end of Day 1. Fixtures do not satisfy the live-adapter requirement; failure is no-go for the agreed MVP. If durable storage or a second provider consumes more than two focused hours before the live path works, defer it and return to deployment/tool reliability.

## Day 2 — prove the product (Sep 1)

**Exit condition:** the must-win journey produces deterministic labels/evidence and the same-origin DOM demo is filmable.

1. Add the demo page and `extract_demo_page_links`, explicitly using `document.querySelectorAll('a[href]')`.
2. Implement the pure policy engine and contract tests for all four labels, separate confidence, supporting evidence, contradicting evidence, provider outage, and conflict.
3. Add disclosure/consent before sending a full normalized URL to each external provider.
4. Add non-mutating `prepare_sighting`, human review, URL redaction/keyed fingerprint/provenance, and private confirmed-only persistence using CSRF protection plus a one-time server nonce.
5. Test the invariant that community reports alone never produce `known malicious`; add recognized-provider and administrator promotion paths.
6. Run supported-browser smoke tests against the deployed app and preserve screenshots/log-free evidence.
7. Prepare final Devpost description and a six-to-eight-shot storyboard.

**Scope freeze:** freeze the core by midday Day 2. Sightings may be reduced to one administrator-only confirm/list view, but normalization, provenance, quarantine, and promotion invariants may not be removed or claimed complete without passing tests.

## Day 3 — safety, proof, submit (Sep 2 to Sep 3 cutoff)

**Exit condition:** public submission is complete, reproducible, and frozen with recovery margin.

1. Add the Watch Dog-mediated high-risk warning interstitial using a signed, short-lived, single-use destination token, and test both **Back to safety** and **Continue Anyway** without creating an open redirect.
2. Run security-focused tests: SSRF targets/redirects, oversized/non-HTML responses, credential URLs, secret/query logging, login throttling, CSRF on mutations, hostile evidence text, and session cookie flags.
3. Attempt the second live provider only after all prior gates are green.
4. Record the deterministic demo, edit to 2:40–2:50, verify narration/captions and no secrets/live malicious links, upload Public to YouTube, and test logged out.
5. Clean-room test README setup and test the deployed app in a supported WebMCP browser with judge credentials.
6. Verify GitHub detects Apache-2.0, all source/assets/instructions are public, links work, and the deployment stays free/available through judging.
7. Submit before the final hours, capture receipt/screenshots, create an immutable submission tag, and freeze the submitted repo/site until judging ends.

**Stretch only after submission readiness:** second live adapter, then minimal Chrome extension for arbitrary active-tab inspection. Never trade the live app, video, or required materials for stretch work.

## Owner-dependent gates

- Register/join the Devpost challenge and confirm entrant eligibility.
- Supply deployment access and at least one provider credential under acceptable terms.
- Choose and securely place the static judge username/password.
- Record narration/voice and make the final Devpost submission.
