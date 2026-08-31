# Watch Dog three-day action plan

Status: **Execution-ready from approved vision v1.0.1**
Deadline: 2026-09-03 1:00 PM PDT / 20:00 UTC

This delivery sequence turns the approved product scope into an executable release plan. Its cut order preserves the product's trust and capability boundaries.

**Protected priority:** Paste Scan and Live Page Scan Demo are equal P0 entry modes. Both must exist in the first vertical slice and neither is cuttable. The Live Page Scan tool name is literally `inspect_current_page`; arbitrary third-party active-tab inspection and the Chrome extension are P2, not deadline stretch.

## Day 1 — deploy the spine (Aug 31)

**Exit condition:** a public licensed repo drives a live authenticated WebMCP page with a production URL.

1. Scaffold the single TypeScript app and deploy immediately.
2. Configure static username/password and session-signing secrets only in the deployment environment; add `.env.example` names without values.
3. Build both entry adapters: Paste Scan and the fixed same-origin reference page. Register `inspect_current_page`, whose callback queries the current rendered anchors and detects a post-load insertion; optional `scan_url` and `get_scan_result` tools reuse the same pipeline.
4. Implement canonical URL parsing and the server fetch safety envelope: HTTP(S) only, no credentials, alternate/private/special-use address rejection, no redirects unless every hop can be pinned, compressed/decompressed byte/time/content limits, no code/subresources, and no raw-URL leakage through logs/traces/analytics/referrers.
5. Add provider interface, deterministic fixtures, and one live adapter. Prefer the credential/terms path that can be verified first; do not let the second adapter block deployment.
6. Expand README with local run, deployment, test credentials, browser enablement, and fixture/live-mode instructions.
7. Smoke-test login, actual WebMCP registration/invocation, safe fetch, and live result in the exact judging browser target; switch hosting/simplify immediately if this is not green. Draft the Devpost project entry early with live URL and repo URL.

**Hard gate:** both scan modes and at least one provider credential/terms fit must be demonstrated by end of Day 1. Fixtures do not satisfy the live-adapter requirement; failure is no-go for the agreed MVP. If durable storage or a second provider consumes time before the protected paths work, defer it and return to deployment/tool reliability.

## Day 2 — prove the product (Sep 1)

**Exit condition:** the must-win journey produces deterministic labels/evidence and the same-origin DOM demo is filmable.

1. Harden the already-running demo page and literal `inspect_current_page` contract: relative normalization, HTTP(S)-only filtering, duplicate occurrence evidence, misleading anchor text, and the post-load-anchor mutation test.
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

**After P0 only:** the second live adapter is P1. Arbitrary third-party active-tab inspection and the Chrome extension are P2/post-submission. Never trade either protected scan mode, security, the live app, video, or required materials for them.

## External release gates

- [x] Complete challenge registration.
- [x] Configure deployment access without committing credentials.
- [x] Generate and securely store the static testing credentials.
- [ ] Configure at least one provider credential under acceptable terms.
- [ ] Record narration and complete the final release submission.
