# Three-day delivery plan

Status: Approved planning input
Deadline: Thursday, 2026-09-03 13:00 PDT / 20:00 UTC

## Priority contract

Paste Scan and Live Page Scan Demo are equal protected P0 capabilities. The planner must not make either conditional on P1/P2 work. Any implementation slices with prerequisites must carry explicit `Blocked by owner/repo#N` edges when decomposed; title order or prose is not dependency enforcement.

## P0 — submission-critical

- Public Apache-2.0 repository, reproducible setup, tests, source/assets, environment template, and deployment instructions.
- Shared typed contracts, canonicalization, deterministic rules, provider adapter, evidence aggregation, result UI, and ephemeral scan store.
- Paste Scan: bounded URL fetch plus optional bounded pasted HTML local-only parser and fail-closed fallback.
- Live Page Scan Demo: fixed Watch Dog-owned reference page, live `a[href]` extraction at invocation, relative normalization, non-HTTP(S) filtering, misleading text/duplicate evidence, and a post-load anchor.
- Registered `inspect_current_page` WebMCP tool and deterministic/agent evals; no navigation tool.
- Typed risk/state/confidence/freshness/provenance UI; no safe result from no-match.
- One working live provider plus a complete deterministic fixture matrix.
- Critical threat-model tests: SSRF/DNS/redirect/limits, inert parsing/XSS/prompt injection/privacy, auth/session/CSRF, and no raw durable/log leakage.
- HTTPS deployment with server-environment static credentials and signed secure session cookie; clean-browser judge smoke test.
- Devpost description, public YouTube video with English audio under three minutes, screenshots, testing instructions, and submission freeze checklist.

## P1 — valuable after P0 is demonstrably ready

- Human-confirmed, sanitized, quarantined sighting persistence with provenance and admin/provider promotion controls.
- Watch Dog-mediated warning/Continue Anyway interstitial with final-target display and point-in-time disclaimer.
- Grounded agent explanation from deterministic evidence, with explicit no-verdict/no-persistence authority.
- Second live provider only if credentials/terms/time allow; fixture adapter remains sufficient for the second provider shape.
- UI polish beyond what the recorded, accessible journey needs.

## P2 — post-submission roadmap

- Chrome extension for arbitrary third-party active-tab scanning with explicit host permissions.
- STIX/TAXII interoperability.
- Reputation-weighted community consensus, accounts/roles, OAuth, password recovery, and production admin controls.
- Continuous rescanning, broader crawling, production-scale queues/caches, automatic browser blocking, and malware detonation.

## Calendar

### Day 1 — Aug 31: contracts and vertical skeleton

Freeze schemas and fixture matrix; scaffold app/tests/deployment; implement canonicalizer and shared pipeline boundary; build the fixed reference document and invocation-time DOM extractor; register tool behind capability detection; publish first deploy.

Exit proof: both entry adapters emit the same candidate schema; the post-load anchor test fails if extraction is replaced with source-only or a hard-coded array.

### Day 2 — Sep 1: secure analysis and complete two-mode journey

Implement bounded fetch/local parser, deterministic evidence, provider adapter/one live provider, typed aggregation, and shared result UI. Run SSRF, execution, privacy, provider-state, duplicate, and misleading-anchor fixtures. Add static auth/session gate.

Exit proof: equivalent Paste/DOM candidates yield equal post-extraction results; all fixture states are visible; no-match is never safe; both modes work on the deployed app.

### Day 3 — Sep 2: harden, record, and prepare submission

Run fresh-clone and supported-browser tests; fix only P0 defects; complete README/testing/deployment/Devpost copy; record a 2:40–2:50 demo; publish YouTube; perform laptop/phone and clean-session QA; stage the final submission.

Exit proof: one immutable candidate revision supports live URL, repo, description, and video; judge instructions need no author intervention.

### Submission window — Sep 3 before 20:00 UTC

Allow only P0 blocker fixes. Re-run smoke/security subset after every change. Finalize at least one hour early, then freeze Devpost, repository, and live site through judging.

## Cut rules

1. Never cut either Paste Scan or Live Page Scan Demo.
2. Never weaken SSRF/privacy/inert parsing, typed uncertainty, shared-pipeline, license/public-repo, deployment, or submission proof to save a lower-priority feature.
3. Cut P2 immediately.
4. Cut the second live provider, advanced polish, warning interstitial, and corpus persistence in that order when P0 is at risk; retain honest fixtures and documentation of the missing surface.
5. Do not record a fake/hard-coded DOM result or claim arbitrary active-tab access.
6. If live provider access fails, choose another permitted adapter; fixtures alone do not satisfy the one-live-provider acceptance criterion.
