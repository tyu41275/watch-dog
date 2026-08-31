# ADR 0001: Watch Dog MVP architecture and deadline tradeoffs

Status: **Accepted**
Decision date: 2026-08-31
Version: 1.0.1

## Context

Watch Dog must become a live, coherent WebMCP application before the 2026-09-03 1:00 PM PDT deadline. It processes hostile URLs, must preserve human control, and needs a small persistent corpus without allowing community claims to become official malicious verdicts.

## Decision

Build one TypeScript web application with a browser UI, in-page WebMCP registration, server endpoints, and a small relational store. The deployment target must support a demonstrably safe outbound-fetch boundary, environment secrets, secure cookies, and durable storage. Cloudflare Worker + D1 is a candidate because the official resources include a Workers WebMCP template, but it is selected only if its private-network isolation and no-redirect behavior pass the safe-fetch release gate; otherwise switch to a runtime that can connect to pinned validated public IPs.

### Components

1. **Browser UI and WebMCP adapter.** Register `inspect_url`, `extract_demo_page_links`, and `prepare_sighting`. The extraction tool explicitly calls `document.querySelectorAll('a[href]')` on the Watch Dog same-origin demo page. Tool calls update the visible UI and use the same validation/policy code as human controls.
2. **Server inspection pipeline.** Parse and canonicalize HTTP(S) URLs; reject credentials, disallowed ports, alternate/private/local/special-use IPv4/IPv6 destinations, and unsafe IDNs; fetch only bounded HTML with time, compressed/decompressed byte, and content-type limits; never execute page code or fetch subresources. Automatic redirects are disabled in the deadline MVP unless the runtime can validate and pin the public destination independently for every hop. Platform-level private-network isolation and DNS-rebinding tests are hard release gates.
3. **Deterministic policy engine.** Combine versioned rule observations and provider observations into immutable `label`, `confidence`, `supportingEvidence`, and `contradictingEvidence` fields. AI narrative is a separate non-authoritative projection.
4. **Provider adapters.** Use a common timeout/error/provenance contract. Implement Google Safe Browsing and URLhaus adapters, with at least one authorized and enabled live in production. Both require credentials/terms checks; Google Safe Browsing is documented for non-commercial use and URLhaus requires an Auth-Key. Deterministic fixtures exercise every demo state and are visibly labeled as fixtures, but never satisfy the live-adapter gate.
5. **Sightings store.** `prepare_sighting` never writes. Persist only after a fresh CSRF-protected human confirmation using a single-use server nonce. Store a redacted canonical URL, keyed HMAC fingerprint, minimal evidence/provenance, timestamps, policy version, status (`quarantined`, `corroborated`, `admin-approved`, `rejected`), and confirmer identity. Sightings are private in MVP. A community sighting alone cannot produce `known malicious`.
6. **Authentication.** The one environment-supplied credential is the MVP administrator. Compare its password using a timing-safe verifier, issue a signed, narrowly scoped `HttpOnly`, `Secure`, `SameSite=Lax`, short-lived session cookie, and never expose credentials in client code or the repo. Rate-limit login, scans, and mutations; require CSRF protection on every mutation.
7. **Navigation mediation.** High-risk results render a warning with destination displayed safely and a user-controlled **Continue Anyway** action. Continuation uses a signed, short-lived, single-use token bound to the reviewed destination/result rather than an open redirect; there is no hard block.

## Data and disclosure decisions

Scans remain memory/request scoped. Application/reverse-proxy logs, analytics, traces, and errors contain request IDs and redacted operational metadata, not raw URLs or page bodies; third-party analytics are disabled and responses set `Referrer-Policy: no-referrer`. Before provider lookup, the interface explains that the named provider receives the full normalized URL and requires affirmative consent for that scan. Before confirmed persistence, fragments are dropped and values for credentials, tokens, email-like identifiers, and a maintained sensitive-key list are redacted; provenance records which transformation occurred. Store normalized provider facts only when their terms permit it.

## Tradeoffs accepted for the deadline

- A same-origin demo proves live DOM extraction; it does not claim access to arbitrary tabs.
- Static single-user authentication is sufficient for judge access; accounts, OAuth, reset, roles, and user management are excluded.
- Provider lookup is adapter-based, but only one live adapter is a release gate. The other can remain implemented but disabled if credentials or reliability threaten submission.
- Fixtures protect the presentation but never masquerade as live intelligence.
- Administrator approval is a manual status transition; reputation-weighted consensus is deferred.
- The browser agent may compare, summarize, and recommend through WebMCP but cannot affect the official result or persist a sighting. The app has no embedded model dependency in MVP.

## Rejected alternatives

- **Extension-first:** rejected because packaging, permissions, store/install friction, and arbitrary-tab security review endanger live-app readiness.
- **Client-side arbitrary URL fetch:** rejected due to CORS, secret exposure, inconsistent behavior, and weaker request controls.
- **AI-generated verdict:** rejected because it is non-deterministic and vulnerable to prompt injection from fetched/community content.
- **Community-vote promotion:** rejected because a three-day MVP cannot establish Sybil resistance or trustworthy reputation.
- **Hard blocking:** rejected because Watch Dog controls only mediated navigation and must preserve user agency.
- **STIX/TAXII:** rejected from MVP because it adds schema/interoperability work without proving the core human-agent workflow.

## Consequences and revisit triggers

The project must test URL parsing/redirects/SSRF boundaries, policy determinism, provider failures, redaction, promotion rules, session protection, and interstitial behavior. Revisit the architecture after submission if arbitrary active-tab inspection, multi-user moderation, high-volume ingestion, commercial provider use, or federation becomes a real requirement.
