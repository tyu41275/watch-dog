# Watch Dog final critic reconciliation

Status: **Complete and operator-ratified**
Vision revision: 1.0.2
Date: 2026-08-31
Inputs: vision v1.0.0, gpt-5.6-luna critique v1.0.0, reconciliation v1.0.1, and latest operator decision

## Operator override

Paste Scan and Live Page Scan Demo are equal protected P0 entry modes. Any recommendation or schedule that demotes the DOM mode is superseded. The demo mode is honestly limited to one fixed, safe, Watch Dog-owned same-origin reference document; arbitrary third-party active-tab scanning still requires the deferred Chrome extension.

## Required DOM proof

The literal `inspect_current_page` WebMCP tool queries the rendered DOM at invocation time (for example `document.querySelectorAll('a[href]')`). It resolves relative URLs, filters non-HTTP(S), retains misleading anchor-text and duplicate-occurrence evidence, and observes at least one anchor inserted after page load. A hard-coded target array, source-only parser, fixture extractor, or prerecorded result does not satisfy the feature.

## Accepted critic controls

Retain typed unknown/unscannable/provider-error/stale/conflicting states; no safe verdict from no-match; confidence separate from risk; prompt-injection/untrusted-content isolation; bounded SSRF-aware fetching with fail-closed pasted HTML/reference-page fallback; ephemeral scans and sanitized confirmed sightings only; provider/admin malicious promotion; one live provider plus fixtures; secure static demo auth; agent outside verdict/persistence/navigation authority; normal UI warnings; no WebMCP navigation.

## Shared architecture and priority

`Paste Scan | Live Page Scan Demo -> one candidate contract -> canonicalization -> deterministic rules -> provider adapters -> evidence aggregation -> shared result UI`

Both modes, shared semantics, critical security tests, one live provider, deployment/authentication, public Apache-2.0 source/instructions, and submission/video proof are P0. Quarantined sightings, warning interstitial, grounded explanation, second provider, and extra polish are P1. Extension, STIX/TAXII, reputation voting, accounts, and production breadth are P2.

## Result

Conditional GO for planning against the full acceptance criteria. The condition is implementation evidence: documentation does not satisfy either protected mode, the live-provider gate, security tests, deployment, or Devpost deliverables.
