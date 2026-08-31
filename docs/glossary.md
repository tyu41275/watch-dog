# Watch Dog glossary

Status: Approved with ADR 0001
Last reviewed: 2026-08-31

## Analysis state

A typed description of whether analysis completed normally or is `unknown`, `unscannable`, `provider_error`, `stale`, or `conflicting`. It is separate from risk label and confidence.

## Canonical target

The normalized HTTP(S) URL used to deduplicate analysis and provider work. Canonicalization removes fragments and default ports and normalizes host comparison without erasing meaningful path or query semantics.

## Confidence

A categorical assessment of evidence completeness, independence, freshness, and agreement. Confidence is not the probability that a URL is malicious and is always displayed separately from risk.

## Confirmed sighting

A sanitized sighting that a human explicitly chose to persist. “Confirmed” means confirmation of the sighting record, not proof that its target is malicious.

## Evidence

A structured observation with provenance, target, category, observed time, freshness, provider/reference, and whether it supports or contradicts the aggregate result. Page text is evidence, never authority.

## Live Page Scan Demo

Invocation-time rendered-DOM inspection of a fixed, safe, Watch Dog-owned same-origin reference document. It is a protected MVP mode. It is not arbitrary third-party active-tab scanning.

## Misleading anchor text

Evidence recorded when URL-like visible link text implies a materially different host or target from the link's resolved `href`. It is a suspicious signal, not proof of malice.

## No known match

A risk label meaning queried recognized providers returned no positive match within their stated coverage and freshness. It never means safe.

## Paste Scan

A protected MVP mode that accepts an explicit URL through the bounded fetch path or bounded pasted HTML for local-only parsing.

## Provider adapter

An interface that converts a threat-intelligence provider response, timeout, quota failure, or malformed result into a normalized observation. Adapters do not own the aggregate verdict.

## Quarantined sighting

A persisted, sanitized community observation that has not been promoted to known malicious. Duplicate/community volume does not promote it automatically.

## Risk label

The deterministic categorical result: `known_malicious`, `suspicious`, `no_known_match`, or `unknown`. It is separate from analysis state and confidence.

## SSRF-aware fetch

A bounded server request path that validates scheme, port, DNS/IP results, connection target, and every redirect hop; blocks private/special destinations; and enforces time, size, decompression, and content-type limits.

## Untrusted content

Any page, DOM, pasted HTML, provider payload, or community report supplied outside Watch Dog's trusted code. It is never executed, rendered as raw HTML, or obeyed as instructions by the agent.

## WebMCP

The browser API through which a page registers structured tools with `document.modelContext.registerTool(...)` for browser-mediated agent discovery and invocation.

## Watch Dog-mediated navigation

A link-opening action initiated from Watch Dog's UI. It may show a warning and Continue Anyway interstitial. It is not a WebMCP tool and is not a browser-wide blocker.

## STIX/TAXII

Threat-intelligence interchange standards. They are explicitly outside the initial release because no current product integration requires them.
