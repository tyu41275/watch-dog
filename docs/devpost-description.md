# Watch Dog — English submission description

## Short description

Watch Dog is an evidence-first URL risk inspector that lets people and WebMCP-capable browser agents examine links together without turning incomplete reputation data into a safety claim.

## What it does

Paste Scan accepts either a URL through a bounded, SSRF-aware server fetch or inert pasted HTML that cannot execute scripts or load subresources. Live Page Scan demonstrates WebMCP on a fixed Watch Dog-owned reference document: its `inspect_current_page` tool enumerates the rendered anchors at invocation time, including an anchor inserted after page load. Both modes use the same canonicalization, deterministic analysis, live-provider adapter, evidence aggregation, ephemeral result store, and visible result UI.

Each result separates risk label, analysis state, confidence, provider state and freshness, supporting evidence, contradicting evidence, and limitations. Google Safe Browsing is consulted only after a person enables the per-invocation disclosure. A no-match means only that the provider returned no known match at that time; Watch Dog never renders it as “safe.”

## How it uses WebMCP

The page registers three bounded read-only tools: `inspect_current_page`, `scan_url`, and `get_scan_result`. A compatible browser agent can discover them through native `document.modelContext`, invoke a scan, and retrieve the same session-owned result the person sees. Page and provider content remains untrusted data. Deterministic application code—not the agent—owns the verdict, and the agent cannot navigate, persist a report, promote a sighting, or inspect arbitrary third-party tabs.

## Better human-agent collaboration

People should not have to correlate raw URL syntax, redirect behavior, extraction provenance, and provider status by hand. Watch Dog gives the agent a small structured interface for gathering that evidence while keeping consequential authority visible and human-controlled. The person decides whether to disclose a target to the provider and what to do with the result; the agent can inspect and explain, but cannot silently broaden access or rewrite the outcome.

## Implementation

Watch Dog is a TypeScript Cloudflare Worker with static assets, a Durable Object for throttling and short-lived session-owned results, strict server-side authentication, CSRF protection, bounded URL/HTML processing, public-address validation at every fetch hop, a normalized Google Safe Browsing v5 adapter, and generated protocol reducers shared by server and browser. The public repository includes the lockfile, environment template without values, tests, deterministic fixtures, deployment verifier, Google Chrome WebMCP capture harness, and Apache-2.0 license.

## Honest limits

This challenge candidate is not a guarantee that a URL is harmless and is not a general-purpose browser extension. Live Page Scan is deliberately limited to Watch Dog's own reference page. Scans are ephemeral, the live provider is restricted to its documented non-commercial use, and unexpected/missing/stale provider evidence produces an explicit reduced-confidence or error state.

Live app: https://watch-dog.tytechnologiesconsulting.workers.dev/

Source: https://github.com/tyu41275/watch-dog

Public demo: https://github.com/tyu41275/watch-dog/releases/download/watchdog-demo-2026-09-03/watchdog-youtube-final-pronunciation-fixed.mp4
