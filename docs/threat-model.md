# Watch Dog MVP threat model

Status: Approved planning baseline
Date: 2026-08-31

## Assets and trust boundaries

Protect server/network reachability, environment secrets, session cookies, scan privacy, provider credentials/quotas, sighting integrity, administrator promotion, and the truthfulness of risk results.

Trust boundaries exist at user URL/HTML input, server fetch egress, fetched bytes, rendered reference-page DOM, provider requests/responses, agent/model context, browser rendering, authentication, and persistence. All content crossing those boundaries is untrusted until validated for its narrow use.

## Threats and required controls

| Threat | MVP control | Failure behavior |
| --- | --- | --- |
| SSRF to localhost, RFC1918/ULA, link-local, metadata, multicast, reserved, or private DNS | HTTP(S)-only; port policy; resolve all A/AAAA; block special ranges; connect only to validated addresses; revalidate each redirect | `unscannable`; offer pasted HTML/reference page |
| DNS rebinding or redirect bypass | bind validation to the connection target; re-resolve/revalidate per hop; cap redirects; disable automatic unvalidated redirects | abort with typed evidence |
| Oversized/decompression response or slow peer | byte/decompressed-byte, time, redirect, parser, and concurrency limits; abortable requests | `unscannable` or `provider_error` as appropriate |
| Malware/script/subresource execution | parse inert bytes; never execute script; never attach untrusted DOM; never load subresources; reject non-HTML where required | show bounded diagnostic |
| XSS/URL injection | text-node rendering; no raw HTML/Markdown/SVG; allow only HTTP(S) navigation; safe display/defanging | omit unsafe rendering/action |
| Prompt injection | mark DOM/fetch/provider/report output untrusted; bound fields; never place instructions in authority channel; agent has no verdict/persistence/navigation authority | deterministic result remains authoritative |
| Secrets/private data leakage | exclude forms, hidden inputs, password fields, storage, cookies, referrers, headers, and arbitrary text; redact sensitive query values before persistence/logging; disclose provider sharing | do not send/persist; fail closed |
| Homograph/misleading display | retain ASCII/punycode plus safe Unicode display; compare visible URL-like anchor text to resolved target; show final host prominently | suspicious evidence, not automatic malice |
| Provider outage/no-match/staleness/conflict | typed normalized observations, freshness, timeouts, quotas, contradictions; no-match never safe | `provider_error`, `stale`, `conflicting`, or `unknown` |
| Corpus poisoning/brigading/duplicates | quarantine; canonical-target dedupe plus provenance; rate limit; community volume is not promotion | administrator/provider corroboration required |
| Auth brute force/session theft/CSRF | no default secret; constant-time credential check where practical; throttle; signed Secure HttpOnly SameSite short-lived cookie; CSRF token for mutations | generic denial; no data mutation |
| Time-of-check/time-of-use navigation | warning says result is point-in-time; re-canonicalize/recheck final target when mediated; explicit Continue Anyway | user retains control |

## Data minimization

Ephemeral scan state may contain only the bounded inputs/results required for the active session and expires automatically. Ordinary logs contain opaque IDs, timings, counts, and typed statuses—not raw HTML, full URL query values, DOM text, provider payloads, credentials, or session cookies.

A persisted sighting contains a fragment-free canonical URL with sensitive query values redacted, minimal categorical evidence/provenance, timestamps, and human confirmation/promotion metadata. It excludes HTML, arbitrary snippets, form values, local storage, cookies, and provider secrets.

## Security test obligations

- IPv4/IPv6 loopback, private, link-local, multicast, unspecified, reserved, metadata, numeric/encoded IP, mixed DNS, rebinding, and redirect-to-private cases.
- Disallowed schemes/ports, credentials in URLs, redirect loops/limits, timeouts, oversized compressed/decompressed bodies, and non-HTML responses.
- Pasted HTML with scripts, event handlers, base tags, frames, images, CSS URLs, malformed markup, and prompt-injection strings causes no execution/fetch.
- DOM extraction excludes form/hidden/password/storage data and admits only anchor `href` metadata.
- XSS payloads render as text and cannot create navigation or script execution.
- Provider no-match, positive, timeout, quota, malformed, stale, and conflicting fixtures map to deterministic expected states.
- Authentication rejects missing/default/wrong credentials, rotates/times out signed cookies, rate limits failures, and protects mutations from CSRF.
- Persistence tests prove raw scan inputs and sensitive query values are absent from durable storage and logs.

## Out of scope

Watch Dog does not safely detonate malware, crawl arbitrary sites, inspect third-party tabs without an extension, block the browser, or promise production-grade authentication/protection.
