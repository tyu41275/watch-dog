# Watch Dog critic reconciliation

Status: **Superseded by v1.0.2 after product priority clarification**
Vision revision: 1.0.1
Date: 2026-08-31
Original input packet: v1.0.0, pre-sanitization SHA-256 `20bc6eb57bf2a217c061b6ab72be54ca5a0ba20066852aafb32d57af33f84116`
Review method: independent critique against the frozen input packet
Critic verdict: `conditional-go`

## Accepted corrections

1. **Safe fetch enforcement.** Disable redirects in the deadline MVP unless the selected runtime can validate and connect to a pinned public IP for every hop. Require platform-level private-network isolation plus tests for alternate IP encodings, IPv4-mapped IPv6, special-use ranges, DNS changes, decompression, and response bounds. If this cannot be demonstrated, the server-fetch feature is no-go; a host allowlist is not accepted as a substitute for the authoritative pasted-URL MVP.
2. **Live provider is a hard gate.** Document credentials and terms fit for at least one provider by the end of Day 1. Fixtures keep tests/demo deterministic but cannot satisfy or be narrated as the live-adapter requirement. No live adapter means no-go for the agreed MVP.
3. **Private, replay-resistant sightings.** `prepare_sighting` is non-mutating. The sole static credential is the MVP administrator. Confirming a sighting requires a fresh server-issued one-time nonce and CSRF protection. Sightings remain private/quarantined; there is no public corpus browsing in MVP.
4. **No embedded AI authority.** “AI investigator” means the user's browser agent invoking bounded WebMCP tools; the app adds no separate model dependency. The page returns deterministic fields/explanation templates. Untrusted fetched/provider/community text is escaped data and is never placed in privileged instructions.
5. **Privacy and navigation hardening.** Use a keyed HMAC fingerprint rather than a plain URL hash, disable third-party analytics, set `Referrer-Policy: no-referrer`, redact error/trace data, retain only normalized provider facts permitted by terms, and bind Continue Anyway to a signed short-lived single-use navigation token rather than an open redirect.
6. **Authority semantics.** The allowlisted-provider configuration is versioned. A current positive provider match is sufficient corroboration; absence of a match never proves safety. Stale results and material provider conflicts yield `unknown` or reduced confidence under the deterministic policy. Administrator promotion is an explicit audited transition by the single authenticated administrator.
7. **Deadline gates.** Exact-target deployment/login/WebMCP/safe-fetch smoke tests and provider authorization must pass by end of Day 1. Freeze core scope by midday Day 2 and reserve Day 3 for testing, video, submission, and freeze.

## Rejected or narrowed advice

- **Fixture-only submission:** rejected because the authoritative interview explicitly requires at least one live adapter. Fixture-only is useful development mode but not an acceptable MVP.
- **Safe-host allowlist as final fetch behavior:** rejected because it would contradict the pasted arbitrary webpage URL decision. If safe arbitrary retrieval cannot be enforced, the agreed MVP is no-go rather than silently narrowed.
- **Remove all sightings before other late features:** narrowed to the authorized cut order. The second adapter and extension go first; sightings may be reduced to the smallest private confirm/quarantine flow but cannot be represented as complete unless its security gates pass.
- **Separate AI implementation:** not applicable. The browser agent is the investigator; Watch Dog itself does not call a generative model in MVP.

## Result

Vision v1.0.1 remained a conditional go for implementation planning. Release requires every hard gate in the compliance matrix and action plan; documentation alone is not release readiness.

## Supersession note

The later product decision made Paste Scan and the Watch Dog-owned Live Page Scan Demo equal protected P0 features. See `reconciliation-v1.0.2.md`. This v1.0.1 record remains unchanged otherwise as historical deliberation evidence.
