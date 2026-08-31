# Watch Dog independent critique — raw record

Invocation model requested by orchestrator: `gpt-5.6-luna`
Reasoning effort: `high`
Packet: `watch-dog-vision-input-v1.0.0.md`
Verified packet SHA-256: `20bc6eb57bf2a217c061b6ab72be54ca5a0ba20066852aafb32d57af33f84116`
Run date: 2026-08-31
Record policy: output below is preserved verbatim

---

# Watch Dog Independent Critique

**Model identity:** GPT-5/Codex, independent critic
**Packet:** `watch-dog-vision-input-v1.0.0.md`, version 1.0.0
**Verified SHA-256:** `20bc6eb57bf2a217c061b6ab72be54ca5a0ba20066852aafb32d57af33f84116`

## Verdict

**conditional-go.** The MVP is directionally coherent, but it is not release-ready until the security, provider-authorization, WebMCP, and persistence gates below are demonstrated. Any failed hard gate should result in a no-go or feature removal.

## Five highest-severity findings

1. **SSRF and DNS-rebinding protection is specified but not proven.**
   **Impact:** A redirect, alternate IP encoding, IPv4-mapped IPv6 address, DNS rebinding event, or platform-level re-resolution could expose internal services or metadata endpoints.
   **Smallest corrective action:** Implement a tested fetch boundary that validates and pins the destination IP for every request and redirect. If the hosting platform cannot guarantee pinning, disable redirects and restrict fetching to an explicitly safe host allowlist for the demo.

2. **Provider authorization and full-URL disclosure remain unresolved.**
   **Impact:** Google Safe Browsing and URLhaus terms/credentials may not permit the intended use; raw query values can expose secrets or personal data to providers.
   **Smallest corrective action:** Before any external call, show provider identity, purpose, and the exact URL disclosure risk and require explicit consent. Complete a written terms/credential check; otherwise run fixture-only mode and remove any live-provider claim.

3. **Persistence authority and corpus-abuse controls are underspecified.**
   **Impact:** A WebMCP agent, replayed request, or holder of the shared static credential could poison sightings. Publicly visible reports could become a phishing/malware directory or create defamation and privacy problems.
   **Smallest corrective action:** Make `prepare_sighting` strictly non-mutating. Require a fresh, authenticated, CSRF-protected human confirmation with a one-time server nonce; keep all reports private/quarantined by default, and provide an administrator-only promotion path or remove promotion from MVP.

4. **Prompt injection and AI authority boundaries are not operationally defined.**
   **Impact:** Fetched page text or provider responses can instruct the AI to misclassify risk, reveal data, or invoke mutation/navigation behavior. “Deterministic rules/providers own the official result” is not enough without an enforced boundary.
   **Smallest corrective action:** Treat all fetched/provider content as untrusted, clearly labelled data; prohibit AI from changing labels, making external calls, or persisting sightings. If this is not implemented by the Day 2 cutoff, remove AI from the MVP and use deterministic explanations.

5. **The critical WebMCP/deployment path has no demonstrated fallback or slack.**
   **Impact:** The app can appear functional while failing the actual ChatGPT in-app browser or Chrome 149+ WebMCP environment, especially with authentication and registration context.
   **Smallest corrective action:** By end of Day 1, execute a smoke test in the exact judging target showing `document.modelContext.registerTool(...)`, tool invocation, authentication, and live results. If it fails, immediately simplify to the smallest working WebMCP spine and switch hosting; do not spend remaining time on stretch features.

## Contradictions and underspecified authority/data flows

- The long-term goal is arbitrary active-tab scanning, while the deadline MVP is pasted URL scanning plus a same-origin demo page. All copy and demo narration must clearly call active-tab support future work.
- “Scans are ephemeral” conflicts with unspecified browser history, reverse-proxy logs, error traces, analytics, provider retention, and D1 records. The retention boundary must include those channels.
- Community reports may persist after explicit confirmation, but public visibility, moderation, takedown, retention, and administrator identity are not defined.
- “Administrator approval” is named, but the static-login design has no roles or administrator workflow.
- `prepare_sighting` sounds potentially mutating even though UI confirmation is the persistence gate. The server must enforce this distinction.
- `known malicious` requires recognized-provider corroboration or administrator approval, but “recognized provider,” corroboration threshold, stale-result handling, and conflicting-provider authority are unspecified.
- “No known threat” must not be presented as safe or reassuring; `unknown`, confidence, provider failure, and contradictory evidence need prominent semantics.
- The AI investigator is a product decision but is absent from the stated three-day implementation sequence. It should be explicitly optional or cut.

## WebMCP and Devpost compliance gaps

The packet identifies the requirements, but several are still delivery gates rather than verified facts:

- Actual `document.modelContext.registerTool(...)` registration must be present in the public repository and work in the target environment.
- A live URL must work in both the intended ChatGPT in-app browser or Chrome 149+ WebMCP configuration.
- Authentication must work in that environment, with judge credentials supplied without exposing operational secrets.
- Public repository, complete source/assets/instructions, detectable Apache-2.0 license, and WebMCP-fit documentation must be verified before freeze.
- The video must be public, under three minutes, contain audio, and clearly show both the working app and WebMCP interaction.
- New-project/meaningful-extension timing, entrant eligibility, and registration remain unresolved.
- Provider SDK/API/data terms must be cleared before submission.
- The free testing target must remain available through judging, followed by a hard freeze at the deadline.

## Security, privacy, and abuse risks

- Validate schemes, credentials, ports, IPv4/IPv6 forms, IPv4-mapped addresses, localhost/private/special-use ranges, IDNs, DNS answers, redirects, redirect count, response bytes, decompression behavior, timeouts, and content types.
- Disable automatic redirect following unless each hop is independently validated and safely connected.
- Sanitize all displayed fetched HTML/text and escape provider evidence to prevent XSS and link-based navigation abuse.
- Keep fetched content and provider output outside any privileged AI instruction channel; page text is adversarial input.
- Static login requires timing-safe password checking, brute-force protection, CSRF protection on every mutation, secure cookie scope, key management, and replay-resistant confirmation.
- Raw URLs can leak through logs, referrers, browser history, traces, provider requests, screenshots, and copied evidence. Query-value redaction and canonicalization need a precise documented rule.
- A URL hash is not automatically private: common URLs can be brute-forced. Do not describe a hash as redaction without defining its threat model.
- Store minimal provider facts and provenance rather than raw provider responses unless retention is explicitly permitted.
- Fixtures must be unmistakably labelled as fixtures, must not imitate live provider timestamps/status, and must never be presented as evidence from a real provider.
- Rate-limit scans, sightings, and login attempts. Prevent the corpus from becoming a public abuse or malware-distribution mechanism.

## Three-day feasibility and exact cuts/triggers

- Cut the arbitrary-tab extension immediately; it is already stretch-only.
- By **end of Day 1**, require a green deployment, login, WebMCP registration, tool invocation, and safe-fetch smoke test. If not green, switch hosting and reduce to the smallest working app.
- By **end of Day 1**, require verified provider credentials and permitted terms. If absent, use deterministic fixtures only and remove live-provider claims; if a live adapter is mandatory for acceptance, stop and mark no-go.
- By **midday Day 2**, freeze the core path: pasted URL, deterministic label/confidence/evidence, same-origin DOM extraction, and WebMCP tools. Cut the second adapter, interstitial, and nonessential persistence work first.
- Implement sightings only if the human confirmation, redaction, quarantine, and abuse controls pass security testing. Otherwise remove persistence from the submission.
- Cut the AI layer unless its untrusted-input and no-authority boundary is demonstrably complete.
- Reserve Day 3 for clean-room testing, recording, documentation, submission, and freeze; do not use it for new architecture.

## Demo failure modes

- WebMCP is disabled, unsupported, or registered on the wrong page.
- Login succeeds in one browser but the in-app agent context lacks the cookie or receives 401 responses.
- Fetches time out, hit provider rate limits, or return `unknown`, making the scripted story misleading.
- A fixture is accidentally narrated or rendered as live provider evidence.
- Same-origin link extraction fails because the demo page is not actually same-origin or the registration is unavailable there.
- The interstitial loses, rewrites, or leaks the target URL; “Continue Anyway” becomes an unsafe open redirect.
- Unredacted URLs, query secrets, console output, or provider payloads appear in the recording.
- Video exceeds three minutes, lacks audio, or fails to visibly demonstrate WebMCP.
- Deployment, repository visibility, license detection, credentials, or documentation is incomplete at submission.
- Any post-deadline change breaks the submitted live target or violates the freeze requirement.

## Non-negotiable release gates

1. Exact-target WebMCP registration and invocation smoke test passes.
2. Public HTTPS deployment and supplied test credentials work end-to-end.
3. SSRF/DNS/redirect/resource-limit tests pass, with no raw URL/page-body logging.
4. Provider credentials and applicable terms are documented; disclosure and consent occur before external calls.
5. Deterministic policy owns official labels; provider failure cannot produce reassurance; AI cannot override or mutate.
6. `prepare_sighting` is read-only, and persistence requires fresh human confirmation with CSRF/replay protection.
7. URL redaction, retention, provenance, quarantine, and visibility rules are implemented and tested.
8. Untrusted fetched/provider content is safely rendered and isolated from privileged instructions.
9. Fixtures are clearly labelled and never represented as live evidence.
10. Public repository, Apache-2.0 license, required WebMCP documentation, eligibility, and registration are complete.
11. Public sub-three-minute audio demo clearly shows the app and WebMCP.
12. Live testing remains available through judging, and the submission is frozen at the deadline.

I inspected only the specified frozen packet and verified its stated SHA-256. I did not inspect another critic output, any other Watch Dog artifact, GitHub state, Obsidian content, or conversation history, and I did not edit any shared file.
