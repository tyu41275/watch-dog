# Frozen execution plan for issue #1

Published: 2026-08-31 UTC  
Owner: root agent  
Status: frozen before implementation

## Objective

Deliver the truthful deployed two-mode WebMCP MVP plus submission evidence for `tyu41275/watch-dog#1` before 2026-09-03 20:00 UTC.

## Authority and exact dispatch state

- Parent: `tyu41275/watch-dog#1`, open; body SHA-256 `f925f115f42ac67c796299006f635fa23849b20a9008d2e5aacb7ba3a1209564`.
- Target/base: public repository `tyu41275/watch-dog`, branch `main`, dispatch SHA `7f1963590b931b30a5cc15da79f01a6993e1423e`.
- Worktree/head: dedicated `/home/ductor-user/.ductor/host-chatter/watch-dog-issue1-p0-agent-20260831`, unique branch `agent/issue-1-p0-20260831`, head initially equal to dispatch SHA, `branch.agent/issue-1-p0-20260831.chatterOwner=agent`. The stale shared checkout is untouched.
- Contract: verbatim 16,566-byte attachment at `evidence/authoritative/operator-contract-verbatim.txt`, SHA-256 `d7c1631a07467a7088d127e54b45ffe488a4cb76d4ed0760e70359feadc7cd40`.
- Live state: no application source/package, PR, release, GitHub deployment, GitHub Pages site, or repository-recorded live URL exists. Cloudflare/provider/auth secret *names* exist in GitHub Actions; values were not read. Local Wrangler is unauthenticated.
- Obsidian policy: canonical product/repository -> personal-comms -> global resolution has no applicable policy on authoritative Obsidian `main` `29bd90f62fe7ed36cc36214f00c70e6a8ded2c8a`. Open issue `tyu41275/Obsidian#389` and unmerged commit `2d1ad3b63b657678f4fe0aeadbe93252285a0a61` are evidence only. The contract's safe fallback therefore binds this task to serial mode, implementation/read-only/heavy ceilings `1/1/1`, and a conservative 1,800-second renewable lease. Exact provenance is preserved in `evidence/authoritative/policy-resolution.json`.
- Routes: planning, orchestration, implementation, integration, and repair use GPT-5.6-sol/high. Final exact-state review uses a fresh no-history GPT-5.6-luna/xhigh read-only child with no mutation/publication authority.

## Cause and mechanism sites

The symptom is the pre-release statement in `README.md`; the cause is that the dispatch tree has no executable application, build, runtime, or deployment mechanism. The cause will be fixed at these ownership boundaries, not papered over in copy:

- contracts/canonicalization/aggregation: `src/shared/`;
- fetch admission, DNS evidence, redirects, byte/time/content bounds: `src/worker/fetch/`;
- inert pasted-HTML extraction: `src/shared/extract-html.ts`;
- provider normalization and live Google adapter: `src/worker/providers/`;
- auth, signed cookie, throttle, session-owned TTL results: `src/worker/auth.ts` and `src/worker/coordinator.ts`;
- real invocation-time DOM extraction: `public/live-page.js`;
- WebMCP registration and bounded tools: `public/webmcp.js`;
- common visible result surface: `public/results.js`;
- activation truth: `.github/workflows/deploy.yml`, exact Cloudflare revision, and exact-revision browser/provider smoke evidence.

## Simplest viable design

One dependency-light TypeScript Cloudflare Worker serves static HTML/CSS/JS assets and JSON routes. One Durable Object serializes login throttling and session-owned ephemeral result access; raw URLs, HTML, DOM dumps, and provider payloads are never written to durable storage. Shared pure TypeScript owns candidate normalization and deterministic results. A conservative inert anchor parser handles pasted HTML. Paste URL fetching uses scheme/credential/port/host admission, DNS-over-HTTPS public-address evidence, manual redirect revalidation, strict limits, and Cloudflare's connection-time public-internet egress enforcement. Google Safe Browsing is the only live adapter, gated by disclosure and environment configuration. Browser code registers the three literal bounded WebMCP tools and updates the same result UI used by forms.

Rejected simpler alternatives:

- Static-only/fixture-only: cannot authenticate, throttle, own scan results by session, safely fetch, or satisfy the one-live-provider gate.
- A separate Node host: makes IP pinning easier, but no deploy authority or credentials for such a host are present; choosing it would leave activation knowingly blocked. Cloudflare is the authorized deployment surface and documents that its outbound proxy permits public Internet services rather than internal network services.
- A framework/ORM/database/provider SDK: adds lockfile and abstraction cost without helping the bounded journey.

## Binding non-goals and complexity budget

No Chrome extension or arbitrary third-party active-tab access; navigation tool; sightings/corpus persistence; warning interstitial; agent-owned verdict/explanation; second provider; accounts/OAuth/reset/roles; database/queue/cache; STIX/TAXII; crawling/detonation/hard blocking; or production-security claim. P1 and P2 cannot enter a repair round.

Every source file stays below 500 LOC (target 300). Every PR stays below 1,000 changed lines including tests/config (target 900). Total P0 target is at most 6,500 non-generated changed lines. Runtime dependencies are zero unless a security discriminator proves one unavoidable. No React/Next/Hono/ORM, provider SDK, generic plugin system, or parallel verdict path.

## Observable acceptance contract

1. A fresh clone follows committed commands to install, typecheck, test, build, and run without private source or secrets; missing secrets fail closed.
2. Paste Scan and Live Page Scan emit the same bounded candidate contract and call exactly one downstream pipeline; equivalent candidates have equal post-extraction structure except origin/time.
3. HTTP(S)-only canonicalization preserves meaningful path/query semantics, removes default ports/fragments, handles IDNs safely, preserves occurrences, deduplicates provider work, and records misleading URL-like text.
4. Disallowed destinations never reach an outbound fetch; DNS/address/redirect/limit/content failures are typed `unscannable`, and pasted HTML causes no execution or subresource load. Live deployed probes include loopback/private/rebinding-style hostnames and redirects; platform guarantees are identified rather than represented as mock evidence.
5. Removing the delayed reference-page anchor or invoking before/after insertion changes `inspect_current_page` output; a hard-coded/source-only mutant fails.
6. Literal risk labels, analysis states, confidence values, support/contradiction, provenance/freshness/provider state/limitations render separately. No no-match, absence, stale observation, error, or empty evidence says "safe."
7. Static credentials have no defaults; login is server-checked with generic throttled failures and produces a signed Secure HttpOnly SameSite short cookie. Results are opaque, session-owned, expiring, and cross-session access fails.
8. Exact tool names/schemas/annotations validate; discovery, selection, parameters, sequencing, cancellation/errors, bounded output, and visible UI effects pass. Untrusted strings render only as text.
9. Google terms/non-commercial eligibility, positive/no-match meaning, quota, timeouts, attribution, and disclosure are documented; one sanitized live no-match or permitted test observation succeeds on the exact deployment, while all failure fixtures stay honestly labeled.
10. An exact reviewed SHA deploys over HTTPS. A clean supported WebMCP browser authenticates, discovers/calls `inspect_current_page`, sees delayed-anchor evidence, completes Paste Scan, retrieves the same result UI, and observes a typed provider failure path.
11. Public repo/source/Apache-2.0/instructions, live URL, English Devpost text, private judge testing instructions, screenshots, a public English-audio YouTube demo under three minutes, receipt, revision mapping, and freeze record all match the demonstrated revision.

Any contrary observable falsifies its check. Unit fixtures alone do not satisfy network, provider, cookie, WebMCP, browser, deployment, video, or submission gates.

## Stable dependency graph

Child issue mapping, created serially from actual API-returned identifiers: WD-P0-01 `#2`, WD-P0-02 `#3`, WD-P0-03 `#4`, WD-P0-04 `#5`, WD-P0-05 `#6`, WD-P0-06 `#7`, WD-P0-07 `#8`, WD-P0-08 `#9`, WD-P0-09 `#10`, WD-P0-10 `#11`, WD-P0-11 `#12`. Every generated consumer body carries one literal `Blocked by tyu41275/watch-dog#N` line per direct edge; the post-creation audit verified all 32 lines.

| Stable node | Objective / expected exclusive paths and resources | Blocked by | Acceptance focus |
| --- | --- | --- | --- |
| WD-P0-01 | Spine and frozen shared contracts: `package*`, `tsconfig*`, `wrangler.jsonc`, `.env.example`, `src/shared/contracts.ts`, minimal worker/assets/test entrypoints | none | fresh-clone commands and closed schemas |
| WD-P0-02 | Candidate/canonicalization/inert parser: `src/shared/{canonicalize,candidates,extract-html}.ts`, focused tests/fixtures | 01 | URL matrix, occurrence provenance, no execution/subresources |
| WD-P0-03 | Deterministic provider seam/analysis: `src/shared/analysis.ts`, `src/worker/providers/types.ts`, fixture adapter/tests | 01,02 | every state/label/confidence; never safe |
| WD-P0-04 | Auth/session/throttle: `src/worker/{auth,coordinator}.ts`, login asset/routes/tests; leases cookie/session schema and DO class | 01,03 | no defaults, signed expiry, generic throttle, ownership |
| WD-P0-05 | Paste Scan secure fetch: `src/worker/fetch/**`, paste route/assets/tests; leases outbound-fetch path | 01,02,03,04 | real bounded fetch and fail-closed fallback |
| WD-P0-06 | Live Page + WebMCP: `public/{reference,live-page,webmcp}.js/html`, candidate route/tests; leases tool names | 01,02,03,04 | invocation-time anchors and delayed mutant proof |
| WD-P0-07 | Live Google adapter: `src/worker/providers/google.ts`, disclosure/terms/config/tests; leases provider credential/quota | 03,04,05,06 | normalized live observation and honest fixtures |
| WD-P0-08 | Shared UI and full trust/security gates: `public/{app,results,styles}.*`, security/tool/equivalence tests and evidence docs | 02,03,04,05,06,07 | two-mode journey, inert rendering, complete matrix |
| WD-P0-09 | Deployment and exact-revision acceptance: workflow, deploy/run docs, sanitized live-provider/network/deployment evidence; leases Cloudflare project/domain/secrets/revision | 01,04,05,06,07,08 | HTTPS exact SHA and green deployed probes |
| WD-P0-10 | Clean browser smoke: browser checklist/captures/tool evidence; leases clean profile and WD-P0-09 revision | 09 | actual discovery/invocation and both visible modes |
| WD-P0-11 | Devpost/video/submission/freeze: final description, screenshots, testing instructions, public video and receipt evidence; root-only external publication leases | 09,10 | all public/submitted surfaces match exact revision |

No mutating nodes are claimed independent under the active serial policy. If policy later changes, any shared file, schema, route, cookie/session shape, provider config/quota, test harness, mutable base, runtime/deployment target, or lifecycle decision falsifies independence. In particular Paste and Live are not independent once either changes the shared contract; provider and aggregation are not independent if normalized fields change; security, deploy, browser, and submission are revision-bound and serial.

Integration order is `01 -> 02 -> 03 -> 04 -> 05 -> 06 -> 07 -> 08 -> 09 -> 10 -> 11`. Each child receives one issue, fresh stamped worktree/branch, exact latest integrated base, frozen node contract, exclusive listed path/schema/runtime/external leases, and 1,800 seconds. A candidate is a commit SHA plus changed-path and test inventory; children cannot publish. Root publication/integration/merge is serial. Any changed byte/base/dependency invalidates affected candidates and review.

At zero READY nodes the root re-derives the graph and retries/decomposes; silence, capacity, missing PRs, conflicts, or stale review are not terminal. Out-of-scope discoveries become separate tracked items.

## Review, activation, and assumptions

The lightest independent review mechanism is a fresh `fork_turns=none` internal GPT-5.6-luna/xhigh child, because it has no inherited conversation and is explicitly denied edit/commit/push/merge/close authority while reporting only into the owning thread. Its prompt includes the entire operator contract verbatim, this plan, exact head/base SHAs, evidence, and boundaries. Prompt hash, launch route, reviewed SHA, findings, and terminal `PASS` or `FIX REQUIRED` are preserved. Changed exact state requires a fresh round.

Activation requires merge, a reviewed GitHub Actions deployment using existing repository secrets, exact Cloudflare revision verification, live-provider/network and clean-browser smoke, then Devpost/YouTube publication and freeze. A merge alone is not activation.

Assumptions chosen conservatively without operator contact:

1. The repository owner's configured Google key and challenge submission establish intended non-commercial use, but live use still fails closed until the exact deployed terms/attribution/semantics check passes.
2. Existing Cloudflare secrets authorize a new bounded `watch-dog` Worker; if account plan/permission blocks Durable Objects, preserve the candidate and use the smallest same-provider coordination primitive that meets the same acceptance contract, with a graph reset.
3. Devpost and YouTube authenticated publication may remain an external-authority boundary; code and immutable evidence will not be mislabeled as a submitted entry or public video.
4. "Pasted HTML" is capped and parsed as inert text; Watch Dog never attaches it to a document.
5. Google no-match proves only `no_known_match`, never safety; the demo will use inert/owned targets and never commit a live malicious URL.
