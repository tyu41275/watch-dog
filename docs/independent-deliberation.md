# Independent deliberation record

Status: Reconciled
Date: 2026-08-31

## Provenance

- Vision author: `gpt-5.6-sol`, task `4d430590`, run `f1f044b6`, thread `1544082582340374681`
- Independent critic: `gpt-5.6-luna`, task `9b942db0`, run `6a155f76`, thread `1544082789132144640`
- Critic output SHA-256: `63b138829e3659fe21db1d6d0eeb50584f71e1d3769ea53bfd1224d6c9840543`
- Synthesis authority: latest operator decision in the needs-plan request

The critic ran read-only and did not coordinate with the vision author. Its disposition was conditional GO for a thin hackathon prototype and NO-GO for implied production/browser-wide security claims.

## Accepted findings

The synthesis adopts the following review findings as non-negotiable:

- distinguish page-owned WebMCP behavior from arbitrary active-tab extension behavior;
- define typed unknown, unscannable, provider-error, stale, and conflicting states;
- never convert a provider no-match into a safe verdict;
- separate confidence from risk and describe confidence as evidence quality/agreement;
- add URL canonicalization, redirect, IDN/homograph, freshness, provenance, and provider-failure semantics;
- make SSRF, DNS rebinding, redirect-hop, size/time/decompression, content execution, XSS, prompt injection, privacy, and logging controls first-class;
- treat page/DOM/provider/report text as untrusted and keep the agent outside verdict and persistence ownership;
- require one real provider, deterministic fixtures, provider terms/quotas/attribution, and typed adapter outputs;
- preserve ephemeral scans and admin/recognized-provider corroboration for malicious promotion;
- omit WebMCP navigation and keep warning/Continue Anyway as normal UI;
- harden the static demo credential with server-only secrets, signed secure cookies, throttling, no defaults, and no sensitive data;
- test WebMCP tool schemas, selection, parameters, sequences, outputs, and UI effects; and
- include the complete Devpost live URL, public repo/license/instructions, description, and public sub-three-minute YouTube deliverables.

## Operator override

The critic recommended treating active-tab scanning as extension-only and described same-origin DOM extraction as keepable. The operator clarified the product vocabulary and priority:

- **Accepted:** arbitrary unrelated third-party active-tab scanning requires an extension and is deferred.
- **Overridden:** rendered-DOM scanning is not demoted. Live Page Scan Demo is a protected MVP mode equal to Paste Scan.
- **Boundary:** Live Page Scan operates only on a fixed, safe, Watch Dog-owned same-origin reference document. Its extraction is nevertheless genuine and runs against the rendered DOM when invoked, including a post-load anchor.

This resolves the apparent conflict without misrepresenting browser permissions.

## Architecture synthesis

`Paste Scan or Live Page Scan Demo -> ExtractedLinkCandidate[] -> canonicalizer -> deterministic rules -> provider adapters -> evidence aggregator -> shared result UI`

The two modes differ only at extraction. Provider adapters normalize observations; the aggregator performs deterministic precedence/state transitions; the agent produces a grounded explanation from untrusted evidence; only explicit UI actions can request sanitized persistence or mediated navigation.

## Remaining risks

- A genuinely safe server fetch boundary may take more time than expected. The fail-closed product behavior is to offer pasted HTML/reference page, not weaken SSRF checks.
- Live provider credentials, terms, quotas, or latency may fail. One adapter must work live before recording; fixture modes must remain honest and labeled.
- WebMCP is experimental. Verify the live deployment in ChatGPT's in-app browser and Chrome 149+ with WebMCP enabled.
- A single shared credential is acceptable only for the judging demo and must not be presented as production security.
- Any incomplete corpus or warning flow must be cut before either protected scan mode, the shared result contract, security controls, deployment, or submission artifacts.

## Sources independently verified during synthesis

- [Official rules and judging criteria](https://webmcp.devpost.com/rules)
- [Devpost resources/FAQ](https://webmcp.devpost.com/resources)
- [Chrome WebMCP security](https://developer.chrome.com/docs/ai/webmcp/secure-tools)
- [Chrome WebMCP evals](https://developer.chrome.com/docs/ai/webmcp/evals)
- [WebMCP specification/explainer](https://github.com/webmachinelearning/webmcp)
- [Google Safe Browsing appropriate use](https://developers.google.com/safe-browsing/reference/Appropriate.Usage)
- [URLhaus Community API](https://urlhaus.abuse.ch/api/)
