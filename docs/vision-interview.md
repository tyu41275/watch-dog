# Watch Dog vision interview

Status: **Complete — authoritative parent direct-chat decisions recorded**
Recorded: 2026-08-31
Record version: 1.0.0

This is a faithful structured record of the completed inline interview. It does not simulate another interview or infer answers that were not supplied.

## Decisions

1. **Audience and promise.** Watch Dog serves everyday users who need understandable URL warnings and agents that contribute structured observations. The safer moment is deciding whether to trust or follow a URL with visible, traceable evidence.
2. **Must-win journey.** A user pastes a webpage URL; Watch Dog fetches it server-side, inspects it, consults deterministic rules/providers, and shows a categorical risk label, separate confidence, and supporting/contradicting evidence. The same-origin demo lets an agent extract links from the live DOM.
3. **MVP combination.** The MVP combines URL inspection with quarantined, explicitly confirmed community sightings. A broad browsable threat-intelligence platform is not required.
4. **WebMCP role.** WebMCP exposes structured tools for inspection, same-origin link extraction using `document.querySelectorAll('a[href]')`, evidence comparison, and preparation of a sighting for human confirmation.
5. **Result policy.** Results use categorical risk labels and a separate confidence value. Supporting and contradicting evidence remain visible. Deterministic rules and recognized providers own the official result; AI cannot change it.
6. **Data and retention.** Scans are ephemeral. Only explicitly confirmed sightings persist. Persisted URLs have fragments removed and sensitive query values redacted; provenance remains attached. The user sees disclosure before a full URL is transmitted to an external provider.
7. **Contribution and moderation.** Agents may prepare structured observations, but a human confirms persistence. Community reports are quarantined and cannot independently promote a URL to known malicious. MVP promotion requires recognized-provider corroboration or administrator approval; reputation-weighted consensus is future work.
8. **Prohibited behavior.** Watch Dog does not guarantee safety, silently send full URLs to providers, execute fetched page code, auto-persist scans, or hard-block navigation. Watch Dog-mediated high-risk navigation shows a warning and a **Continue Anyway** choice.
9. **Architecture constraints.** External intelligence uses a provider-adapter interface. Google Safe Browsing and URLhaus are initial targets, at least one live adapter is required, and deterministic fixtures protect the demo. Authentication is one static environment-supplied username/password checked server-side with a simple session cookie.
10. **Submission constraints.** The deployed WebMCP app, public Apache-2.0 repo, and submission materials come first. The official deadline is 2026-09-03 at 1:00 PM PDT; the required public YouTube demo must be under three minutes.
11. **Success outcomes.** A judge can access and run the live app; WebMCP visibly completes the pasted-URL and same-origin link workflow; the result clearly separates risk, confidence, and both sides of the evidence while preserving human control.
12. **Explicit deferrals.** STIX/TAXII are out of MVP. A second live provider and an arbitrary-tab Chrome extension follow submission readiness; reputation-weighted consensus is future work.

## Remaining implementation choices

Exact deployment account, provider credentials, and final demo fixtures were not specified in the interview. They are delivery dependencies, not reasons to reopen product vision.
