# Watch Dog glossary

Status: **Approved — vision v1.0.1**
Last reviewed: 2026-08-31

| Term | Watch Dog definition |
| --- | --- |
| Watch Dog | The WebMCP-powered, evidence-first URL risk inspector and community threat-sighting corpus. |
| WebMCP tool | A structured tool registered by the active Watch Dog page through `document.modelContext`; it reuses page logic and shares visible state with the user. |
| Inspection / scan | An ephemeral evaluation of one normalized URL using deterministic rules, optional page retrieval, and provider adapters. A scan is not a persisted sighting. |
| Active tab | The arbitrary webpage currently open in a user's browser. Direct inspection of it requires the deferred extension; the MVP operates on a pasted URL and Watch Dog's same-origin demo DOM. |
| Official result | The deterministic `risk label + confidence + supporting evidence + contradicting evidence` produced by the versioned policy engine. AI text is not part of it. |
| Risk label | One of `known malicious`, `suspicious`, `no known threat`, or `unknown`. Labels are categorical and separate from confidence. |
| Confidence | The policy engine's separately displayed degree of support for the selected risk label. Confidence is not probability of safety. |
| Supporting evidence | Versioned observations that increase support for the official label. |
| Contradicting evidence | Observations, gaps, staleness, or failures that weaken the official label or support a different interpretation. |
| Recognized provider | An externally governed threat-intelligence source explicitly allowlisted by the project; Google Safe Browsing and URLhaus are initial adapters. |
| Provider adapter | A common interface that normalizes provider requests, responses, timeouts, errors, provenance, and fixture behavior. |
| Deterministic fixture | A local, labeled provider response used to make tests and the demo repeatable; it is never represented as a live lookup. |
| Sighting | A private, human-confirmed persisted report containing a redacted canonical URL, structured observations, and provenance. |
| Draft sighting | An agent- or human-prepared preview that has not been confirmed and is not persisted. |
| Quarantine | The default state of a confirmed community sighting before provider corroboration or administrator disposition. |
| Promotion | A state change allowing evidence to support `known malicious`; in the MVP it requires recognized-provider corroboration or administrator approval. |
| Provenance | Source, retrieval time, adapter/rule identity, policy version, transformation history, and fixture/live status attached to evidence. |
| URL fingerprint | A keyed HMAC of the canonical URL used for correlation without storing a guessable plain URL hash; it is pseudonymous, not anonymous. |
| Redacted canonical URL | A normalized persisted URL with its fragment removed and sensitive query values replaced while retaining enough structure for investigation. |
| Watch Dog-mediated navigation | Navigation initiated through a Watch Dog control or redirect endpoint, allowing a high-risk warning interstitial. Watch Dog does not control all browser navigation. |
| AI investigator | The user's browser agent that invokes bounded WebMCP tools to compare evidence, explain ambiguity, recommend next steps, and prepare sightings. Watch Dog adds no embedded model in MVP; the agent cannot set results or bypass confirmation. |
| STIX/TAXII | Threat-intelligence representation/exchange standards that are explicitly outside the MVP. |
