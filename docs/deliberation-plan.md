# Independent multi-model deliberation plan

Status: Ready to run after the vision interview  
Execution gate: Do not start until the interview answers are persisted verbatim or as user-approved summaries.

## Independence protocol

Use at least three genuinely distinct model routes, preferably different model families/providers. Record the exact provider, model identifier, date, prompt hash, and output for every route. If three distinct routes are unavailable, pause and report the limitation rather than presenting repeated runs of one model as independent.

Each route receives the same frozen packet: the project request, approved interview record, deadline/judging facts, repository status, and relevant WebMCP constraints. Routes run in separate sessions with no access to one another's output, identities, critiques, or emerging synthesis. No route may edit the shared vision artifacts.

## Independent lenses

- **Route A — product and demo:** challenge user value, the must-win journey, WebMCP visibility, judging clarity, and what can be filmed convincingly in under three minutes.
- **Route B — security and corpus governance:** challenge URL handling, false assurance, data provenance, privacy, moderation, abuse, malicious submissions, licensing, and safe defaults.
- **Route C — delivery and architecture:** challenge the less-than-three-day schedule, external dependencies, failure modes, testability, deployment, and explicit deferrals such as STIX/TAXII.

Every route must also give a go/conditional-go/no-go recommendation, propose the smallest credible MVP, list non-negotiable safety invariants, identify assumptions requiring evidence, and name cuts needed to finish within the deadline.

## Reconciliation

Only after all raw outputs are sealed, create a separate synthesis pass. Normalize recommendations into a comparison matrix covering scope, user journey, WebMCP role, architecture, data, trust/safety, demo, schedule, and deferrals. Mark consensus, material disagreement, unique risk findings, and unsupported assumptions.

The reconciler must prefer direct interview constraints, then externally verified facts, then cross-route consensus. It may choose among disagreements only with an explicit rationale and may not silently average incompatible recommendations. Unresolved decisions return to the parent direct chat.

Persist the raw route records and synthesis before completing ADR 0001, the vision brief, or the glossary. Record rejected advice and why it was rejected. The deliberation is complete only when another reader can trace each accepted recommendation to an interview answer, verified fact, or independent route.
