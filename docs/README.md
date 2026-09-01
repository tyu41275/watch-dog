# Watch Dog documentation

## Product and architecture

1. [Product vision](vision-brief.md)
2. [ADR 0001: two scan modes and one evidence pipeline](adr/0001-mvp-boundary.md)
3. [Threat model](threat-model.md)
4. [Google Safe Browsing integration](google-safe-browsing.md)
5. [Acceptance criteria](acceptance-criteria.md)
6. [Glossary](glossary.md)

Paste Scan and Live Page Scan are equal product capabilities. Both feed one deterministic evidence pipeline. Live Page Scan is currently bounded to a Watch Dog-owned reference document; inspecting unrelated browser tabs requires a future extension with explicit permissions.

## Product decisions

- [Vision decision record](vision-interview.md)
- [Independent review](independent-deliberation.md)
- [Review protocol](deliberation-plan.md)
- [Versioned deliberation records](deliberation/)

## Delivery records

These documents capture time-bound launch requirements without defining the product itself:

- [Delivery plan](three-day-plan.md)
- [Launch compliance](devpost-compliance.md)
- [Demo script and resources](demo-script-and-resources.md)
- [General demo-production workflow](demo-workflow.md)
