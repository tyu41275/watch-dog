# Watch Dog

Watch Dog is a WebMCP-powered, evidence-first URL risk inspector and community threat-sighting corpus. It gives people understandable warnings while agents compare structured evidence and prepare sightings for human confirmation.

## Vision status

**Approved for planning — v1.0.1 (2026-08-31).** Product boundaries are frozen in the [vision brief](docs/vision-brief.md) and [ADR 0001](docs/adr/0001-mvp-boundary.md). The final implementation-planning issue has intentionally not been created yet.

The deadline MVP is a deployed web app that accepts a pasted webpage URL, fetches it server-side without executing page code, and demonstrates same-origin live-DOM link extraction with `document.querySelectorAll('a[href]')`. WebMCP tools let an agent inspect a URL, analyze the demo page's links, explain evidence, and prepare a sighting; a person remains in control of persistence and navigation.

## Product principles

- Evidence before assertion: categorical risk, confidence, supporting evidence, and contradicting evidence are separate fields.
- Deterministic authority: rules and recognized providers determine the official result; AI investigates and explains but never sets it.
- Human control: scans are ephemeral, sightings persist only after explicit confirmation, and high-risk navigation uses a warning with **Continue Anyway**, not a hard block.
- Privacy by design: fragments are removed, sensitive query values are redacted, provenance is retained, and users see a disclosure before a full URL is sent to an external provider.
- Deadline discipline: the active arbitrary browser tab is the long-term target; a Chrome extension is stretch-only after submission readiness.

## Documentation

- [Vision brief](docs/vision-brief.md)
- [ADR 0001: architecture and deadline boundary](docs/adr/0001-mvp-boundary.md)
- [Glossary](docs/glossary.md)
- [Devpost compliance matrix](docs/devpost-compliance-matrix.md)
- [Three-day action plan](docs/three-day-action-plan.md)
- [Sub-three-minute demo plan and resources](docs/demo-workflow.md)
- [Vision interview record](docs/vision-interview.md)
- [Frozen Luna critic input v1.0.0](docs/deliberation/watch-dog-vision-input-v1.0.0.md)
- [Raw Luna critique v1.0.0](docs/deliberation/gpt-5.6-luna-critique-v1.0.0.md) and [reconciliation v1.0.1](docs/deliberation/reconciliation-v1.0.1.md)

## License

Licensed under the [Apache License 2.0](LICENSE).
