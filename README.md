# Watch Dog

Watch Dog is a WebMCP-powered, evidence-first URL risk inspector. It helps people and agents examine the links on a page without pretending that an absence of threat-intelligence matches proves safety.

## Approved MVP

Two entry modes are equal, protected MVP features:

1. **Paste Scan** accepts a URL through a bounded, SSRF-aware server fetch path. A user may instead paste HTML for local-only parsing; pasted HTML never causes embedded resources to load.
2. **Live Page Scan Demo** inspects the rendered DOM of a fixed, safe, Watch Dog-owned same-origin reference page when invoked. It reads the live anchors at that moment, including a link inserted after page load, then sends the extracted candidates through the same analysis pipeline as Paste Scan.

The Live Page Scan Demo is intentionally not arbitrary active-tab scanning. A normal website cannot inspect unrelated third-party tabs. That capability requires a future browser extension with explicit host permissions; the Chrome extension is deferred beyond the submission.

Both modes converge on one pipeline:

`extraction -> canonicalization -> deterministic rules -> provider adapters -> evidence aggregation -> result UI`

The result presents a categorical risk label, a separate evidence-confidence assessment, provenance, freshness, supporting evidence, contradicting evidence, and typed failure/uncertainty states. A provider no-match is `no_known_match`, never “safe.”

## WebMCP boundary

The reference page registers a real `inspect_current_page` tool with `document.modelContext.registerTool(...)`. Its execution callback performs rendered-DOM extraction at invocation time, for example by iterating `document.querySelectorAll('a[href]')`; it does not return a hard-coded URL list or prerecorded scan.

The MVP may also expose read-only `scan_url` and `get_scan_result` tools. It exposes no navigation tool. Any Watch Dog-mediated navigation remains a normal UI action and uses a warning/Continue Anyway interstitial when warranted.

## Trust boundary

- Deterministic code and recognized providers own the official result.
- The agent can explain evidence and ambiguity, but cannot set verdicts, promote reports, or persist data.
- Page content, pasted HTML, provider text, and community reports are untrusted data and are never executed or followed as instructions.
- Scans are ephemeral. Only a user-confirmed, sanitized sighting may persist.
- Community volume alone cannot promote a target to known malicious; promotion requires recognized-provider corroboration or an administrator decision.
- One live provider is required. Fixtures cover deterministic success and failure states; a second live provider is expendable before either protected scan mode.

## Deadline and submission

The WebMCP Challenge deadline is **September 3, 2026 at 1:00 PM PDT (20:00 UTC)**. The submission must include a working hosted URL, a public repository with all required source/instructions and a visible open-source license, an English project description, and a public YouTube demo with audio lasting less than three minutes.

The repository is public and licensed under [Apache License 2.0](LICENSE).

## Documentation

- [Vision brief](docs/vision-brief.md)
- [ADR 0001](docs/adr/0001-mvp-boundary.md)
- [Threat model](docs/threat-model.md)
- [Glossary](docs/glossary.md)
- [Independent deliberation record](docs/independent-deliberation.md)
- [Devpost compliance matrix](docs/devpost-compliance.md)
- [Three-day plan](docs/three-day-plan.md)
- [Demo script and resources](docs/demo-script-and-resources.md)
- [Acceptance criteria](docs/acceptance-criteria.md)

## Security

Do not put live malicious URLs, secrets, credentials, or private browsing material in public issues or fixtures. See [SECURITY.md](SECURITY.md) and the [threat model](docs/threat-model.md).
