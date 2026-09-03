# Watch Dog

Watch Dog is an evidence-first URL risk inspector for people and browser agents. It analyzes links, explains the evidence behind each result, and represents uncertainty honestly: a threat provider returning no match means `no_known_match`, never “safe.”

## How it works

Watch Dog supports two complementary scan modes:

1. **Paste Scan** accepts a URL through a bounded, SSRF-aware fetch path or parses pasted HTML locally without executing scripts or loading embedded resources.
2. **Live Page Scan** inspects the rendered links on a Watch Dog-owned reference page when its WebMCP tool is invoked. This demonstrates genuine invocation-time DOM inspection, including links inserted after page load.

Both modes feed the same pipeline:

`extraction -> canonicalization -> deterministic rules -> provider adapters -> evidence aggregation -> result UI`

Results keep distinct concepts separate:

- a categorical risk label;
- an analysis state, including unknown, unscannable, provider error, stale, or conflicting;
- confidence based on evidence quality, freshness, independence, and agreement;
- supporting and contradicting evidence with provenance; and
- clear limitations and provider status.

## WebMCP

The reference page exposes a read-only `inspect_current_page` tool. Its callback extracts the page's current rendered anchors and sends them through the same analysis pipeline as Paste Scan. Supporting read-only tools may start a URL scan or retrieve a session-owned result.

Watch Dog does not claim access to unrelated browser tabs. Arbitrary active-tab inspection requires a future browser extension with explicit host permissions. The product exposes no agent-controlled navigation tool.

## Trust model

- Deterministic code and normalized provider observations own the official result.
- Agents may explain evidence and ambiguity, but cannot change verdicts, persist reports, promote sightings, or navigate.
- Page content, pasted HTML, provider text, and community reports are untrusted data. Watch Dog does not execute or obey them.
- Scans are ephemeral. Any future persistence requires explicit human confirmation and a sanitized, quarantined record.
- Community volume alone cannot establish that a target is malicious.
- External URL disclosure requires clear provider identification and consent.
- Google Safe Browsing lookups send the canonical address-bar URL to Google from
  the server. They are enabled only with a server secret and are restricted to
  non-commercial use; a no-match is never a safety guarantee.

See the [threat model](docs/threat-model.md) for the complete security boundary.
Provider-specific terms, attribution, privacy, and failure semantics are in the
[Google Safe Browsing integration note](docs/google-safe-browsing.md).

## Local browser verification

The bounded [browser verification profile](docs/browser-verification.md) uses
Playwright's pinned bundled Chromium at the visible default-port origin
`https://watch.example`. A byte-transparent loopback CONNECT connector carries
encrypted browser traffic to the real local Wrangler HTTPS Worker; it does not
terminate TLS or serve application content. This local registration-shim run is
not deployment or supported-browser proof. Issues #10, #11, and #12 separately
own deployment, supported-browser verification, and public audio/video evidence.

## Project status

Watch Dog is currently pre-release. This repository contains the approved product architecture, security requirements, and acceptance criteria; application implementation is tracked in [issue #1](https://github.com/tyu41275/watch-dog/issues/1).

The project is licensed under the [Apache License 2.0](LICENSE).

## Documentation

- [Product vision](docs/vision-brief.md)
- [Architecture decision](docs/adr/0001-mvp-boundary.md)
- [Threat model](docs/threat-model.md)
- [Google Safe Browsing integration](docs/google-safe-browsing.md)
- [Local browser verification](docs/browser-verification.md)
- [Acceptance criteria](docs/acceptance-criteria.md)
- [Glossary](docs/glossary.md)
- [Documentation index](docs/README.md)

## Security

Do not publish live malicious URLs, credentials, secrets, or private browsing material in issues or fixtures. Follow [SECURITY.md](SECURITY.md) when reporting a vulnerability.
