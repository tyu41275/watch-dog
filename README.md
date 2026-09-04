# Watch Dog

Watch Dog is an evidence-first URL risk inspector for people and browser agents. It analyzes links, explains the evidence behind each result, and represents uncertainty honestly: a threat provider returning no match means `no_known_match`, never “safe.”

- Live HTTPS app: https://watch-dog.tytechnologiesconsulting.workers.dev/
- Public demo video: [download the 2:46 English MP4](https://github.com/tyu41275/watch-dog/releases/download/watchdog-demo-2026-09-03/watchdog-youtube-final-pronunciation-fixed.mp4)
- License: [Apache-2.0](LICENSE)

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

## Local browser harness

The pinned Playwright harness exercises real local Wrangler HTTPS, authentication, Assets, Durable Objects, sessions, scans, and WebMCP registration in one networkless container. Its evidence is local-only and makes no deployment, provider, supported-browser, recording-publication, or submission claim. See [local browser verification](docs/browser-verification.md).

## Install, test, and run

Use Node.js 22 or newer. From a fresh clone:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run check:protocol
npm run typecheck
npm test
npm run build
npm audit --audit-level=high
```

For local development, copy `.env.example` to an ignored `.dev.vars`, supply local-only values, and run `npm run dev`. No credential has a default. Keep Google Safe Browsing disabled unless an authorized server-side key is present; the UI still requires explicit disclosure consent for every live invocation. See [exact deployment](docs/deployment.md), [judge testing](docs/judge-testing.md), and [provider terms and bounds](docs/google-safe-browsing.md).

## Project status

The deployed challenge candidate implements both protected scan modes, the shared evidence pipeline, static judge authentication, a live Google Safe Browsing adapter, and three read-only WebMCP tools. Public evidence and any remaining external submission gate are tracked in the [submission record](docs/submission-record.md) and [issue #12](https://github.com/tyu41275/watch-dog/issues/12).

The project is licensed under the [Apache License 2.0](LICENSE).

## Documentation

- [Product vision](docs/vision-brief.md)
- [Architecture decision](docs/adr/0001-mvp-boundary.md)
- [Threat model](docs/threat-model.md)
- [Google Safe Browsing integration](docs/google-safe-browsing.md)
- [Acceptance criteria](docs/acceptance-criteria.md)
- [Local browser verification](docs/browser-verification.md)
- [Judge testing instructions](docs/judge-testing.md)
- [English submission description](docs/devpost-description.md)
- [Submission and freeze record](docs/submission-record.md)
- [Glossary](docs/glossary.md)
- [Documentation index](docs/README.md)

## Security

Do not publish live malicious URLs, credentials, secrets, or private browsing material in issues or fixtures. Follow [SECURITY.md](SECURITY.md) when reporting a vulnerability.
