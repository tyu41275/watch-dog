# Browser verification and recording boundary

## Acceptance profile

`npm run test:browser` launches Wrangler 4.127.1 over local HTTPS with synthetic test-only environment bindings, then runs Playwright against the actual Worker, asset, authentication, Durable Object, and browser DOM seams. It checks:

- generic login denial and a successful signed session;
- browser-observed `Secure`, `HttpOnly`, `SameSite=Strict` cookie attributes;
- inert pasted HTML, deduplication, rejection, and shared result rendering;
- typed `not_configured` provider and private-address fetch-refusal states;
- absence of active injected image, SVG, or script nodes;
- the fixed Watch Dog-owned reference route and before/after delayed anchor;
- invocation-time posted DOM candidates and relative-link resolution;
- the three bounded read-only/untrusted WebMCP tool contracts; and
- visible evidence, provider, uncertainty, and limitation fields without a “safe” claim.

The default project uses Playwright’s pinned Chromium because no branded Chrome is assumed on a fresh clone. To use an installed branded Chrome channel, run:

```sh
WATCHDOG_BROWSER_CHANNEL=chrome npm run test:browser
```

The browser injects `document.modelContext` only to discriminate registration and invocation integration when the local browser has no enabled WebMCP implementation. This shim is labeled integration evidence. It is not Chrome 149+, ChatGPT in-app-browser, or deployed WebMCP acceptance evidence. WD-P0-10 / issue #11 must reuse this stable journey against the immutable deployed revision in an actually supported browser.

Trace is retained only on first retry; screenshots and video only on failure. Each run uses a unique timestamped output directory (or the explicit `WATCHDOG_EVIDENCE_ID`) so a later run cannot erase earlier evidence. Local `.wrangler/` and `test-results/` state is ignored by Git but remains available until an operator deliberately archives or removes it.

## Operator recording profile

`npm run record:demo` is a separate headed, operator-invoked rehearsal profile. It reuses the tested login and scan helpers, records video, and captures sanitized Paste and Live Page screenshots beneath a timestamped `artifacts/operator-recording/` directory (or `WATCHDOG_RECORDING_ID`). It does not replace acceptance assertions and its output is ignored by Git.

Playwright video has no English audio by itself. A truthful submission capture must use OBS with live English narration, or add and verify an English narration track in post-production. WD-P0-11 / issue #12 owns publication, public playback, duration, audio, sanitized-content, and exact-revision receipts.
