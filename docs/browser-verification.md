# Browser verification and recording boundary

## Local acceptance profile

Install and run the pinned local browser profile with:

```sh
npm ci
PLAYWRIGHT_BROWSERS_PATH=0 npx playwright install chromium
npm run test:tunnel
WATCHDOG_EVIDENCE_ID=local-check PLAYWRIGHT_BROWSERS_PATH=0 npm run test:browser
```

The profile runs exactly two zero-retry tests with one worker and finite test,
suite, startup, and shutdown limits. Playwright 1.62.1 uses its bundled Chromium.
A fixed loopback HTTP CONNECT connector maps only `watch.example:443` to the
local Wrangler listener. It handles proxy control only: Chromium owns TLS and
the visible origin remains exactly `https://watch.example`; Wrangler 4.127.1 is
the sole TLS, Worker, Assets, authentication, Durable Object, and application
server. The connector does not resolve names, inspect tunneled bytes, or serve
content.

The journey checks browser-observed session-cookie flags, login and consent,
inert hostile-looking Paste input, deduplication and typed rejection, provider
and safe-fetch failure states, structured evidence and limitations, stale
result suppression, the exact reference-page 308-to-200 chain, invocation-time
DOM extraction, relative URL resolution, three bounded read-only/untrusted
tools, callback effects, cancellation, recovery, and partial-registration
cleanup. Results are read only from session-owned inert `#results.textContent`.

The browser injects `document.modelContext` only as a registration/invocation
shim when exercising Watch Dog's real browser registration path. It supplies no
scan data or application response. The connector and shim are local integration
evidence, not supported Chrome 149+, ChatGPT in-app-browser, deployment, live
provider, or production-readiness evidence. Issue #10 owns deployment and issue
#11 owns supported-browser proof against the exact deployed revision.

Successful runs retain no per-test screenshots, trace, or video. Failure media
is bounded beneath the unique `test-results/playwright/<evidence-id>` directory;
the operator decides when to archive or exactly remove it. Local `.wrangler/`
and test output are ignored by Git.

## Separate operator recording profile

The following is a separate headed operator action and is not run by acceptance:

```sh
WATCHDOG_RECORDING_ID=<operator-id> PLAYWRIGHT_BROWSERS_PATH=0 npm run record:demo
```

It calls the same asserted journey and captures only the declared synthetic
Paste and Live checkpoints in a unique ignored recording directory. It neither
skips assertions nor proves deployment, browser support, publication, or
submission. Playwright video contains no English audio by itself. Issue #12 owns
sanitized public video, verified English audio, playback, duration, publication,
and submission receipts.
