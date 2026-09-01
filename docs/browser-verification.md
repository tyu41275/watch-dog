# Browser verification and recording boundary

## Acceptance profile

`npm run test:browser` launches Wrangler 4.127.1 over local HTTPS with synthetic test-only bindings, then runs Playwright against the actual Worker, assets, authentication, Durable Object, and browser DOM seams. It checks generic denial and signed sessions; browser-observed `Secure`/`HttpOnly`/`SameSite=Strict`; consent; inert HTML, deduplication, rejection and shared rendering; typed provider/fetch failures; no active injected nodes; fixed reference routing; delayed invocation-time DOM candidates and relative resolution; all three bounded read-only/untrusted tools; visible tool effects; and separated evidence, provider, uncertainty and limitations without a “safe” claim.

The default project uses Playwright’s pinned Chromium because no branded Chrome is assumed on a fresh clone. To use an installed branded Chrome channel, run:

```sh
WATCHDOG_BROWSER_CHANNEL=chrome npm run test:browser
```

The browser injects `document.modelContext` only to discriminate registration and invocation integration when the local browser has no enabled WebMCP implementation. This shim is labeled integration evidence. It is not Chrome 149+, ChatGPT in-app-browser, or deployed WebMCP acceptance evidence. WD-P0-10 / issue #11 must reuse this stable journey against the immutable deployed revision in an actually supported browser.

Trace, screenshots, and video are retained only on failure; the acceptance profile does not retry. Each run uses a unique timestamped output directory (or the explicit `WATCHDOG_EVIDENCE_ID`) so a later run cannot erase earlier evidence. Local `.wrangler/` and `test-results/` state is ignored by Git but remains available until an operator deliberately archives or removes it.

## Operator recording profile
`npm run record:demo` is a separate headed, operator-invoked rehearsal profile. It reuses the tested login and scan helpers, records video, and captures sanitized Paste and Live Page screenshots beneath a timestamped `artifacts/operator-recording/` directory (or `WATCHDOG_RECORDING_ID`). It does not replace acceptance assertions and its output is ignored by Git.

Playwright video has no English audio by itself. A truthful submission capture must use OBS with live English narration, or add and verify an English narration track in post-production. WD-P0-11 / issue #12 owns publication, public playback, duration, audio, sanitized-content, and exact-revision receipts.
