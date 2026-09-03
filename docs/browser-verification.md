# Local browser verification

This repository includes a pinned Playwright/Chromium acceptance and operator-invoked recording harness. Its local evidence does not prove deployment, provider access, supported Chrome/WebMCP behavior, recording publication, or submission acceptance.

The credential-bound deployment workflow separately installs Google Chrome stable, proves its reported product/version is 149 or newer, launches that exact installed binary with experimental web-platform features enabled, and requires native `document.modelContext` discovery and invocation against the exact deployed revision. Its sanitized artifact retains the product/version, tool names, invocation outcomes, screenshots and recordings, but no browser binary path, credential, cookie, CSRF value, API key, raw provider response or scan identifier.

## Isolation boundary

The acceptance image pins Playwright 1.62.1, Wrangler 4.127.1, matching Chromium, the tracer package, BuildKit, and the SBOM generator. Setup may acquire those exact dependencies; runtime is one disposable `--network none` container with no published port, unprivileged UID/GID, read-only root, all capabilities dropped, `no-new-privileges`, private namespaces, task-owned `/out`, and memory-backed scratch space. It receives no credential, Docker socket, device, host namespace, or named-volume mount.
Wrangler, workerd, the strict `watch.example:443` CONNECT shim, Playwright, Chromium, probes, and descendants share that boundary. Browser controls disable background networking, updates, telemetry, components, discovery, QUIC, WebRTC escape, preconnect, DNS prefetch/DoH, and direct resolution. Full trace-ancestry closure fails on successful non-loopback traffic or DNS, external authority acceptance, origin bypass, an untraced descendant, or a trace gap; kernel-rejected attempts remain reported containment evidence.

## Evidence and commands

Run `npm ci --ignore-scripts --no-audit --no-fund`, `npm run typecheck`, `npm test`, and `npm audit --audit-level=high` in clean setup. The root then builds `Dockerfile.browser-acceptance` with the ledgered immutable builder and launches its exact image under the boundary above. Normal acceptance uses one worker and zero retries, retains no successful-run media, and proves bounded failure-only screenshot, video, trace, and error-context capture. Never relax the isolation flags.
For an operator-only headed recording, start the already required local Wrangler/CONNECT boundary and run `npm run browser:record`; it reuses the asserted journey and writes local artifacts that are not public evidence by themselves.
