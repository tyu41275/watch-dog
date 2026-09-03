# Local browser verification

This repository includes a pinned Playwright/Chromium acceptance harness for local evidence only. It does not prove deployment, provider access, supported Chrome/WebMCP behavior, an operator recording, audio, video publication, or submission acceptance.

## Isolation boundary

The acceptance image pins Playwright 1.62.1, Wrangler 4.127.1, Chromium from the matching Playwright image, and the tracer package. A separately bounded setup phase may acquire those exact dependencies. The runtime itself is one disposable container started by exact image ID with:

- `--network none`, no published port, and no Docker network;
- an unprivileged numeric user, a read-only root filesystem, all capabilities dropped, default seccomp, and `no-new-privileges`;
- writable task-owned `/out` plus memory-backed `/tmp`, `/state`, and `/dev/shm`; and
- no credential, Docker-socket, device, host namespace, or named-volume mount.

Wrangler, the CONNECT shim, Playwright, Chromium, probes, and descendants share that boundary. Wrangler terminates real local HTTPS at numeric loopback. Chromium sees only `https://watch.example` through the fixed loopback proxy. The proxy accepts only `CONNECT watch.example:443` and dials only `127.0.0.1:8787`.

The browser launch disables background networking, component updates and extensions, default apps, domain reliability, sync, pings, QUIC, client-side phishing lookups, breakpad, preconnect, DNS prefetch, direct WebRTC UDP, DoH upgrades, Media Router, network-time queries, optimization-hint fetching, and Safe Browsing real-time lookup. Kernel isolation remains defense in depth: full descendant tracing reports every Internet-socket attempt. Successful non-loopback traffic, successful DNS, an external CONNECT authority, direct bypass, missing descendant, or trace gap fails acceptance. A kernel-rejected attempt is reported as containment evidence and follow-up.

## Evidence and commands

Run unit and static checks in a clean setup environment:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run typecheck
npm test
npm audit --audit-level=high
```

The root acceptance workflow builds `Dockerfile.browser-acceptance` with the pre-ledgered immutable BuildKit engine and then launches the exact image with the restrictions above. The container exports bounded JSON summaries, toolchain identities, process censuses, test reports, failure-only artifacts, and restricted raw traces before teardown. Do not run it with host networking, extra capabilities, relaxed seccomp, or a browser-sandbox override.

The normal profile has one worker, zero retries, and retains screenshots, video, and trace only on failure. A controlled failing probe establishes that policy without becoming a product verdict. Successful acceptance generates no green video. The headed profile is operator-invoked only:

```sh
npm run browser:record
```
It reuses the asserted journey and writes local recording artifacts; those artifacts are not produced by acceptance and are not public evidence by themselves.
