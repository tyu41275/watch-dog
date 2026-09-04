# Watch Dog

Watch Dog is an evidence-first URL risk inspector for people and browser agents. It analyzes URLs and inert pasted HTML, explains the evidence behind each result, and keeps uncertainty explicit: a provider no-match is `no_known_match`, never a claim that a URL is safe.

The implemented app includes protected Paste Scan and Live Page Scan flows, static operator authentication, ephemeral session-owned results, Google Safe Browsing v5 integration, and three read-only WebMCP tools. It is not a general-purpose security control or a safety guarantee.

- Health: https://watch-dog.tytechnologiesconsulting.workers.dev/api/health
- Deployment revision check: https://watch-dog.tytechnologiesconsulting.workers.dev/api/revision
- Public demo: [2:46 English MP4](https://github.com/tyu41275/watch-dog/releases/download/watchdog-demo-2026-09-03/watchdog-youtube-final-pronunciation-fixed.mp4)
- License: [Apache-2.0](LICENSE)

## Architecture and security boundary

Watch Dog has two entry modes that feed the same deterministic pipeline:

`extraction -> canonicalization -> deterministic rules -> provider adapters -> evidence aggregation -> result UI`

- **Paste Scan** accepts one HTTP(S) URL through a bounded, SSRF-aware fetch path, or parses pasted HTML without executing scripts or loading embedded resources.
- **Live Page Scan** inspects the rendered anchors on Watch Dog's fixed `/reference` page at WebMCP invocation time, including links inserted after page load.

The application, not an agent or provider, owns the official risk label, analysis state, and confidence. Page content, pasted HTML, anchor text, and provider output remain untrusted data. Live Page Scan cannot inspect unrelated tabs; that would require a future extension with explicit host permissions. Scans are ephemeral, and only hashed login-throttle records are written to Durable Object storage.

See the [threat model](docs/threat-model.md), [architecture decision](docs/adr/0001-mvp-boundary.md), and [security policy](SECURITY.md) before changing these boundaries.

## Prerequisites

- Git.
- Node.js 22 or newer and npm. CI deploys with Node.js 24.
- A Cloudflare account for deployment. The repository pins Wrangler 4.127.1.
- Docker with BuildKit for the isolated Playwright/Chromium acceptance harness.
- Google Chrome 149 or newer, or a Chromium build that exposes native WebMCP, for manual WebMCP testing. The production harness has verified Google Chrome 152.
- Optional: a Google Safe Browsing v5 API key authorized for the intended non-commercial use.

Do not put credentials in commands, issues, logs, screenshots, recordings, or tracked files.

## Clone and install

From a fresh checkout of `main`:

```sh
git clone https://github.com/tyu41275/watch-dog.git
cd watch-dog
npm ci --ignore-scripts --no-audit --no-fund
```

`npm ci` consumes the committed lockfile. Do not substitute `npm install` when reproducing CI or a reviewed deployment.

## Environment configuration

[`.env.example`](.env.example) is the authoritative local template. Copy it to Wrangler's ignored local file and restrict its permissions:

```sh
cp .env.example .dev.vars
chmod 600 .dev.vars
```

Edit `.dev.vars` locally without sharing or committing its values:

| Name | Requirement |
| --- | --- |
| `ADMIN_USERNAME` | Non-empty. Leading and trailing whitespace is removed. |
| `ADMIN_PASSWORD` | Non-empty static operator password. |
| `SESSION_SIGNING_KEY` | Non-empty and at least 32 characters; use an independently generated high-entropy value. |
| `GOOGLE_SAFE_BROWSING_ENABLED` | The exact string `true` enables the adapter. Keep `false` for offline/default development. |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Server-only v5 key. Leave empty while the adapter is disabled. |

There are no credential defaults. Authentication fails closed if any of the first three values is absent or if `SESSION_SIGNING_KEY` is too short. `.dev.vars` is ignored by Git; verify before adding any local configuration with `git check-ignore .dev.vars`.

`BUILD_REVISION`, `ASSETS`, and `SESSION_COORDINATOR` are deployment bindings, not entries in `.env.example`: the deployment workflow supplies the revision, while `wrangler.jsonc` defines both Cloudflare bindings.

## Local Wrangler development

After configuring `.dev.vars`:

```sh
npm run dev
```

Wrangler serves the Worker and `public/` assets, creates the local `SessionCoordinator` Durable Object namespace, and prints the local origin (normally `http://localhost:8787`). Verify the public route in another terminal:

```sh
curl --fail --show-error http://localhost:8787/api/health
```

Open the exact origin printed by Wrangler and sign in with the local values. Current browsers treat `localhost` as a potentially trustworthy origin; use Wrangler HTTPS if a browser policy refuses the Secure session cookie. Stop Wrangler with Ctrl-C. To choose a different port:

```sh
npm run dev -- --port 8788
```

Local state is under `.wrangler/`. Never copy production credentials or production Durable Object data into local development.

## Authentication setup

This application intentionally uses one static operator identity, not end-user accounts or OAuth. A successful same-origin login creates a 15-minute `Secure`, `HttpOnly`, `SameSite=Strict` cookie. Authenticated state-changing calls (logout and scans) also require the session's CSRF token and an exact same-origin request. Results are owned by that session and expire after 10 minutes.

For local development, use the first three values in `.dev.vars`. For production, configure these GitHub Actions secrets; the workflow maps them to the Worker's runtime names without writing them to the repository:

| GitHub Actions secret | Worker runtime name |
| --- | --- |
| `WATCH_DOG_JUDGE_USERNAME` | `ADMIN_USERNAME` |
| `WATCH_DOG_JUDGE_PASSWORD` | `ADMIN_PASSWORD` |
| `WATCH_DOG_SESSION_SIGNING_SECRET` | `SESSION_SIGNING_KEY` |

After five failed attempts within five minutes, the next attempt for the hashed IP-and-username fingerprint is blocked for ten minutes. Responses intentionally use generic login errors. Rotate the signing secret to invalidate all existing sessions.

## Google Safe Browsing

Watch Dog's only live provider adapter calls Google Safe Browsing v5 `urls.search` from the Worker. When the adapter is enabled and configured, every accepted canonical address-bar URL is disclosed to Google. The client therefore requires explicit per-invocation consent for every scan, even when the adapter is disabled or misconfigured. Keys stay server-side in `X-Goog-Api-Key`; they must never enter URLs, assets, results, or evidence.

Important limitations:

- The Safe Browsing API is for non-commercial use unless the operator has a separate Google agreement. A commercial service needs an appropriately licensed product such as Web Risk or another agreement.
- Google states that protection is not comprehensive or error-free. A no-match is rendered only as `no_known_match`; Watch Dog never calls it “safe.”
- Quota, timeout, unavailable, malformed-response, and disabled states remain visible provider states rather than being converted into verdicts.

For local testing, place the key only in `.dev.vars` and change `GOOGLE_SAFE_BROWSING_ENABLED` to the exact string `true`. For production, configure the `GOOGLE_SAFE_BROWSING_API_KEY` GitHub Actions secret; the deploy workflow sets the enable flag. Test only with a Google-provided inert test URL or another permitted, non-malicious input, and accept the UI disclosure for that invocation.

Read [Google Safe Browsing integration](docs/google-safe-browsing.md) for request bounds, response mapping, terms, privacy, and authoritative Google links.

## Build, typecheck, and unit tests

Run the same source gates used by deployment:

```sh
npm run check:protocol
npm run typecheck
npm test
npm run build
npm audit --audit-level=high
```

`npm test` runs a build and then the Node test suite. `npm run build` verifies the generated browser protocol and compiles TypeScript into ignored `dist/`. A passing run must leave tracked generated protocol files unchanged:

```sh
git status --short
```

## Playwright browser acceptance

`npm run browser:acceptance` is the inner Playwright command; it expects the repository's HTTPS Wrangler supervisor, strict CONNECT shim, and generated test credentials. Run the complete pinned harness through `Dockerfile.browser-acceptance` instead of invoking that script against an arbitrary server:

```sh
docker build --pull --tag watch-dog-browser-acceptance \
  --file Dockerfile.browser-acceptance .

acceptance_out="$(mktemp -d)"
mkdir "$acceptance_out/raw-trace"
docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 256 \
  --memory 2g \
  --shm-size 512m \
  --user "$(id -u):$(id -g)" \
  --tmpfs "/state:rw,nosuid,nodev,mode=0700,uid=$(id -u),gid=$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,mode=1777 \
  --mount "type=bind,src=$acceptance_out,dst=/out" \
  watch-dog-browser-acceptance

node --input-type=module -e \
  'const r=JSON.parse(await import("node:fs").then(m=>m.readFileSync(process.argv[1],"utf8"))); if(r.result!=="PASS") process.exit(1)' \
  "$acceptance_out/runtime-result.json"
```

The container runs real local Wrangler HTTPS, Assets, Durable Objects, login/session/CSRF behavior, Paste and Live scans, WebMCP registration, and retained-on-failure Playwright evidence with network disabled. A local Chromium shim exercises registration semantics; it does not prove native WebMCP. See [local browser verification](docs/browser-verification.md) for the isolation and evidence boundary.

## Cloudflare deployment and Durable Objects

[`wrangler.jsonc`](wrangler.jsonc) is the deployment authority:

- Worker: `watch-dog`, entrypoint `src/worker/index.ts`, compatibility date `2026-08-31`.
- Assets binding: `ASSETS` -> `./public`, with `run_worker_first: true`.
- Durable Object binding: `SESSION_COORDINATOR` -> exported class `SessionCoordinator`.
- Durable Object migration: tag `v1`, `new_sqlite_classes: ["SessionCoordinator"]`.
- Default `workers.dev` deployment enabled; preview URLs disabled.

Do not rename the binding or class, remove/reuse migration tag `v1`, or deploy the assets separately from the Worker. Wrangler applies the first Durable Object migration during deployment. Future storage migrations require a new, monotonically advancing migration tag.

The supported production path is the manual [Deploy exact Watch Dog revision](.github/workflows/deploy.yml) GitHub Actions workflow. Configure these repository secrets without exposing their values:

- `CLOUDFLARE_ACCOUNT_ID`
- `CLOUDFLARE_API_TOKEN`
- `WATCH_DOG_JUDGE_USERNAME`
- `WATCH_DOG_JUDGE_PASSWORD`
- `WATCH_DOG_SESSION_SIGNING_SECRET`
- `GOOGLE_SAFE_BROWSING_API_KEY`

The Cloudflare token must be scoped to the target account and allowed to deploy Workers, Assets, and Durable Objects. The workflow accepts a full 40-character lowercase commit SHA already merged into `main`; it reruns install, protocol, typecheck, unit, build, audit, public-control, and Wrangler dry-run gates before deploying. It supplies plaintext `BUILD_REVISION` and `GOOGLE_SAFE_BROWSING_ENABLED=true`, injects the four Worker secrets without logging them, applies the Durable Object configuration, and verifies the live deployment.

For a reviewed PR, use the repository's authenticated, resumable review-to-deploy transition documented in [exact deployment](docs/deployment.md). First verify that the explicit PR number and exact head SHA still match without changing anything:

```sh
node scripts/deployment-transition.mjs --check-only \
  --pr <explicit-pr-number> --expected-head <40-lowercase-head-sha>
```

After independent Reviewer and QA PASS on that identical head/tree/base, run the transition without `--check-only`:

```sh
node scripts/deployment-transition.mjs \
  --pr <explicit-pr-number> --expected-head <40-lowercase-head-sha>
```

The second command authenticates and merges that exact PR, proves merged ancestry, dispatches the matching deployment once, and resumes an already-dispatched transition without guessing another run. Do not run it unless the reviewed change is intended for production. Keep its Git-directory journal until the matching workflow run and sanitized evidence have been authenticated.

After deployment, compare the exact reviewed head SHA with `/api/revision`, check `/api/health`, and complete an authenticated permitted scan. Keep all verification output sanitized.

## Native WebMCP in Chrome/Chromium

WebMCP is experimental. For local/manual testing in a supported Google Chrome 149+ or compatible Chromium build:

1. Open `chrome://flags/#enable-webmcp-testing`.
2. Set **WebMCP for testing** to **Enabled** and relaunch the browser. For automation, the production harness uses `--enable-experimental-web-platform-features` and rejects Chrome versions below 149.
3. Use a clean profile, open the production URL or your local origin, and authenticate.
4. Open `/reference` and wait for the delayed anchor. The page must report `WebMCP tools registered: inspect_current_page, scan_url, get_scan_result.`
5. In DevTools, confirm native discovery:

   ```js
   typeof document.modelContext === "object"
   ;(await document.modelContext.getTools()).map(({ name }) => name)
   ```

6. Invoke the page-inspection tool natively; accept the Google disclosure dialog for this invocation:

   ```js
   const tool = (await document.modelContext.getTools())
     .find(({ name }) => name === "inspect_current_page")
   await document.modelContext.executeTool(tool, "{}")
   ```

Expected discovery is exactly `inspect_current_page`, `scan_url`, and `get_scan_result`. Do not install a page shim: `document.modelContext.getTools()` and `executeTool()` must come from the browser. The [judge testing path](docs/judge-testing.md) and [browser verification record](docs/browser-verification.md) describe the accepted end-to-end flow.

## Available WebMCP tools

All three tools are read-only, treat content as untrusted, require the current authenticated session, and cannot navigate or alter a verdict.

| Tool | Input | Behavior |
| --- | --- | --- |
| `inspect_current_page` | `{}` | Reads current rendered anchors on Watch Dog's fixed `/reference` page and stores session-owned results. |
| `scan_url` | `{ targetUrl }` or `{ targetUrl, pastedHtml, baseUrl? }` | Scans one URL, or inert HTML using `baseUrl` (falling back to `targetUrl`) for relative links. Requires provider consent on every invocation. |
| `get_scan_result` | `{ scanId }` | Retrieves one 32-character lowercase hexadecimal result ID owned by the current session. |

## Troubleshooting

### Login or session failures

- Generic `401 invalid_credentials`: confirm all three auth names are present in `.dev.vars` or the mapped GitHub secrets, and that `SESSION_SIGNING_KEY` is at least 32 characters. Restart Wrangler after changing `.dev.vars`.
- `429` with `Retry-After`: the failed-login limit was exceeded; wait for the ten-minute block to expire. Do not bypass the Durable Object throttle.
- Login succeeds but the UI immediately signs out: use the same origin throughout, allow cookies, and confirm the browser accepts Secure cookies on the chosen local/HTTPS origin. Sessions expire after 15 minutes.
- Protected scan returns `401`: refresh/re-authenticate; the cookie, CSRF token, origin, and current session must all match.

### Provider failures

- `not_configured`: the enable value is not exact `true`, the API key is absent, or the key was not injected into the Worker.
- `provider_consent_required`: select the UI checkbox or accept the native WebMCP confirmation for that single invocation; consent is intentionally not remembered.
- `quota`, `timeout`, `unavailable`, or `malformed_response`: inspect the normalized provider state and Cloudflare logs, key restrictions, API enablement, and quota without logging the key or raw response. Do not reinterpret the failure as a clean result.
- `no_known_match`: the provider returned no recognized match. It is not a safety claim.

### Browser/WebMCP failures

- “WebMCP is unavailable”: confirm Chrome/Chromium is version 149+, enable `chrome://flags/#enable-webmcp-testing`, relaunch, and use a top-level page rather than an iframe.
- The page says tools registered but `getTools()` is absent: a shim or unsupported build is present. Retest in a clean supported profile with the native API.
- `inspect_current_page` fails: authenticate, use the canonical `/reference` route, wait for the delayed anchor, and accept that invocation's disclosure dialog.
- A Playwright command cannot reach `watch.example`: use the complete Docker harness above; the inner npm script depends on its Wrangler and CONNECT supervisors.

### Wrangler/deployment failures

- Local API calls fail while assets load: confirm `wrangler.jsonc` still contains `ASSETS`, `SESSION_COORDINATOR`, and the `v1` migration, then restart the full Worker rather than serving `public/` alone.
- Production login always returns `401`: verify the three mapped auth secrets and Durable Object binding exist; the Worker intentionally hides which dependency is missing.
- `/api/revision` returns `503`: deploy with a lowercase 40-character `BUILD_REVISION`; the GitHub workflow supplies the exact reviewed head SHA after authenticating its merged ancestry.
- GitHub Actions rejects the revision: fetch `main` and dispatch the exact full SHA already reachable from `origin/main`, not a branch name, short SHA, or unmerged PR head.
- Durable Object migration fails: keep the exported `SessionCoordinator` name and existing `v1` migration unchanged. Add a new migration tag for a real class/storage change.
- The deployed revision differs: do not retry blindly. Compare the workflow run, `/api/revision`, and exact reviewed head SHA, then follow the resumable procedure in [exact deployment](docs/deployment.md).

## Further documentation

- [Documentation index](docs/README.md)
- [Architecture decision: two scan modes, one pipeline](docs/adr/0001-mvp-boundary.md)
- [Threat model](docs/threat-model.md)
- [Security policy and private reporting](SECURITY.md)
- [Exact deployment](docs/deployment.md)
- [Google Safe Browsing integration](docs/google-safe-browsing.md)
- [Acceptance criteria](docs/acceptance-criteria.md)
- [Local and native browser verification](docs/browser-verification.md)
- [Judge testing instructions](docs/judge-testing.md)
- [Submission, revision, and freeze record](docs/submission-record.md)

Never publish live malicious URLs, credentials, secrets, cookies, CSRF tokens, private browsing material, or raw provider responses. Use the repository's Security tab for private vulnerability reports.
