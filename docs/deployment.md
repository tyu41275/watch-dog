# Exact deployment

Issue #10 uses the single manual `deploy.yml` workflow and the default HTTPS `workers.dev` surface. It deploys the reviewed SHA only after proving that SHA is merged into `main`; previews remain disabled. Assets, the `SessionCoordinator` v1 SQLite migration, `BUILD_REVISION`, and `GOOGLE_SAFE_BROWSING_ENABLED=true` are deployed together.

The workflow consumes only `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN`, `WATCH_DOG_JUDGE_USERNAME`, `WATCH_DOG_JUDGE_PASSWORD`, `WATCH_DOG_SESSION_SIGNING_SECRET`, and `GOOGLE_SAFE_BROWSING_API_KEY`. Values flow directly to Wrangler or the verifier and must never be printed, saved in the repository, or published as evidence.

After independent Reviewer and QA PASS on the identical PR head/tree/base, reauthenticate that state and run the whole merge/ref/dispatch transition once:

```sh
node scripts/deployment-transition.mjs --pr <explicit-number> --expected-head <40-lowercase-hex-sha>
```

Use `--check-only` before acceptance to authenticate the explicit PR, head, base, current main, source ref, repository, and workflow without mutation. The transition is resumable: it never discovers a PR, never overwrites a drifted ref, proves merged ancestry, and treats an ambiguous dispatch outcome as terminal instead of dispatching again. Keep its Git-directory journal until the matching run and sanitized durable evidence are authenticated; root then removes it during final cleanup.

The run repeats clean install, protocol, typecheck, 145+ tests, build, high-severity audit, generated cleanliness, Wrangler dry-run, and the real link-bearing public control. Deployment acceptance additionally checks exact revision, login/cookie/session/CSRF/logout/ownership, genuine Google observations for both control targets, public fetch, loopback/private/rebinding-style/redirect refusal, and root/reference assets. Only sanitized state classes and identifiers may be retained.

The public-egress control is the fixed `https://httpbin.org/links/3/0` response. The verifier binds its exact byte count and digest, its two extracted relative links, one DNS-admitted public hop, and the corresponding live provider observations. This replaced the equivalent fixed-shape httpbingo variant after a secret-safe production comparison showed that Cloudflare egress accepted httpbin while httpbingo returned a non-2xx response to the Worker. The verifier authenticates a correct session before exercising one generic wrong-password denial, so a stale throttle record cannot make the negative probe mask valid deployment credentials.

## Production DNS resolution

URL-fetch admission uses Cloudflare Workers' supported [`node:dns`](https://developers.cloudflare.com/workers/runtime-apis/nodejs/dns/) implementation and queries both `A` and `AAAA` records before every hop. Cloudflare documents that these queries use Cloudflare DNS over HTTPS and consume Worker subrequests. A missing record family is empty only for `ENODATA`/`ENOTFOUND`; other failures fail closed. The fetch machine retains its per-operation and total deadlines, 32-address cap, public-address validation, mixed/private rejection, redirect revalidation and sanitized hop counts.

The configured `2026-08-31` compatibility date already enables Node.js compatibility by default. Cloudflare documents this for dates on or after `2026-08-04`, so an explicit `nodejs_compat` flag would be redundant and would not change a manual `fetch()` DNS request into the supported runtime API. A separate resolver Worker or service binding would add deployment topology without strengthening the existing address-admission boundary.
