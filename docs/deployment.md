# Exact deployment

Issue #10 uses the single manual `deploy.yml` workflow and the default HTTPS `workers.dev` surface. It deploys the reviewed SHA only after proving that SHA is merged into `main`; previews remain disabled. Assets, the `SessionCoordinator` v1 SQLite migration, `BUILD_REVISION`, and `GOOGLE_SAFE_BROWSING_ENABLED=true` are deployed together.

The workflow consumes only `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN`, `WATCH_DOG_JUDGE_USERNAME`, `WATCH_DOG_JUDGE_PASSWORD`, `WATCH_DOG_SESSION_SIGNING_SECRET`, and `GOOGLE_SAFE_BROWSING_API_KEY`. Values flow directly to Wrangler or the verifier and must never be printed, saved in the repository, or published as evidence.

After independent Reviewer and QA PASS on the identical PR head/tree/base, reauthenticate that state and run the whole merge/ref/dispatch transition once:

```sh
node scripts/deployment-transition.mjs --pr <explicit-number> --expected-head <40-lowercase-hex-sha>
```

Use `--check-only` before acceptance to authenticate the explicit PR, head, base, current main, source ref, repository, and workflow without mutation. The transition is resumable: it never discovers a PR, never overwrites a drifted ref, proves merged ancestry, and treats an ambiguous dispatch outcome as terminal instead of dispatching again. Keep its Git-directory journal until the matching run and sanitized durable evidence are authenticated; root then removes it during final cleanup.

The run repeats clean install, protocol, typecheck, 145+ tests, build, high-severity audit, generated cleanliness, Wrangler dry-run, and the real link-bearing public control. Deployment acceptance additionally checks exact revision, login/cookie/session/CSRF/logout/ownership, genuine Google observations for both control targets, public fetch, loopback/private/rebinding-style/redirect refusal, and root/reference assets. Only sanitized state classes and identifiers may be retained.
