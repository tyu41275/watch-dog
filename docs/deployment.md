# Exact deployment and live acceptance

Issue #10 is deployed only through the manual **Deploy exact Watch Dog revision** workflow. It enables the default Cloudflare `workers.dev` HTTPS surface, disables preview URLs, and refuses a SHA that is malformed, is not the workflow event and checked-out commit, or is not contained in `main`.

## Repository configuration

The workflow reads these repository secret names without exposing their values:

| Repository secret | Worker binding |
| --- | --- |
| `WATCH_DOG_JUDGE_USERNAME` | `ADMIN_USERNAME` |
| `WATCH_DOG_JUDGE_PASSWORD` | `ADMIN_PASSWORD` |
| `WATCH_DOG_SESSION_SIGNING_SECRET` | `SESSION_SIGNING_KEY` |
| `GOOGLE_SAFE_BROWSING_API_KEY` | `GOOGLE_SAFE_BROWSING_API_KEY` |

`CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN` authenticate Wrangler. The workflow sets the non-secret binding `GOOGLE_SAFE_BROWSING_ENABLED=true` and binds `BUILD_REVISION` to the checked-out GitHub SHA. Wrangler deploys the `public/` Assets binding and the configured `SessionCoordinator` Durable Object, including its `v1` SQLite-class migration. Secret JSON travels through an anonymous process-substitution pipe; it is not written to a workspace or artifact.

## Reviewed-head runbook

1. Obtain independent Reviewer and QA PASS verdicts on the identical published PR head, tree, and base.
2. Reauthenticate those refs, merge the PR without changing its accepted head, and keep the source branch until deployment completes.
3. Dispatch the workflow from that source ref, substituting the accepted 40-character head for `SHA`:

   ```sh
   gh workflow run deploy.yml --repo tyu41275/watch-dog --ref agent/wd-p0-09-deploy-7196a94f -f expected_sha=SHA
   ```

4. Authenticate the resulting run's event, head SHA, conclusion, and artifact digest before publishing its sanitized receipt. Do not publish runner logs, secret values, credential inputs, cookie/CSRF values, raw provider bodies, or probe targets.

The workflow reruns fresh-clone-equivalent install, protocol, typecheck, test, build, high-severity audit, generated-tree, and Wrangler dry-run gates before deployment. It then uploads one sanitized JSON artifact with the public Worker URL, exact revision, redacted deployment ID, cookie attributes, provider classification, network refusal classes, and root/reference UI results.

## Live acceptance boundary

The verifier requires HTTPS and exact `/api/revision` identity; generic wrong-login denial; correct login; the `Secure`, `HttpOnly`, `SameSite=Strict`, host-only 15-minute cookie; session and CSRF enforcement; logout expiry; same-session ownership and cross-session denial; deliberate non-commercial Google Safe Browsing consent with a live normalized observation; one successful public HTML fetch; loopback, private, rebinding-style, and redirect-to-disallowed refusal; and the deployed root/reference UI.

Provider authentication, quota, Cloudflare authentication/permission/plan, a revision mismatch, or any live-gate failure is terminal for that run. Do not disable a check or substitute fixtures. Preserve the exact sanitized blocker and park issue #10 once if bounded rechecks confirm an external failure.
