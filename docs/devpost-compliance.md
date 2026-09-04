# WebMCP Challenge compliance record

Reviewed: 2026-09-03. The official rules control if another document conflicts. This file distinguishes verified public evidence from the authenticated Devpost action that is not available in this environment.

| Requirement | Evidence | Status |
| --- | --- | --- |
| WebMCP-powered application | Literal read-only tool source, unit/e2e corpus, and native browser capture | Verified |
| Working HTTPS app | https://watch-dog.tytechnologiesconsulting.workers.dev/ and exact deployment evidence in issue #10 | Verified |
| Actual Chrome 149+ WebMCP | Google Chrome 152 run https://github.com/tyu41275/watch-dog/actions/runs/33819716163 and issue #11 | Verified |
| Public repository | https://github.com/tyu41275/watch-dog | Verified public |
| Detectable open-source license | Root `LICENSE`; GitHub License API identifies Apache-2.0 | Verified |
| Source, lockfile, assets, and instructions | `src/`, `public/`, `package-lock.json`, `.env.example`, README and docs | Verified |
| One authorized live provider | Google Safe Browsing v5, consent-gated and server-only; live no-match observations in issue #10 artifact | Verified |
| Public fetching and typed refusal | Exact Cloudflare public-egress and special-address evidence in issue #6 | Verified |
| English description | [Final English copy](devpost-description.md) | Prepared |
| Private judge credentials and steps | Existing bindings plus [testing steps](judge-testing.md); values belong only in the private field | Prepared; private field requires authenticated submission |
| Screenshots | Google Chrome capture images in artifact 9917897142 and the submission release | Verified capture; public release copy prepared |
| Demo under three minutes with English audio | Public 166.361-second downloadable MP4; H.264/AAC; logged-out HTTP 200 | Verified downloadable publication |
| YouTube visibility if the form specifically requires YouTube | No public YouTube URL is evidenced | Not verified |
| Devpost submission receipt | [Submission record](submission-record.md) | External authenticated action pending |
| Revision mapping and freeze | Tagged source/evidence release plus explicit earlier video revision mapping | Prepared; final freeze waits for receipt |

## Final operator-only action

An authorized person must enter the existing judge credential values in Devpost's private testing field, attach the prepared public URLs/copy/assets, submit, and preserve the receipt. No credential value should be pasted into any public artifact. Until that receipt exists, neither issue #12 nor parent #1 is complete.
