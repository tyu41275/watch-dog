# Google Safe Browsing integration

Verified: 2026-09-01

Watch Dog uses the Google Safe Browsing v5 `urls.search` method as its one live
provider adapter. The adapter is server-only, normalized, bounded, and does not
own the product's risk label, analysis state, or confidence.

## Terms and activation boundary

The Safe Browsing API is permitted only for non-commercial use unless the
operator has a separate agreement with Google. Watch Dog currently assumes the
hackathon demonstration is not for sale and does not generate revenue. A
commercial deployment must replace this integration with an appropriately
licensed service such as Web Risk or document a separate Google agreement.

Do not activate live lookups until the UI presents the provider disclosure and
the user has deliberately submitted a scan. The `urls.search` method sends each
accepted canonical address-bar URL to Google. Google's terms allow Google to use
and share submitted URLs and associated data to operate and improve its
services. Do not use this path for subresources, private browsing material, raw
HTML, page text, form data, cookies, or secrets.

Google states that its protection is not comprehensive or error-free. Both
false positives and false negatives are possible. Watch Dog therefore:

- renders an empty threat list only as `no_known_match`, never as “safe”;
- qualifies match evidence instead of making an absolute safety claim;
- uses **Advisory provided by Google** with a link to Google's Safe Browsing
  advisory only for warnings derived from a Google match;
- never attaches Google attribution to a warning derived solely from another
  source; and
- caps match freshness at 30 minutes even if Google returns a longer cache
  duration.

## Request and credential handling

The Worker calls:

`GET https://safebrowsing.googleapis.com/v5/urls:search?urls=<canonical-url>`

The `GOOGLE_SAFE_BROWSING_API_KEY` secret is sent in the `X-Goog-Api-Key`
header. It is never placed in the request URL, client JavaScript, normalized
observation, stored result, error message, or committed configuration. There is
no fallback key. Missing configuration becomes a typed live-source
`not_configured` observation.

The current adapter performs one request per retained canonical target. Each
request has a 2.5-second timeout and a 64,000-byte response cap. It accepts only
the documented closed JSON shape and these threat enums:

| Google threat type | Watch Dog category |
| --- | --- |
| `MALWARE` | `malware` |
| `SOCIAL_ENGINEERING` | `social_engineering` |
| `UNWANTED_SOFTWARE` | `unwanted_software` |
| `POTENTIALLY_HARMFUL_APPLICATION` | `potentially_harmful_application` |

Unknown or malformed values fail closed as `malformed_response`. HTTP 429 is
`quota`; local timeout and HTTP 408/504 are `timeout`; other HTTP/network
failures are `unavailable`. Raw provider payloads and error bodies are discarded.
Fixtures remain explicitly labeled with `source: fixture`; production responses
use `source: live`.

## Configuration and verification

For local feature work, place the key only in an ignored `.dev.vars` file. For
Cloudflare, configure it as a Worker secret. The repository secret is named
`GOOGLE_SAFE_BROWSING_API_KEY`; deployment wiring remains owned by the deployment
node.

Unit and shimmed HTTP tests do not satisfy the live-provider gate. Before
activation, run one sanitized permitted lookup against the exact deployed
revision and preserve provider, observation time, deployment identity, response
classification, and redacted command/output. Use a Google-provided inert test
URL or another sanctioned input; do not publish a live malicious destination or
the API key.

## Authoritative sources

- [Safe Browsing Terms of Service](https://developers.google.com/safe-browsing/terms),
  modified 2025-11-20.
- [Appropriate Usage](https://developers.google.com/safe-browsing/reference/Appropriate.Usage),
  including non-commercial use, address-bar URL scope, warning qualification,
  attribution, limitations, and quota guidance.
- [`urls.search` v5 reference](https://developers.google.com/safe-browsing/reference/rest/v5/urls/search),
  updated 2026-02-20.
- [Google Cloud API-key best practices](https://cloud.google.com/docs/authentication/api-keys-best-practices),
  which recommends the header instead of a URL query parameter.

Raw page retrieval SHA-256 values recorded on 2026-09-01 are, respectively:
`94ee988b99d65377ab0f63de5fd06a0b1312ace724fa2e8a747f1040fe03b4da`,
`da9efaf1ccb33995febf5d0215a37430eb0d0336cfdadbb4ed021ef7a5fffa01`,
`3c48eea971f7609be4a181258f000c3600aad344b0adcf5201a68893405e1d32`,
and `7d2108e84ff0a98e7799da915a895e2dba281b9b26f267206acb0f6eb05f1602`.
