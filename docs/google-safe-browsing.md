# Google Safe Browsing integration (verified 2026-09-01)

Watch Dog uses Google Safe Browsing v5 `urls.search` as its one live provider adapter. It is server-only, normalized and bounded; it does not own the risk label, analysis state or confidence.

## Terms and activation boundary

The API is permitted only for non-commercial use unless the operator has a separate Google agreement. This hackathon demonstration is assumed neither sold nor revenue-generating; commercial deployment requires an appropriately licensed service such as Web Risk or a separate agreement. Do not activate until the UI identifies Google, discloses that each accepted canonical address-bar URL is sent to Google, links applicable terms/privacy information, and makes deliberate submission the user's consent action. Google's terms permit use and sharing of submitted URLs and associated data to operate and improve its services. Never send subresources, private-browsing material, raw HTML, page text, form data, cookies or secrets. Google says protection is not comprehensive or error-free. Watch Dog renders an empty list only as `no_known_match`, never “safe”; qualifies match evidence; uses **Advisory provided by Google** and Google's advisory link only for a Google match; never attributes another source to Google; and caps match freshness at 30 minutes.

## Request, credentials and bounds

The Worker calls `GET https://safebrowsing.googleapis.com/v5/urls:search?urls=<canonical-url>`. `GOOGLE_SAFE_BROWSING_API_KEY` is sent only in `X-Goog-Api-Key`, never in URLs, client assets, observations, stored results, errors or committed config. There is no fallback key; missing configuration yields live-source `not_configured`. `GOOGLE_SAFE_BROWSING_ENABLED` must equal exact string `true`; absence, `false` or any other value disables lookup even when the key exists. Keep it disabled until deployed disclosure and consent pass. Each retained target gets one request with a 2.5-second end-to-end deadline and 64,000-byte cap. The closed response maps `MALWARE` → `malware`, `SOCIAL_ENGINEERING` → `social_engineering`, `UNWANTED_SOFTWARE` → `unwanted_software`, and `POTENTIALLY_HARMFUL_APPLICATION` → `potentially_harmful_application`. Unknown/malformed values yield `malformed_response`; HTTP 429 is `quota`; local deadline and HTTP 408/504 are `timeout`; other HTTP/network failures are `unavailable`. Raw payloads/error bodies are discarded. Fixtures stay `source: fixture`; production is `source: live`.

## Configuration and verification

For local work, put the key only in ignored `.dev.vars`. For Cloudflare, configure Worker secret `GOOGLE_SAFE_BROWSING_API_KEY`; deployment wiring belongs to the deployment node. Keep activation absent/false until UI and exact revision pass. Unit and shimmed HTTP tests do not satisfy the live-provider gate. Before activation, run one sanitized permitted lookup on the exact deployment and preserve provider, time, deployment identity, classification and redacted command/output. Use a Google-provided inert test URL or sanctioned input; publish neither malicious destination nor key.

## Authoritative sources

[Terms](https://developers.google.com/safe-browsing/terms) (modified 2025-11-20); [Appropriate Usage](https://developers.google.com/safe-browsing/reference/Appropriate.Usage); [`urls.search` v5](https://developers.google.com/safe-browsing/reference/rest/v5/urls/search) (updated 2026-02-20); [URL/hash expressions](https://developers.google.com/safe-browsing/reference/URLs.and.Hashing) (updated 2025-05-23); and [API-key best practices](https://cloud.google.com/docs/authentication/api-keys-best-practices).

Raw retrieval SHA-256 values for Terms, Appropriate Usage, `urls.search`, and the key guide are: `94ee988b99d65377ab0f63de5fd06a0b1312ace724fa2e8a747f1040fe03b4da`, `da9efaf1ccb33995febf5d0215a37430eb0d0336cfdadbb4ed021ef7a5fffa01`, `3c48eea971f7609be4a181258f000c3600aad344b0adcf5201a68893405e1d32`, `7d2108e84ff0a98e7799da915a895e2dba281b9b26f267206acb0f6eb05f1602`.
