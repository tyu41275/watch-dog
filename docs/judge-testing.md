# Judge testing instructions

Use the public HTTPS app at https://watch-dog.tytechnologiesconsulting.workers.dev/ with the username and password supplied only in the private submission testing field. No secret value belongs in this repository, screenshots, recordings, issue comments, or logs.

## Browser setup

Use a clean Google Chrome 149 or newer profile with experimental WebMCP support enabled, or a compatible ChatGPT in-app browser. The automated production acceptance uses an explicitly installed Google Chrome stable binary, confirms its version, and fails unless native `document.modelContext.getTools()` and `executeTool()` are present. Do not install a page shim.

## Five-minute path

1. Open the live app, enter the privately supplied credentials, and sign in. The scan panel should appear and the browser should receive a short-lived Secure, HttpOnly, SameSite=Strict session cookie.
2. In Paste Scan, choose pasted HTML with base URL `https://example.com/demo` and input `<a href="/account">Customer account</a> <a href="mailto:help@example.com">Help</a>`.
3. Enable the per-invocation Google disclosure checkbox and submit. Expect one accepted HTTP(S) target, one typed scheme rejection, a session-owned result, and a live provider observation. A provider no-match is displayed only as `no_known_match`, never “safe.”
4. Open `/reference`. Wait until the visibly labeled delayed anchor appears. In the browser's native WebMCP surface, discover `inspect_current_page`, `scan_url`, and `get_scan_result`.
5. Invoke `inspect_current_page` with `{}`. Expect the delayed-anchor count to change from zero at initial observation to one at invocation, the delayed target to appear in the result, and `misleading_url_like_text` evidence for the intentionally mismatched visible URL.
6. Invoke `get_scan_result` with the returned opaque `scanId`. Expect the same session-owned result shown in the page UI. The ID expires and is unusable from another session.
7. Sign out. The prior cookie and result access should no longer work.

## Boundaries

Live Page Scan reads only rendered anchors on Watch Dog's own fixed reference route. It does not inspect unrelated tabs; that would require a future extension with explicit host permissions. The tools are read-only and cannot navigate, persist sightings, alter verdicts, or bypass provider disclosure. Use only the inert example targets above—never a live malicious URL.
