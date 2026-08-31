# Watch Dog sub-three-minute demo plan and resources

Status: Current research snapshot
Reviewed: 2026-08-31

This is a deadline-friendly production workflow, not a product-architecture decision. Prefer tools the presenter already knows; changing editors near the deadline is a larger risk than missing a decorative effect. The approved Watch Dog story and exact proof obligations are in [demo-script-and-resources.md](demo-script-and-resources.md).

1. Watch Dog is genuinely WebMCP-powered: the agent invokes a registered page tool that updates shared visible state.
2. It helps a person reason about a URL: risk, confidence, supporting evidence, contradicting evidence, and provider status are distinct and understandable.
3. It preserves human authority: full-URL sharing is disclosed, sightings require confirmation, and high-risk navigation warns without hard blocking.

## Shot plan

| Time | Screen and action | Narration purpose |
| --- | --- | --- |
| 0:00–0:10 | Title plus a defanged suspicious message/link | State the problem and promise: know what is known, unknown, and why before following a link. |
| 0:10–0:25 | Live deployed Watch Dog page; authenticate quickly or begin already authenticated | Identify the two-sided experience: understandable human warnings and structured agent observations. |
| 0:25–0:50 | Agent invokes `extract_demo_page_links`; page highlights/returns links extracted via live DOM | Prove WebMCP and `document.querySelectorAll('a[href]')` on the same-origin page. |
| 0:50–1:30 | Select/paste deterministic risky fixture; acknowledge provider disclosure; invoke `inspect_url` | Show bounded server retrieval and the shared agent/page workflow. Clearly label fixture versus live provider evidence. |
| 1:30–1:55 | Result card expands supporting and contradicting evidence, confidence, provider provenance, and next steps | Explain that deterministic rules/providers own the official result and AI only investigates ambiguity. |
| 1:55–2:15 | Agent prepares a sighting; user reviews redaction/provenance and explicitly confirms quarantine | Prove community contribution cannot silently persist or self-promote to known malicious. |
| 2:15–2:32 | Click mediated high-risk destination; warning interstitial shows Back and Continue Anyway | Show user agency and no hard blocking; return safely without visiting a live malicious URL. |
| 2:32–2:48 | Repo/license and final product view | State limits: no safety guarantee, active-tab extension and STIX/TAXII deferred; show public repo. |

Do not spend video time on installation, account creation, a feature tour, or speculative roadmap. The approved story protects both Paste Scan and Live Page Scan Demo and explicitly discloses the reference-page/extension boundary.

## Capture and edit workflow

1. Freeze claim text and fixture identifiers; rehearse the exact tool calls twice.
2. Use a clean 1920×1080 browser profile at readable zoom, notifications off, secrets absent, and every tab preloaded.
3. Record 1080p/30 fps in OBS Studio after a short audio/video test. Capture a clean backup take before editing.
4. Use one familiar editor. Transcript-based cuts, filler removal, audio cleanup, and auto-captions are useful, but review every security term, product name, URL, and cut.
5. Export 16:9 H.264 progressive MP4 with AAC-LC 48 kHz audio at the capture frame rate. Upload early enough for 1080p processing.
6. Set the YouTube video to **Public** (the official rule does not accept merely Unlisted), then verify duration, audio, captions, and playback while logged out on desktop and phone.

## Demo acceptance checklist

- Under 3:00 after YouTube processing; target leaves at least ten seconds of margin.
- Working deployment URL is visible/readable and matches the submitted app.
- WebMCP invocation and resulting UI change are unmistakable.
- Audio says what was built and how WebMCP is used.
- Fixture and live evidence are never conflated.
- No passwords, API keys, personal data, raw sensitive query values, or live malicious links appear.
- No unauthorized music, stock media, or unnecessary third-party logos/trademarks appear.
- Captions correctly render “Watch Dog,” “WebMCP,” provider names, and risk labels.
- Repo URL and Apache-2.0 license are visible near the close.

## Official and production resources

- [Devpost official rules](https://webmcp.devpost.com/rules)
- [Devpost official WebMCP resources](https://webmcp.devpost.com/resources)
- [WebMCP specification repository](https://github.com/webmachinelearning/webmcp)
- [Chrome WebMCP developer documentation](https://developer.chrome.com/docs/ai/webmcp)
- [Chrome WebMCP tool security](https://developer.chrome.com/docs/ai/webmcp/secure-tools)
- [OpenAI WebMCP Showcase](https://developers.openai.com/showcase?view=webmcp-apps)
- [OBS Studio quick start](https://obsproject.com/kb/quick-start-guide)
- [YouTube recommended upload encoding](https://support.google.com/youtube/answer/1722171?hl=en)
- [YouTube processing quality guidance](https://support.google.com/youtube/answer/71674?hl=en)
