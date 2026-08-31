# Demo script and recording resources

Status: Approved narrative
Target runtime: 2:40–2:50

## Claim sheet

The video must prove:

1. Paste Scan and Live Page Scan Demo are two real inputs to one evidence pipeline.
2. `inspect_current_page` is a registered WebMCP tool whose invocation inspects the rendered Watch Dog reference DOM and detects a post-load anchor.
3. Watch Dog communicates evidence and uncertainty honestly: no-match is not safe, confidence is not risk, and arbitrary third-party tabs require a future extension.

Do not claim production-grade protection, automatic browser blocking, arbitrary active-tab access, community consensus, two live providers unless shown, or safety guarantees.

## Shot-by-shot script

| Time | Screen and action | Narration intent |
| --- | --- | --- |
| 0:00–0:12 | Title and Paste Scan input | “Links can look familiar while pointing somewhere else. Watch Dog shows the evidence before you decide.” |
| 0:12–0:42 | Paste safe fixture URL/HTML; scan | Show bounded fetch/local-only choice and extracted target count. |
| 0:42–1:08 | Result UI | Point out risk label, separate confidence, freshness, source, contradictions, and `no_known_match` disclaimer. |
| 1:08–1:25 | Open fixed reference page; show delayed-link badge/count before/after insertion | State explicitly that this is a safe Watch Dog-owned page, not another browser tab. |
| 1:25–1:52 | Agent discovers/invokes `inspect_current_page` | Show real WebMCP tool registration/invocation and the dynamically inserted anchor in the result. |
| 1:52–2:16 | Expanded extraction evidence | Show relative normalization, rejected non-HTTP(S), duplicate occurrences, and misleading anchor text. |
| 2:16–2:34 | Same result component/fixture provider failure | Demonstrate the shared pipeline and typed provider-error/unknown behavior; say no-match never means safe. |
| 2:34–2:48 | Architecture/limits/repo card | State agent/verdict boundary, extension deferral, public Apache-2.0 repo, and human-controlled next step. |

## Live demo resources

- Fixed reference page populated only with inert/example-owned targets; no live malicious links.
- Delayed anchor inserted after `DOMContentLoaded`/a visible timer and labeled in UI so the capture proves timing.
- Deterministic fixtures for positive threat match, no-match, provider error, stale evidence, conflicting evidence, invalid/unscannable target, redirect, duplicate, and misleading anchor text.
- One configured live provider checked before recording; fixture mode clearly labeled whenever shown.
- Clean browser profile, Chrome 149+ WebMCP flag or ChatGPT in-app browser, notifications off, 125–150% UI zoom if needed.
- Backup local screen recording of the exact deployed revision; never substitute a prerecorded result inside the app.

## Recording workflow

Record 1920x1080 at 30 fps in OBS or a familiar recorder after a short audio/cursor test. Keep narration around 325–375 words. Use one familiar editor for transcript cuts, audio cleanup, and reviewed captions. Export 16:9 H.264 progressive MP4 with AAC-LC 48 kHz audio, upload publicly to YouTube early, then check processed playback on laptop and phone.

Final QA verifies runtime under 3:00, English audio/captions, readable evidence, correct WebMCP invocation, both protected modes, no secrets/private data/live malicious URL, no unlicensed music/trademarks, matching deployed revision, and a repository link.

## Resources

- [Devpost submission FAQ](https://webmcp.devpost.com/resources)
- [Official rules](https://webmcp.devpost.com/rules)
- [Chrome WebMCP evals](https://developer.chrome.com/docs/ai/webmcp/evals)
- [OBS quick start](https://obsproject.com/kb/quick-start-guide)
- [YouTube encoding recommendations](https://support.google.com/youtube/answer/1722171?hl=en)
