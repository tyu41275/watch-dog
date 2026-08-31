# Watch Dog vision interview record

Status: Complete
Recorded: 2026-08-31
Source: parent operator decisions provided to vision task `4d430590`, run `f1f044b6`, thread `1544082582340374681`, with the latest two-mode correction supplied to the synthesis task.

## Approved answers

1. **Audience:** everyday users receive understandable warnings; agents contribute structured observations and explanations.
2. **Must-win journey:** inspect links through either Paste Scan or the Live Page Scan Demo, then show categorical risk, separate confidence, and supporting/contradicting evidence.
3. **MVP surface:** two equal protected scan modes plus a small quarantined sighting flow. Paste Scan accepts bounded URL fetch or local-only pasted HTML. Live Page Scan inspects a fixed Watch Dog-owned same-origin rendered DOM.
4. **WebMCP proof:** register and invoke `inspect_current_page`; extraction must query live anchors at invocation, include a post-load anchor, normalize relatives, filter non-HTTP(S), retain misleading text/duplicates, and enter the shared pipeline.
5. **Result policy:** categorical risk with typed unknown/unscannable/provider-error/stale/conflicting states; confidence is separate; no-match never means safe.
6. **Data sources and retention:** provider-adapter interface, one live adapter plus fixtures; scans ephemeral; only explicit confirmed sanitized sightings persist; disclose full-URL provider sharing.
7. **Moderation:** community reports are quarantined and cannot independently promote known malicious; recognized-provider corroboration or administrator approval is required.
8. **Never do:** no safety guarantee, content execution, hard blocking, LLM-owned verdict/persistence, WebMCP navigation, or undisclosed provider sharing.
9. **Deployment/auth:** simple server-side environment-secret username/password check and signed secure cookie; no account system.
10. **Deadline/compliance:** public hosted WebMCP app, public Apache-2.0 repository, instructions, description, and public English YouTube demo with audio under three minutes by September 3, 2026 13:00 PDT.
11. **Observable success:** both modes visibly work through one pipeline; the post-load anchor proves DOM timing; results show honest uncertainty and provenance.
12. **Deferrals:** arbitrary third-party active-tab extension, STIX/TAXII, reputation weighting, production auth, autonomous navigation/blocking, and a second provider if it threatens submission readiness.

## Latest operator override

Any recommendation to demote rendered-DOM inspection is superseded. Paste Scan and Live Page Scan Demo are equal MVP/demo priorities. The Live Page Scan Demo remains bounded to Watch Dog's reference page; the Chrome extension remains deferred.
