# Under-three-minute YouTube demo workflow

Status: Current research snapshot  
Reviewed: 2026-08-31

This is a deadline-friendly production workflow, not a product-architecture decision. Prefer tools the presenter already knows; changing editors near the deadline is a larger risk than missing a decorative effect.

## Recommended narrative budget

Target **2:40–2:50**, leaving ten to twenty seconds of upload and judging tolerance.

| Time | Purpose |
| --- | --- |
| 0:00–0:10 | Show the phishing problem and one-sentence promise. |
| 0:10–0:25 | Name Watch Dog, the intended user, and why WebMCP matters. |
| 0:25–1:55 | Demonstrate one uninterrupted must-win journey with stable sample data. |
| 1:55–2:25 | Show only the strongest evidence, community-corpus value, and safety boundary. |
| 2:25–2:45 | State the result, limits, repository, and next step. |

Do not spend video time on installation, account creation, a feature tour, or speculative roadmap. The exact story remains gated on the vision interview.

## Fast production sequence

1. **Freeze the claim sheet.** Write the three claims the video must prove, the exact screen evidence for each, and claims that must not be made. Keep the narration around 325–375 words for a calm 2.5-minute delivery.
2. **Storyboard six to eight shots.** Use a clean browser profile, fixed window size, readable zoom, notifications disabled, deterministic demo records, and defanged/inert URLs. Preload every tab and keep a fallback screen recording of the successful path.
3. **Record a clean master.** OBS Studio is the free, local default. Its official quick start recommends the auto-configuration wizard, explicit display/window and audio sources, and a short test recording before the real take. Record the product at 1920×1080, 30 fps, with the cursor deliberate and secrets absent.
4. **Use one AI-assisted editor.** Descript is the fastest transcript-first option when narration is central: its current tools edit media through transcript text, remove filler words, shorten gaps, clean audio, and add captions. CapCut Desktop is a reasonable familiar alternative with auto captions and filler-word removal. Review every automated cut and caption, especially product names, security terms, and URLs.
5. **Polish sparingly.** Add a short title card, consistent two-line captions, two or three callouts, and light audio leveling. Canva or Adobe Express can quickly create a thumbnail/title card or remove a talking-head background, but neither is required. Do not add synthetic threat evidence or AI-generated product footage that could be mistaken for the working demo.
6. **Export and upload early.** Use 16:9 MP4, H.264 progressive video, the same frame rate as the recording, AAC-LC audio at 48 kHz, and roughly 8 Mbps for 1080p/30 fps. YouTube currently lists those as recommended upload settings. Upload unlisted first because 1080p processing can lag behind the initial low-quality version.
7. **Run a human QA pass.** Watch the processed YouTube version once on a laptop and once on a phone. Verify duration, audio, caption accuracy, cursor visibility, readable text, absence of secrets/personal data/live malicious links, truthful claims, repository link, and that the opening ten seconds make sense without prior context.

## Deadline choice matrix

| Need | Lowest-risk choice | AI assist worth using | Avoid under deadline |
| --- | --- | --- | --- |
| Screen capture | OBS Studio or an already-familiar recorder | Noise suppression if already configured | Learning a complex scene system |
| Spoken edit | Descript | Transcript cuts, filler removal, gap tightening, Studio Sound | Blindly accepting every AI cut |
| Timeline edit | Familiar CapCut/Desktop editor | Auto captions, filler removal | Switching editors mid-project |
| Title/thumbnail | Existing brand template; Canva/Adobe Express if familiar | Background removal or layout suggestions | Generating a visual identity from scratch |
| Export | 1080p/30 H.264 MP4 | None needed | 4K/60, which adds render and processing time without helping a short UI demo |

## Sources

- [OBS Studio Quick Start Guide](https://obsproject.com/kb/quick-start-guide)
- [Descript: edit media like a document](https://help.descript.com/hc/en-us/articles/10164808475149-Inline-notes)
- [Descript AI tools overview](https://help.descript.com/hc/en-us/articles/27252457732237-AI-Tools-Overview)
- [CapCut Desktop AI-powered editor](https://www.capcut.com/tools/desktop-ai-power)
- [Canva AI quick tools](https://www.canva.com/help/ai-tools-pages/)
- [Adobe Express video background remover](https://www.adobe.com/express/feature/video/remove-background)
- [YouTube recommended upload encoding settings](https://support.google.com/youtube/answer/1722171?hl=en)
- [YouTube: low quality after upload](https://support.google.com/youtube/answer/71674?hl=en)
