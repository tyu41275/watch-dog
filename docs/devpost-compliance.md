# WebMCP Challenge compliance matrix

Verified: 2026-08-31
Submission deadline: 2026-09-03 13:00 PDT / 20:00 UTC

The official rules control if other materials conflict. After the deadline, do not change the submission, repository, or live site during judging.

| Official requirement / criterion | Watch Dog evidence required before submission | Status now |
| --- | --- | --- |
| WebMCP-powered web app | Working `document.modelContext.registerTool(...)` registration for `inspect_current_page`; invocation runs live DOM extraction | Planned / P0 |
| Working live URL in ChatGPT in-app browser or Chrome with WebMCP enabled | Public HTTPS deployment plus smoke-test instructions and judge credentials | Planned / P0 |
| Function matches video/text | Recorded flows run against deployed revision; fixture modes labeled; no arbitrary-tab claim | Planned / P0 |
| Public code repository | `https://github.com/tyu41275/watch-dog` is public | Verified |
| Open-source license visible/detectable | Apache-2.0 `LICENSE`; configure GitHub About license visibility if absent | Verified file; About check before submit |
| Source, assets, instructions sufficient to run | Application source, lockfile, environment template without secrets, setup/test/deploy docs, fixtures | Planned / P0 |
| Project description | Explain WebMCP fit, better user experience, human-agent collaboration, and implementation | Planned / P0 |
| Demo video | Public YouTube, English, audio, functioning product/WebMCP demo, strictly under 3:00 | Planned / P0 |
| Rights/third-party terms | Original/inert fixtures; licensed assets/music only; provider use complies with terms | Planned / P0 |
| Free judge access through judging | Hosted project maintained through Sep 21; credentials supplied in private submission fields | Planned / P0 |
| WebMCP Leverage | Genuine `inspect_current_page`, post-load DOM proof, shared Paste/DOM pipeline, bounded tool contracts/evals | Planned / P0 |
| Execution | Coherent deployed flow, typed evidence UI, secure fallback, deterministic demo | Planned / P0 |
| Potential Impact | Specific anti-phishing/evidence problem for users and agent-assisted inspection | Vision approved |
| Creativity & Ambition | Community sightings plus live DOM WebMCP collaboration, honestly bounded | Vision approved |

## Submission lock checklist

- [ ] Live HTTPS URL loads and both scan modes work from a clean browser session.
- [ ] `inspect_current_page` is discoverable and callable in a supported WebMCP browser.
- [ ] Judge credentials and exact testing steps are entered in the submission form, not committed.
- [ ] Repository is public, default branch is the demonstrated revision, license is visible, and setup/tests pass from a fresh clone.
- [ ] Description covers every required prompt and does not claim arbitrary active-tab scanning.
- [ ] Public YouTube video is under three minutes, has English audio, and shows both modes plus WebMCP invocation.
- [ ] Video, repo, app, and description show the same behavior and revision.
- [ ] No secret, live malicious URL, private data, unlicensed trademark/music, or active malware appears.
- [ ] Submission is finalized before 20:00 UTC and all submitted surfaces are frozen through judging.

## Sources

- [Official rules: dates, requirements, judging, and testing](https://webmcp.devpost.com/rules)
- [Official resources/FAQ](https://webmcp.devpost.com/resources)
