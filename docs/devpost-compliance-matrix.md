# Devpost compliance matrix

Status: **Verified requirements; implementation evidence pending**
Version: 1.0.1
Verified: 2026-08-31 against the [official rules](https://webmcp.devpost.com/rules), [challenge overview](https://webmcp.devpost.com/), and [official resources tab](https://webmcp.devpost.com/resources)

The official rules are controlling and may change. Recheck them immediately before submission.

| Official requirement / criterion | Watch Dog response | Evidence or release gate | Current status |
| --- | --- | --- | --- |
| Submit by Sep 3, 2026, 1:00 PM PDT | Freeze and submit before 20:00 UTC; leave recovery margin. | Devpost confirmation receipt | Pending owner action |
| WebMCP-powered web app for human-agent collaboration | Three in-page tools share the visible inspection/sighting workflow. | Source containing `document.modelContext.registerTool(...)`; live tool test | Designed |
| Working, consistently runnable project | One deployed TypeScript app, bounded server pipeline, fixtures, smoke test. | Live URL plus `README` run/test instructions | Not implemented |
| New during submission period or clearly documented WebMCP extension | Repository began during the Aug 25–Sep 3 period; preserve timestamped commits. | Public commit history and submission-period note | In progress |
| Authorized third-party integrations | Review Google Safe Browsing and URLhaus terms; use credentials server-side and attribution where required. | Adapter docs, terms note, configured secret | Pending credentials/terms check |
| At least one authorized live provider (product gate) | A live adapter is required by the approved vision; fixtures cannot substitute. | Production smoke test and terms record | Hard gate not yet met |
| Working live URL usable in ChatGPT in-app browser or Chrome 149+ with flag | Deploy and test in at least Chrome 149+ with `#enable-webmcp-testing`; also test ChatGPT browser if available. | Recorded smoke-test checklist and URL | Not implemented |
| Authentication permitted only with testing credentials supplied | Static environment credentials and server session cookie; provide judge credentials privately in submission form. | Testing instructions; credential check | Designed |
| Text: strong WebMCP fit | Agents reliably inspect URLs, compare evidence, and prepare sightings inside the visible page. | Final Devpost description | Draft after app works |
| Text: better user experience | People see understandable labels/uncertainty and avoid manually correlating sources. | Final Devpost description + screenshots | Draft after app works |
| Text: new human-agent collaboration | Agent performs evidence work; human controls disclosure, persistence, and navigation. | Final Devpost description + demo | Designed |
| Text: brief implementation explanation | Name registered tools, shared client logic, server pipeline, deterministic policy, provider adapters, and confirmation gate. | Final Devpost description | Designed |
| Public code repository | Use `https://github.com/tyu41275/watch-dog`. | Public repository access | Pass |
| All source, assets, and functional instructions in repo | Add application source, fixtures, setup, deployment, and testing instructions before submission. | Repository tree and clean-room run | Not implemented |
| Detectable open-source license visible in repo About area | Apache-2.0 `LICENSE`; ensure GitHub detects it and About shows the license. | GitHub repository header/About | File present; UI verification pending |
| Repository shows WebMCP registration | Commit actual `document.modelContext.registerTool(...)` source, not documentation alone. | Source search and browser invocation | Not implemented |
| Demo is under 3:00 | Target 2:40–2:50. Judges need not watch beyond 3:00. | Processed YouTube duration | Not recorded |
| Demo clearly shows working project and WebMCP, with audio | Capture live tool invocation, page state change, result/evidence, and human confirmation boundary. | Public YouTube URL | Not recorded |
| Demo is publicly visible on YouTube | Upload as Public, not Unlisted, before submission. | Logged-out playback check | Not uploaded |
| Demo avoids unauthorized trademarks/music/material | Use owned UI/assets, no copyrighted music, and only necessary factual product/provider names. | Media rights checklist | Pending |
| English materials or English translations | Publish repo, description, instructions, and narration in English. | Submission review | Planned |
| Free, unrestricted judge access through judging | Keep app and credentials live through Sep 21, 2026 5:00 PM PDT. Do not introduce paid gates. | Uptime owner/check | Pending |
| Do not alter submission after deadline | Freeze submitted repo/live site/Devpost entry through judging; fork for later work if necessary. | Tagged release and freeze record | Pending |
| Stage-one viability/theme fit | Demo a real WebMCP workflow, not only documentation or mocks. | Live app/video/repo | Not implemented |
| Safe arbitrary server fetch (product release gate) | No redirects unless pinned, public-destination validation, runtime isolation, resource/log/referrer tests. | Security test report | Hard gate not yet met |
| WebMCP Leverage (equal weight) | Multiple coherent tools, shared UI state, live DOM extraction, human-in-loop action. | Tool tests and demo | Designed |
| Execution (equal weight) | Prioritize deployed coherent journey and deterministic reliability over extension breadth. | End-to-end smoke test | Designed |
| Potential Impact (equal weight) | Specific anti-phishing decision support for everyday users with scalable agent observations. | User story and demo evidence | Designed |
| Creativity & Ambition (equal weight) | Combine agent-native page inspection with provenance-preserving community sightings and explicit authority boundaries. | Description/demo | Designed |

## Official implementation resources selected

- [WebMCP specification repository](https://github.com/webmachinelearning/webmcp)
- [Chrome WebMCP developer documentation](https://developer.chrome.com/docs/ai/webmcp)
- [Chrome WebMCP tool security guide](https://developer.chrome.com/docs/ai/webmcp/secure-tools)
- [OpenAI WebMCP Showcase](https://developers.openai.com/showcase?view=webmcp-apps)
- [Official challenge resources](https://webmcp.devpost.com/resources), including Chrome debugging/evals and the Cloudflare Workers template
