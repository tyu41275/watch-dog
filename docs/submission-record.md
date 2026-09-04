# Submission, revision, and freeze record

Status: submission package prepared; authenticated Devpost receipt not accessible from this environment, so no Devpost submission or final freeze is claimed.

## Public surfaces

- Live app: https://watch-dog.tytechnologiesconsulting.workers.dev/
- Public source: https://github.com/tyu41275/watch-dog
- Detected license file: https://github.com/tyu41275/watch-dog/blob/main/LICENSE (Apache-2.0)
- Canonical downloadable demo: https://github.com/tyu41275/watch-dog/releases/download/watchdog-demo-2026-09-03/watchdog-youtube-final-pronunciation-fixed.mp4
- Demo release and media verification: https://github.com/tyu41275/watch-dog/releases/tag/watchdog-demo-2026-09-03
- Final source/evidence release: https://github.com/tyu41275/watch-dog/releases/tag/watchdog-submission-2026-09-03

The final evidence release is the immutable mapping authority for its source revision, exact deployment run, Google Chrome capture artifact, screenshots, and reused demo asset digest. Judge credential values are supplied only through the authenticated private testing field and are never copied here.

## Revision mapping

- Production acceptance for login, cookie, provider, public egress, UI, and refusal behavior: revision `22214695895fb91d410637c5a27896f580983865`, run https://github.com/tyu41275/watch-dog/actions/runs/33818017937.
- Genuine Google Chrome acceptance: revision `8b7fccd74b0534c44a0a342592bc764029cb2601`, wholly green run https://github.com/tyu41275/watch-dog/actions/runs/33819716163, deployment artifact `9917896706`, and Chrome capture artifact `9917897142`. A same-revision capture with a live provider no-match is artifact `9917789315` from run `33819383227`.
- The downloadable edited MP4 truthfully demonstrates the earlier production revision `92664c060a47e50cbbc7f3e1b50aa4d30f50ca6d` and an honestly rendered provider-error state. Its native Chromium 151 source capture is run https://github.com/tyu41275/watch-dog/actions/runs/33816557188.
- The final source/evidence release records the later exact Google Chrome acceptance and final deployed revision. It does not pretend the edited MP4 was recorded from that later revision.

## Media verification

The canonical MP4 from video replacement task `c965d4b9`, run `184f3f95`, is 166.361 seconds, H.264 1920×1080, with non-silent AAC-LC 48 kHz stereo English audio and burned-in English captions. SHA-256: `f0e4bd383cd3dddcf4cab5eee82f8316752d1322ce298329e08e49d756091150`. A logged-out request follows the GitHub release redirect to HTTP 200.

The Google Chrome artifact contains `watchdog-native-webmcp.png` and `watchdog-paste-scan.png`. The first visibly includes an opaque result ID generated for the capture session; it expired before public release and cannot be used without the unrecorded HttpOnly cookie. It is not a credential or durable record.

## Submission receipt and freeze

No authenticated Devpost session or receipt is available to this automation context, and no public Devpost project page was found. Therefore:

- no Devpost receipt is claimed;
- issue #12 must remain open until an authorized person submits the prepared English description, private credentials, testing instructions, live URL, repository, screenshots, and public video/download URL and returns the receipt;
- the final repository/app/submission freeze must not be marked complete before that receipt is recorded; and
- after receipt, the operator should record the Devpost project URL and receipt timestamp without copying private credentials, then leave the tagged source, deployed revision, media, and entry unchanged through judging except for a critical security fix documented here.
