import type { ExtractedLinkCandidate } from "./contracts.js";
import {
  canonicalizeUrl,
  type CanonicalRejectionReason,
  type CanonicalTarget,
} from "./canonicalize.js";

export interface MisleadingTextEvidence {
  displayed_text: string;
  displayed_target: string;
  linked_target: string;
}

export interface CandidateOccurrence {
  candidate: ExtractedLinkCandidate;
  misleading_text: MisleadingTextEvidence | null;
}

export interface CanonicalCandidateTarget extends CanonicalTarget {
  occurrences: CandidateOccurrence[];
  anchor_text_variants: string[];
}

export interface RejectedCandidate {
  candidate: ExtractedLinkCandidate;
  reason: CanonicalRejectionReason;
}

export interface CandidateCollection {
  targets: CanonicalCandidateTarget[];
  rejected: RejectedCandidate[];
}

const EXPLICIT_URL_TEXT = /^https?:\/\/\S+$/i;
const BARE_URL_TEXT = /^(?:(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?\.)+(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?))(?::\d+)?(?:[/?#]\S*)?$/iu;

function misleadingText(
  anchorText: string,
  linkedTarget: string,
): MisleadingTextEvidence | null {
  const displayedText = anchorText.trim();
  if (!EXPLICIT_URL_TEXT.test(displayedText) && !BARE_URL_TEXT.test(displayedText)) return null;

  const linkedScheme = new URL(linkedTarget).protocol;
  const parseableText = EXPLICIT_URL_TEXT.test(displayedText)
    ? displayedText
    : `${linkedScheme}//${displayedText}`;
  const displayed = canonicalizeUrl(parseableText);
  if (!displayed.ok || displayed.target.canonical_url === linkedTarget) return null;

  return {
    displayed_text: displayedText,
    displayed_target: displayed.target.canonical_url,
    linked_target: linkedTarget,
  };
}

/**
 * The common post-extraction path for paste and live-page occurrences.
 * Target insertion order is stable; only provider/analysis work is deduplicated.
 */
export function collectLinkCandidates(
  candidates: readonly ExtractedLinkCandidate[],
): CandidateCollection {
  const targets = new Map<string, CanonicalCandidateTarget>();
  const rejected: RejectedCandidate[] = [];

  for (const candidate of candidates) {
    const result = canonicalizeUrl(candidate.raw_href, candidate.base_url);
    if (!result.ok) {
      rejected.push({ candidate, reason: result.reason });
      continue;
    }

    const key = result.target.canonical_url;
    let target = targets.get(key);
    if (target === undefined) {
      target = {
        ...result.target,
        occurrences: [],
        anchor_text_variants: [],
      };
      targets.set(key, target);
    }

    const text = candidate.anchor_text.trim();
    if (text !== "" && !target.anchor_text_variants.includes(text)) {
      target.anchor_text_variants.push(text);
    }
    target.occurrences.push({
      candidate,
      misleading_text: misleadingText(candidate.anchor_text, key),
    });
  }

  return { targets: [...targets.values()], rejected };
}
