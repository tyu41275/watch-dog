import { defaultTreeAdapter, parseFragment, type DefaultTreeAdapterMap } from "parse5";

import type { ExtractedLinkCandidate } from "./contracts.js";
import type { ExtractAtom } from "./scan-machine.js";

export const HTML_EXTRACTION_LIMITS = {
  max_input_chars: 200_000,
  max_candidates: 256,
  max_href_chars: 2_048,
  max_anchor_text_chars: 512,
} as const;

export interface HtmlExtractionContext {
  base_url: string;
  document_url: string;
  extracted_at: string;
}

type Node = DefaultTreeAdapterMap["node"];
type Element = DefaultTreeAdapterMap["element"];

// These elements are not candidate-bearing content under the frozen paste
// contract. Skipping the element also skips template.content and foreign trees.
const EXCLUDED_CONTENT = new Set([
  "script", "style", "template", "noscript", "iframe", "frame",
  "object", "svg", "math", "textarea", "xmp", "plaintext", "title",
  "noembed", "noframes", "select",
]);

function isElement(node: Node): node is Element {
  return defaultTreeAdapter.isElementNode(node);
}

function pushChildren(node: Node, stack: Node[]): void {
  if (!("childNodes" in node)) return;
  for (let index = node.childNodes.length - 1; index >= 0; index -= 1) {
    const child = node.childNodes[index];
    if (child !== undefined) stack.push(child);
  }
}

function anchorText(element: Element): { text: string; overflow: boolean } { let text = "", separating = false;
  const stack: Node[] = [];
  pushChildren(element, stack);
  while (stack.length > 0) {
    const node = stack.pop();
    if (node === undefined) break;
    if (defaultTreeAdapter.isTextNode(node)) {
      for (const character of node.value) {
        if (/\s/u.test(character)) { if (text.length > 0) separating = true; continue; }
        if (separating && text.length < HTML_EXTRACTION_LIMITS.max_anchor_text_chars) text += " ";
        if (text.length + character.length > HTML_EXTRACTION_LIMITS.max_anchor_text_chars) return { text, overflow: true };
        text += character; separating = false;
      }
    } else if (!(isElement(node) && EXCLUDED_CONTENT.has(node.tagName))) pushChildren(node, stack);
  }
  return { text, overflow: false };
}

export function extractHtmlScanAtoms(input: string): ExtractAtom[] {
  const fragment = parseFragment(input.slice(0, HTML_EXTRACTION_LIMITS.max_input_chars)), atoms: ExtractAtom[] = [], stack: Node[] = [fragment];
  while (stack.length > 0) {
    const node = stack.pop();
    if (node === undefined) break;
    if (isElement(node)) {
      if (EXCLUDED_CONTENT.has(node.tagName)) continue;
      if (node.tagName === "a") {
        const href = node.attrs.find(({ name }) => name === "href")?.value;
        if (href !== undefined) {
          if (atoms.length === HTML_EXTRACTION_LIMITS.max_candidates) {
            atoms.push({ kind: "OCCURRENCE_OVERFLOW" }); break;
          }
          const bounded = href.length <= HTML_EXTRACTION_LIMITS.max_href_chars, label = anchorText(node);
          atoms.push({ kind: "ANCHOR", href: bounded ? href : null, href_overflow: !bounded,
            text: label.text, text_overflow: label.overflow });
        }
      }
    }
    pushChildren(node, stack);
  }
  return atoms;
}

export function extractHtmlLinkCandidates(input: string, context: HtmlExtractionContext): ExtractedLinkCandidate[] {
  const candidates: ExtractedLinkCandidate[] = [];
  for (const atom of extractHtmlScanAtoms(input)) {
    if (atom.kind !== "ANCHOR" || atom.href === null) continue;
    candidates.push({ raw_href: atom.href, anchor_text: atom.text, base_url: context.base_url,
      provenance: { source: "paste_html", document_url: context.document_url,
        occurrence_index: candidates.length, extracted_at: context.extracted_at } });
  }
  return candidates;
}
