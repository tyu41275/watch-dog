import { defaultTreeAdapter, parseFragment, type DefaultTreeAdapterMap } from "parse5";

import type { ExtractedLinkCandidate } from "./contracts.js";

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

function normalizedAnchorText(element: Element): string {
  const parts: string[] = [];
  const stack: Node[] = [];
  let length = 0;
  pushChildren(element, stack);
  while (stack.length > 0 && length < HTML_EXTRACTION_LIMITS.max_anchor_text_chars) {
    const node = stack.pop();
    if (node === undefined) break;
    if (defaultTreeAdapter.isTextNode(node)) {
      const value = node.value.slice(
        0,
        HTML_EXTRACTION_LIMITS.max_anchor_text_chars - length,
      );
      parts.push(value);
      length += value.length;
    } else if (!(isElement(node) && EXCLUDED_CONTENT.has(node.tagName))) {
      pushChildren(node, stack);
    }
  }
  return parts.join("").replace(/\s+/g, " ").trim();
}

/**
 * Parse bounded pasted text as an inert HTML fragment. parse5 implements the
 * HTML tokenizer/tree builder without a live DOM, script execution, fetching,
 * rendering, or subresource loading. Only anchor hrefs and bounded text are
 * read; document-controlled base elements are ignored.
 */
export function extractHtmlLinkCandidates(
  input: string,
  context: HtmlExtractionContext,
): ExtractedLinkCandidate[] {
  const fragment = parseFragment(input.slice(0, HTML_EXTRACTION_LIMITS.max_input_chars));
  const candidates: ExtractedLinkCandidate[] = [];
  const stack: Node[] = [fragment];

  while (stack.length > 0 && candidates.length < HTML_EXTRACTION_LIMITS.max_candidates) {
    const node = stack.pop();
    if (node === undefined) break;
    if (isElement(node)) {
      if (EXCLUDED_CONTENT.has(node.tagName)) continue;
      if (node.tagName === "a") {
        const href = node.attrs.find((attribute) => attribute.name === "href")?.value;
        if (href !== undefined && href.length <= HTML_EXTRACTION_LIMITS.max_href_chars) {
          candidates.push({
            raw_href: href,
            anchor_text: normalizedAnchorText(node),
            base_url: context.base_url,
            provenance: {
              source: "paste_html",
              document_url: context.document_url,
              occurrence_index: candidates.length,
              extracted_at: context.extracted_at,
            },
          });
        }
      }
    }
    pushChildren(node, stack);
  }
  return candidates;
}
