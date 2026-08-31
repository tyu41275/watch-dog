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

interface TagToken {
  name: string;
  closing: boolean;
  selfClosing: boolean;
  attributes: Map<string, string>;
}

interface OpenAnchor {
  href: string;
  text: string;
}

// Content in these elements is deliberately never interpreted as links.
const INERT_CONTENT = new Set([
  "script", "style", "template", "noscript", "iframe", "frame",
  "object", "svg", "math", "textarea", "xmp", "plaintext", "title",
  "noembed", "noframes", "select",
]);

function opensInertContent(token: TagToken): boolean {
  if (token.closing || !INERT_CONTENT.has(token.name) || token.name === "frame") return false;
  // Self-closing syntax is honored in foreign SVG/MathML content, but ignored
  // for non-void HTML raw-text and container elements.
  return !(token.selfClosing && (token.name === "svg" || token.name === "math"));
}

const NAMED_ENTITIES: Readonly<Record<string, string>> = {
  amp: "&",
  apos: "'",
  gt: ">",
  lt: "<",
  nbsp: "\u00a0",
  quot: '"',
};

function decodeEntities(value: string): string {
  return value.replace(
    /&(#(?:x[\da-f]+|\d+)|[a-z]+);/gi,
    (whole: string, body: string) => {
      if (body[0] !== "#") return NAMED_ENTITIES[body.toLowerCase()] ?? whole;
      const hex = body[1]?.toLowerCase() === "x";
      const numeric = Number.parseInt(body.slice(hex ? 2 : 1), hex ? 16 : 10);
      if (!Number.isInteger(numeric) || numeric === 0 || numeric > 0x10ffff ||
          (numeric >= 0xd800 && numeric <= 0xdfff)) return "\ufffd";
      return String.fromCodePoint(numeric);
    },
  );
}

function normalizeText(value: string): string {
  return decodeEntities(value).replace(/\s+/g, " ").trim();
}

function readTagEnd(html: string, start: number): number {
  let quote = "";
  for (let index = start + 1; index < html.length; index += 1) {
    const character = html[index] ?? "";
    if (quote !== "") {
      if (character === quote) quote = "";
    } else if (character === '"' || character === "'") {
      quote = character;
    } else if (character === ">") {
      return index;
    }
  }
  return -1;
}

function parseTag(source: string): TagToken | null {
  let index = 1;
  while (/\s/.test(source[index] ?? "")) index += 1;
  const closing = source[index] === "/";
  if (closing) index += 1;
  while (/\s/.test(source[index] ?? "")) index += 1;

  const nameStart = index;
  while (/[A-Za-z0-9:-]/.test(source[index] ?? "")) index += 1;
  if (index === nameStart) return null;
  const name = source.slice(nameStart, index).toLowerCase();
  const attributes = new Map<string, string>();

  while (index < source.length - 1 && !closing) {
    while (/\s/.test(source[index] ?? "")) index += 1;
    if (source[index] === "/" || source[index] === ">") break;
    const attributeStart = index;
    while (/[^\s=/>]/.test(source[index] ?? "")) index += 1;
    if (index === attributeStart) {
      index += 1;
      continue;
    }
    const attributeName = source.slice(attributeStart, index).toLowerCase();
    while (/\s/.test(source[index] ?? "")) index += 1;
    let value = "";
    if (source[index] === "=") {
      index += 1;
      while (/\s/.test(source[index] ?? "")) index += 1;
      const quote = source[index];
      if (quote === '"' || quote === "'") {
        index += 1;
        const valueStart = index;
        while (index < source.length && source[index] !== quote) index += 1;
        value = source.slice(valueStart, index);
        if (source[index] === quote) index += 1;
      } else {
        const valueStart = index;
        while (/[^\s>]/.test(source[index] ?? "")) index += 1;
        value = source.slice(valueStart, index);
      }
    }
    // Match browser behavior for duplicate attributes: the first wins.
    if (!attributes.has(attributeName)) attributes.set(attributeName, decodeEntities(value));
  }

  return {
    name,
    closing,
    selfClosing: /\/\s*>$/.test(source),
    attributes,
  };
}

function appendText(anchor: OpenAnchor | null, value: string): void {
  if (anchor === null || anchor.text.length >= HTML_EXTRACTION_LIMITS.max_anchor_text_chars) return;
  anchor.text += value.slice(0, HTML_EXTRACTION_LIMITS.max_anchor_text_chars - anchor.text.length);
}

/**
 * Extract anchors from pasted text without constructing a DOM. This function
 * has no execution, fetching, or subresource-loading capability and ignores
 * document-controlled base elements.
 */
export function extractHtmlLinkCandidates(
  input: string,
  context: HtmlExtractionContext,
): ExtractedLinkCandidate[] {
  const html = input.slice(0, HTML_EXTRACTION_LIMITS.max_input_chars);
  const candidates: ExtractedLinkCandidate[] = [];
  const inertStack: string[] = [];
  let anchor: OpenAnchor | null = null;
  let cursor = 0;

  const finishAnchor = (): void => {
    if (anchor === null || candidates.length >= HTML_EXTRACTION_LIMITS.max_candidates) return;
    if (anchor.href.length <= HTML_EXTRACTION_LIMITS.max_href_chars) {
      candidates.push({
        raw_href: anchor.href,
        anchor_text: normalizeText(anchor.text),
        base_url: context.base_url,
        provenance: {
          source: "paste_html",
          document_url: context.document_url,
          occurrence_index: candidates.length,
          extracted_at: context.extracted_at,
        },
      });
    }
    anchor = null;
  };

  while (cursor < html.length && candidates.length < HTML_EXTRACTION_LIMITS.max_candidates) {
    const tagStart = html.indexOf("<", cursor);
    if (tagStart < 0) {
      if (inertStack.length === 0) appendText(anchor, html.slice(cursor));
      break;
    }
    if (inertStack.length === 0) appendText(anchor, html.slice(cursor, tagStart));

    if (html.startsWith("<!--", tagStart)) {
      const end = html.indexOf("-->", tagStart + 4);
      cursor = end < 0 ? html.length : end + 3;
      continue;
    }
    const tagEnd = readTagEnd(html, tagStart);
    if (tagEnd < 0) break;
    const token = parseTag(html.slice(tagStart, tagEnd + 1));
    cursor = tagEnd + 1;
    if (token === null) continue;

    if (inertStack.length > 0) {
      if (token.closing && token.name === inertStack[inertStack.length - 1]) inertStack.pop();
      else if (opensInertContent(token)) {
        inertStack.push(token.name);
      }
      continue;
    }

    if (!token.closing && INERT_CONTENT.has(token.name)) {
      if (opensInertContent(token)) inertStack.push(token.name);
      continue;
    }
    if (token.name !== "a") continue;
    if (token.closing) {
      finishAnchor();
      continue;
    }

    // HTML's nested-anchor recovery closes the previous anchor first.
    finishAnchor();
    const href = token.attributes.get("href");
    if (href !== undefined) anchor = { href, text: "" };
    if (token.selfClosing) finishAnchor();
  }

  finishAnchor();
  return candidates;
}
