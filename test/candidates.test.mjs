import assert from "node:assert/strict";
import test from "node:test";

import {
  CANONICAL_REJECTION_REASONS,
  canonicalizeUrl,
} from "../dist/shared/canonicalize.js";
import { collectLinkCandidates } from "../dist/shared/candidates.js";
import {
  HTML_EXTRACTION_LIMITS,
  extractHtmlLinkCandidates,
} from "../dist/shared/extract-html.js";

function accepted(raw, base) {
  const result = canonicalizeUrl(raw, base);
  assert.equal(result.ok, true, JSON.stringify(result));
  return result.target;
}

function rejected(raw, reason, base) {
  const result = canonicalizeUrl(raw, base);
  assert.deepEqual(result, { ok: false, reason });
}

function occurrence(raw_href, anchor_text, occurrence_index, overrides = {}) {
  return {
    raw_href,
    anchor_text,
    base_url: "https://source.example/dir/page.html",
    provenance: {
      source: "live_page",
      document_url: "https://source.example/reference",
      occurrence_index,
      extracted_at: "2026-08-31T20:00:00Z",
    },
    ...overrides,
  };
}

const extractionContext = {
  base_url: "https://source.example/original/path",
  document_url: "https://source.example/pasted",
  extracted_at: "2026-08-31T20:01:02Z",
};

test("canonicalization uses platform parsing while preserving path and query semantics", () => {
  assert.deepEqual(accepted("HTTPS://ExAmPle.COM:443/a/../b/%2F?q=a+b&q=%2F#section"), {
    canonical_url: "https://example.com/b/%2F?q=a+b&q=%2F",
    scheme: "https",
    hostname_ascii: "example.com",
    display_hostname: "example.com",
  });
  assert.equal(accepted("http://EXAMPLE.com:80/path?").canonical_url, "http://example.com/path?");
  assert.equal(accepted("  https://EXAMPLE.com/trimmed  ").canonical_url, "https://example.com/trimmed");
  assert.equal(
    accepted("../next?keep=1&keep=2", "https://Base.Example/a/b/page#old").canonical_url,
    "https://base.example/a/next?keep=1&keep=2",
  );
  assert.equal(
    accepted("//Other.Example/x", "https://base.example/").canonical_url,
    "https://other.example/x",
  );
  assert.equal(accepted("http:example.com").canonical_url, "http://example.com/");
  assert.equal(accepted("https:\\example.com\\a\\b").canonical_url, "https://example.com/a/b");
});

test("IDNs use their lowercase ASCII form for comparison and safe display", () => {
  const unicode = accepted("https://BÜCHER.example/angebot");
  const ascii = accepted("https://xn--bcher-kva.example/angebot");
  assert.deepEqual(unicode, ascii);
  assert.equal(unicode.hostname_ascii, "xn--bcher-kva.example");
  assert.equal(unicode.display_hostname, "xn--bcher-kva.example");
});

test("numeric and IPv6 hosts have deterministic WHATWG forms", () => {
  assert.equal(accepted("http://127.1/a").canonical_url, "http://127.0.0.1/a");
  assert.equal(accepted("http://0x7f000001/").hostname_ascii, "127.0.0.1");
  assert.equal(accepted("https://[2001:0db8::1]/x").canonical_url, "https://[2001:db8::1]/x");
});

test("only credential-free HTTP(S) URLs on default ports are admitted", () => {
  assert.deepEqual(CANONICAL_REJECTION_REASONS, [
    "empty_input", "missing_base_url", "invalid_url", "unsupported_scheme",
    "credentials_not_allowed", "disallowed_port",
  ]);
  rejected("", "empty_input");
  rejected("/relative", "missing_base_url");
  rejected("https://exa mple/", "invalid_url");
  rejected("/relative", "invalid_url", "data:text/plain,base");
  rejected("javascript:alert(1)", "unsupported_scheme");
  rejected("data:text/html,hello", "unsupported_scheme");
  rejected("ftp://example.com/file", "unsupported_scheme");
  rejected("https://user:secret@example.com/", "credentials_not_allowed");
  rejected("http://example.com:443/", "disallowed_port");
  rejected("https://example.com:80/", "disallowed_port");
  rejected("https://example.com:8443/", "disallowed_port");
  rejected("https://example.com:99999/", "invalid_url");
  assert.equal(accepted("https://example.com:443/").canonical_url, "https://example.com/");
});

test("collection deduplicates targets but retains every occurrence and text variant", () => {
  const first = occurrence("HTTPS://Example.com:443/report#one", "First label", 4);
  const second = occurrence("https://example.com/report#two", "Second label", 9);
  const bad = occurrence("mailto:help@example.com", "mail", 10);
  const collection = collectLinkCandidates([first, second, bad]);

  assert.equal(collection.targets.length, 1);
  assert.equal(collection.targets[0].canonical_url, "https://example.com/report");
  assert.deepEqual(collection.targets[0].anchor_text_variants, ["First label", "Second label"]);
  assert.deepEqual(collection.targets[0].occurrences.map((item) => item.candidate), [first, second]);
  assert.deepEqual(collection.targets[0].occurrences.map((item) => item.candidate.provenance.occurrence_index), [4, 9]);
  assert.deepEqual(collection.rejected, [{ candidate: bad, reason: "unsupported_scheme" }]);
});

test("URL-like anchor text records bounded mismatch evidence", () => {
  const misleading = occurrence(
    "https://accounts.example.invalid/login",
    "https://accounts.example.com/login#top",
    0,
  );
  const equivalent = occurrence(
    "https://www.example.com/#section",
    "www.example.com",
    1,
  );
  const prose = occurrence("https://target.example/", "Visit the target", 2);
  const bareDomain = occurrence("https://elsewhere.invalid/path", "example.com/path", 3);
  const collection = collectLinkCandidates([misleading, equivalent, prose, bareDomain]);

  assert.deepEqual(collection.targets[0].occurrences[0].misleading_text, {
    displayed_text: "https://accounts.example.com/login#top",
    displayed_target: "https://accounts.example.com/login",
    linked_target: "https://accounts.example.invalid/login",
  });
  assert.equal(collection.targets[1].occurrences[0].misleading_text, null);
  assert.equal(collection.targets[2].occurrences[0].misleading_text, null);
  assert.deepEqual(collection.targets[3].occurrences[0].misleading_text, {
    displayed_text: "example.com/path",
    displayed_target: "https://example.com/path",
    linked_target: "https://elsewhere.invalid/path",
  });
});

test("inert HTML extraction returns anchors with provenance and decoded text", () => {
  const html = `
    <base href="https://attacker.invalid/">
    <A data-x="1 > 0" HREF="../report?a=1&amp;b=2#part"> Report <b>one</b> &amp; more </A>
    <a href='https://EXAMPLE.com:443/second'>second</a>
    <a href="/third" href="https://duplicate.invalid/">duplicate href</a>`;
  const candidates = extractHtmlLinkCandidates(html, extractionContext);

  assert.deepEqual(candidates, [
    occurrence("../report?a=1&b=2#part", "Report one & more", 0, {
      base_url: extractionContext.base_url,
      provenance: {
        source: "paste_html",
        document_url: extractionContext.document_url,
        occurrence_index: 0,
        extracted_at: extractionContext.extracted_at,
      },
    }),
    occurrence("https://EXAMPLE.com:443/second", "second", 1, {
      base_url: extractionContext.base_url,
      provenance: {
        source: "paste_html",
        document_url: extractionContext.document_url,
        occurrence_index: 1,
        extracted_at: extractionContext.extracted_at,
      },
    }),
    occurrence("/third", "duplicate href", 2, {
      base_url: extractionContext.base_url,
      provenance: {
        source: "paste_html",
        document_url: extractionContext.document_url,
        occurrence_index: 2,
        extracted_at: extractionContext.extracted_at,
      },
    }),
  ]);
  assert.equal(
    collectLinkCandidates(candidates).targets[0].canonical_url,
    "https://source.example/report?a=1&b=2",
  );
});

test("scripts, comments, inert containers and subresource attributes yield no candidates", () => {
  globalThis.__watchDogExecuted = false;
  const hostile = `
    <script>globalThis.__watchDogExecuted = true; '<a href="https://script.invalid">x</a>';</script>
    <!-- <a href="https://comment.invalid">x</a> -->
    <style>.x { background: url(https://css.invalid/a) }</style>
    <template><a href="https://template.invalid">x</a></template>
    <noscript><a href="https://noscript.invalid">x</a></noscript>
    <iframe src="https://frame.invalid"><a href="https://fallback.invalid">x</a></iframe>
    <svg><a href="https://svg.invalid">x</a></svg>
    <img src="https://image.invalid" srcset="https://set.invalid 2x" onerror="globalThis.__watchDogExecuted=true">
    <object data="https://object.invalid"></object>
    <link href="https://stylesheet.invalid" rel="stylesheet">
    <div style="background:url(https://inline.invalid)"></div>`;
  assert.deepEqual(extractHtmlLinkCandidates(hostile, extractionContext), []);
  assert.equal(globalThis.__watchDogExecuted, false);
  delete globalThis.__watchDogExecuted;
});

test("self-closing syntax cannot escape HTML raw-text containers", () => {
  const hostile = `
    <script src="https://script.invalid"/><a href="https://inside-script.invalid">hidden</a>
    <plaintext><a href="https://plaintext.invalid">hidden</a>`;
  assert.deepEqual(extractHtmlLinkCandidates(hostile, extractionContext), []);
});

test("malformed and nested markup is handled conservatively", () => {
  const html = `
    <a href=/first>first<a href="/second">second</a>
    <a href="javascript:alert(1)">not admitted</a>
    <a href="/unterminated">tail
    <script><a href="/hidden">hidden</a>`;
  const extracted = extractHtmlLinkCandidates(html, extractionContext);
  assert.deepEqual(extracted.map((item) => [item.raw_href, item.anchor_text]), [
    ["/first", "first"],
    ["/second", "second"],
    ["javascript:alert(1)", "not admitted"],
    ["/unterminated", "tail"],
  ]);
  const collected = collectLinkCandidates(extracted);
  assert.deepEqual(collected.targets.map((item) => item.canonical_url), [
    "https://source.example/first",
    "https://source.example/second",
    "https://source.example/unterminated",
  ]);
  assert.equal(collected.rejected[0].reason, "unsupported_scheme");
});

test("an explicit empty href is retained for typed candidate rejection", () => {
  const extracted = extractHtmlLinkCandidates('<a href="">same document</a><a>no href</a>', extractionContext);
  assert.equal(extracted.length, 1);
  assert.equal(extracted[0].raw_href, "");
  assert.deepEqual(collectLinkCandidates(extracted).rejected, [
    { candidate: extracted[0], reason: "empty_input" },
  ]);
});

test("HTML extraction enforces input, href, text and candidate limits", () => {
  const many = Array.from(
    { length: HTML_EXTRACTION_LIMITS.max_candidates + 5 },
    (_, index) => `<a href="/${index}">${"x".repeat(700)}</a>`,
  ).join("");
  const extracted = extractHtmlLinkCandidates(many, extractionContext);
  assert.equal(extracted.length, HTML_EXTRACTION_LIMITS.max_candidates);
  assert.equal(extracted[0].anchor_text.length, HTML_EXTRACTION_LIMITS.max_anchor_text_chars);
  assert.equal(extracted.at(-1).provenance.occurrence_index, HTML_EXTRACTION_LIMITS.max_candidates - 1);

  const oversizedHref = `<a href="/${"z".repeat(HTML_EXTRACTION_LIMITS.max_href_chars)}">skip</a>`;
  assert.deepEqual(extractHtmlLinkCandidates(oversizedHref, extractionContext), []);
});
