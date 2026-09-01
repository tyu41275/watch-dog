const MAX_ITEMS = 16;
const text = (value, maximum = 2048) => String(value ?? "").slice(0, maximum);

function element(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined) node.textContent = text(value);
  return node;
}

function evidenceList(title, items) {
  const section = element("section", "evidence-group");
  section.append(element("h4", "", title));
  const list = element("ul", "evidence");
  for (const item of Array.isArray(items) ? items.slice(0, MAX_ITEMS) : []) {
    const description = [item?.source, item?.category, item?.freshness, item?.target]
      .filter((part) => typeof part === "string").map((part) => text(part, 512)).join(" · ");
    list.append(element("li", "", description || "Unavailable evidence detail"));
  }
  if (!list.childNodes.length) list.append(element("li", "", "None recorded."));
  section.append(list);
  return section;
}

function verdicts(result) {
  const list = element("dl", "verdicts");
  for (const [label, value] of [
    ["Risk", result.risk_label], ["State", result.analysis_state], ["Confidence", result.confidence],
  ]) {
    const group = element("div");
    group.append(element("dt", "", label), element("dd", "", value));
    list.append(group);
  }
  return list;
}

function providerList(observations) {
  const section = element("section");
  section.append(element("h4", "", "Provider observations"));
  const list = element("ul", "evidence");
  for (const item of Array.isArray(observations) ? observations.slice(0, MAX_ITEMS) : []) {
    list.append(element("li", "", [item?.provider, item?.state, item?.freshness,
      item?.category, item?.error].filter(Boolean).map((value) => text(value, 256)).join(" · ")));
  }
  if (!list.childNodes.length) list.append(element("li", "", "No provider observation."));
  section.append(list);
  return section;
}

export function renderResults(container, results) {
  for (const old of container.querySelectorAll(".result-grid, .trust-note")) old.remove();
  const note = element("p", "trust-note", "Page, URL, and provider strings below are untrusted evidence rendered as inert text.");
  const grid = element("div", "result-grid");
  for (const result of Array.isArray(results) ? results.slice(0, MAX_ITEMS) : []) {
    const card = element("article", "result-card");
    card.dataset.scanId = text(result?.scan_id, 64);
    card.append(element("h3", "break", result?.canonical_target || "Unscannable input"), verdicts(result ?? {}));
    card.append(evidenceList("Supporting evidence", result?.supporting_evidence));
    card.append(evidenceList("Contradicting evidence", result?.contradicting_evidence));
    card.append(providerList(result?.provider_observations));
    card.append(evidenceList("Limitations", (result?.limitations ?? []).map((category) => ({ category }))));
    grid.append(card);
  }
  if (!grid.childNodes.length) grid.append(element("p", "", "No result records were returned."));
  container.append(note, grid);
  container.hidden = false;
}
