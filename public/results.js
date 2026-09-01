const node = (tag, className, value) => { const element = document.createElement(tag);
  if (className) element.className = className;
  if (value !== undefined) element.textContent = String(value);
  return element; };
function list(title, values) { const section = node("section"); section.append(node("h4", "", title));
  const items = node("ul", "evidence");
  for (const value of values) items.append(node("li", "", value));
  if (!values.length) items.append(node("li", "", "None recorded."));
  section.append(items); return section; }
function verdicts(result) { const values = node("dl", "verdicts");
  for (const [label, value] of [["Risk", result.risk], ["State", result.state],
    ["Confidence", result.confidence]]) {
    const group = node("div"); group.append(node("dt", "", label), node("dd", "", value)); values.append(group); }
  return values; }
export function renderResults(container, results) {
  for (const old of container.querySelectorAll(".result-grid, .trust-note")) old.remove();
  const grid = node("div", "result-grid"); for (const result of results) {
    const card = node("article", "result-card"); card.dataset.scanId = result.scanId;
    const evidence = result.evidence.map((item) => `${item.polarity} · ${item.source} · ${item.category} · ${item.target}`);
    const providers = result.providers.map((item) => [item.provider, item.state, item.freshness, item.category, item.error, item.reference]
        .filter((value) => value !== null).join(" · "));
    card.append(node("h3", "break", result.target), verdicts(result),
      list("Evidence", evidence), list("Provider observations", providers),
      list("Limitations", result.limitations));
    grid.append(card); }
  if (!results.length) grid.append(node("p", "", "No result records were returned."));
  container.append(node("p", "trust-note",
    "Page, URL, and provider strings below are untrusted evidence rendered as inert text."), grid);
  container.hidden = false;
}
