const delayMilliseconds = 900;

setTimeout(() => {
  const list = document.querySelector("#reference-links");
  const status = document.querySelector("#delayed-status");
  if (!(list instanceof HTMLElement) || !(status instanceof HTMLElement)) return;
  const item = document.createElement("li");
  const anchor = document.createElement("a");
  anchor.id = "delayed-live-anchor";
  anchor.href = "./delayed-evidence";
  anchor.textContent = "Anchor inserted after page load";
  item.append(anchor);
  list.append(item);
  status.textContent = "The delayed rendered anchor is now present.";
}, delayMilliseconds);
