const clone = (value) => structuredClone(value);
const DELETE = Symbol("delete");
const key = (path) => path.map(String).join(".");

function owner(root, path) {
  let current = root;
  for (const segment of path.slice(0, -1)) current = current[segment];
  return [current, path.at(-1)];
}

export function mutateAt(value, path, replacement) {
  const copy = clone(value);
  const [parent, field] = owner(copy, path);
  if (replacement === DELETE) delete parent[field];
  else parent[field] = clone(replacement);
  return copy;
}

function wrongType(value) {
  if (typeof value === "string") return 0;
  if (typeof value === "number") return "0";
  if (typeof value === "boolean") return null;
  if (Array.isArray(value)) return {};
  if (value === null) return [];
  return [];
}

function records(value, path = [], output = []) {
  if (value === null || typeof value !== "object") return output;
  if (!Array.isArray(value)) output.push([path, value]);
  for (const [field, child] of Object.entries(value)) records(child, [...path, Array.isArray(value) ? Number(field) : field], output);
  return output;
}

function fields(value, path = [], output = []) {
  if (value === null || typeof value !== "object") return output;
  for (const [field, child] of Object.entries(value)) {
    const childPath = [...path, Array.isArray(value) ? Number(field) : field];
    output.push([childPath, child, Array.isArray(value)]);
    fields(child, childPath, output);
  }
  return output;
}

export function oneFieldMutants(value, { targeted = [], boundaries = [0, 1, 15, 16, 17, 32, 256] } = {}) {
  const mutants = [];
  const push = (kind, path, replacement, detail = kind) => mutants.push({ kind, path, detail, value: mutateAt(value, path, replacement) });
  for (const [path] of records(value)) push("add", [...path, "__unknown__"], true);
  for (const [path, current, arrayElement] of fields(value)) {
    if (!arrayElement) push("delete", path, DELETE);
    push("type", path, wrongType(current));
    if (typeof current === "number") for (const boundary of boundaries) if (boundary !== current) push("bound", path, boundary, `boundary:${boundary}`);
    if (typeof current === "boolean") push("boolean", path, !current);
    if (Array.isArray(current)) {
      if (current.length > 1) push("order", path, [...current].reverse());
      if (current.length > 0) {
        push("duplicate", path, [...current, clone(current[0])]);
        push("count", path, current.slice(0, -1));
      }
    }
  }
  for (const { path, kind, values } of targeted) {
    let current = value;
    for (const segment of path) current = current[segment];
    for (const replacement of values) if (JSON.stringify(replacement) !== JSON.stringify(current)) push(kind, path, replacement);
  }
  const unique = new Map(mutants.map((mutant) => [`${mutant.kind}:${key(mutant.path)}:${JSON.stringify(mutant.value)}`, mutant]));
  return [...unique.values()];
}

export function changedTopLevel(original, mutant) {
  const names = new Set([...Object.keys(original), ...Object.keys(mutant)]);
  return [...names].filter((name) => JSON.stringify(original[name]) !== JSON.stringify(mutant[name]));
}
