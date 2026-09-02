import type { FetchRejectionReason } from "../../shared/canonicalize.js";

export type AddressResolver = (
  hostname: string,
  signal: AbortSignal,
) => Promise<readonly string[]>;

export type AddressAdmission =
  | { ok: true; hostname: string; addresses: string[] }
  | { ok: false; reason: Extract<FetchRejectionReason, "unsafe_address" | "dns_failure" | "mixed_address"> };

// IANA special-use registries, checked 2026-09-01. Broad entries subsume
// narrower assignments; the conservative policy rejects every listed space.
export const SPECIAL_NAMES = [
  "alt", "arpa", "example", "example.com", "example.net", "example.org",
  "invalid", "local", "localhost", "onion", "test", "internal",
];

function ipv4(value: string): number[] | null {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  const bytes = parts.map((part) => /^\d{1,3}$/u.test(part) ? Number(part) : -1);
  return bytes.every((byte) => byte >= 0 && byte <= 255) ? bytes : null;
}

function ipv6(value: string): Uint8Array | null {
  let input = value.toLowerCase();
  if (input.startsWith("[") && input.endsWith("]")) input = input.slice(1, -1);
  if (input.includes("%") || input.split("::").length > 2) return null;
  const lastColon = input.lastIndexOf(":");
  const tail = input.slice(lastColon + 1);
  if (tail.includes(".")) {
    const mapped = ipv4(tail);
    if (mapped === null) return null;
    input = `${input.slice(0, lastColon)}:${((mapped[0] as number) << 8 | (mapped[1] as number)).toString(16)}:${((mapped[2] as number) << 8 | (mapped[3] as number)).toString(16)}`;
  }
  const halves = input.split("::");
  const left = halves[0] === "" ? [] : (halves[0] as string).split(":");
  const right = halves.length === 1 || halves[1] === "" ? [] : (halves[1] as string).split(":");
  if (halves.length === 1 ? left.length !== 8 : left.length + right.length >= 8) return null;
  const groups = [...left, ...Array(8 - left.length - right.length).fill("0"), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[\da-f]{1,4}$/u.test(group))) return null;
  const bytes = new Uint8Array(16);
  groups.forEach((group, index) => {
    const word = Number.parseInt(group, 16);
    bytes[index * 2] = word >>> 8;
    bytes[index * 2 + 1] = word & 255;
  });
  return bytes;
}

export function addressFamily(value: string): 4 | 6 | null { return ipv4(value) !== null ? 4 : ipv6(value) !== null ? 6 : null; }
function prefix(bytes: Uint8Array, expected: number[], bits: number): boolean {
  const full = Math.floor(bits / 8);
  for (let index = 0; index < full; index += 1) {
    if (bytes[index] !== expected[index]) return false;
  }
  const remaining = bits % 8;
  if (remaining === 0) return true;
  const mask = 256 - 2 ** (8 - remaining);
  return ((bytes[full] as number) & mask) === ((expected[full] as number) & mask);
}

const SPECIAL_IPV4: [number[], number][] = [
  [[0], 8], [[10], 8], [[100, 64], 10], [[127], 8], [[169, 254], 16],
  [[172, 16], 12], [[192, 0, 0], 24], [[192, 0, 2], 24],
  [[192, 31, 196], 24], [[192, 52, 193], 24], [[192, 88, 99], 24],
  [[192, 168], 16], [[192, 175, 48], 24], [[198, 18], 15],
  [[198, 51, 100], 24], [[203, 0, 113], 24], [[224], 3],
];

function publicIpv4(bytes: number[]): boolean {
  const packed = Uint8Array.from(bytes);
  return !SPECIAL_IPV4.some(([expected, bits]) => prefix(packed, expected, bits));
}

function publicIpv6(bytes: Uint8Array): boolean {
  if (!prefix(bytes, [0x20], 3)) return false;
  if (prefix(bytes, [0x20, 0x01, 0x00], 23)) return false;
  if (prefix(bytes, [0x20, 0x01, 0x0d, 0xb8], 32)) return false;
  if (prefix(bytes, [0x20, 0x02], 16)) return false;
  if (prefix(bytes, [0x26, 0x20, 0x00, 0x4f, 0x80, 0x00], 48)) return false;
  if (prefix(bytes, [0x3f, 0xff, 0x00], 20)) return false;
  return true;
}

export function isPublicAddress(value: string): boolean {
  const v4 = ipv4(value);
  if (v4 !== null) return publicIpv4(v4);
  const v6 = ipv6(value);
  return v6 !== null && publicIpv6(v6);
}

export function literalAddress(hostname: string): string | null {
  const stripped = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
  return ipv4(stripped) !== null || ipv6(stripped) !== null ? stripped : null;
}

export async function admitPublicHost(
  hostname: string,
  resolver: AddressResolver,
  signal: AbortSignal,
): Promise<AddressAdmission> {
  const normalized = hostname.toLowerCase().replace(/\.+$/u, "");
  const literal = literalAddress(normalized);
  if (literal !== null) {
    return isPublicAddress(literal)
      ? { ok: true, hostname: normalized, addresses: [literal] }
      : { ok: false, reason: "unsafe_address" };
  }
  if (
    !normalized.includes(".") ||
    SPECIAL_NAMES.some((name) => normalized === name || normalized.endsWith(`.${name}`))
  ) return { ok: false, reason: "unsafe_address" };
  let resolved: readonly string[];
  try {
    resolved = await resolver(normalized, signal);
  } catch {
    if (signal.aborted) throw new TypeError("address resolution timed out");
    return { ok: false, reason: "dns_failure" };
  }
  const addresses = [...new Set(resolved)];
  if (addresses.length === 0 || addresses.length > 32) return { ok: false, reason: "dns_failure" };
  const publicFlags = addresses.map(isPublicAddress);
  if (publicFlags.every(Boolean)) return { ok: true, hostname: normalized, addresses };
  return { ok: false, reason: publicFlags.some(Boolean) ? "mixed_address" : "unsafe_address" };
}
