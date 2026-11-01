// Debian Policy 5.6.12: https://www.debian.org/doc/debian-policy/ch-controlfields.html#version
// OSV evaluation: https://ossf.github.io/osv-schema/#evaluation
// This module supports Debian/Ubuntu ECOSYSTEM ordering only. Callers must gate ecosystem/type.
type Ordering = -1 | 0 | 1;
export type OsvRangeEvent = {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
};

function numeric(a: string, b: string): Ordering {
  a = a.replace(/^0+/, "");
  b = b.replace(/^0+/, "");
  if (a.length !== b.length) return a.length < b.length ? -1 : 1;
  return a === b ? 0 : a < b ? -1 : 1;
}

function parseVersion(value: string) {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096)
    throw new Error("Malformed or unsupported Debian version");
  let epoch = "0", rest = value;
  const colon = value.indexOf(":");
  if (colon !== -1) {
    epoch = value.slice(0, colon);
    rest = value.slice(colon + 1);
    if (!/^[0-9]+$/.test(epoch)) throw new Error("Malformed Debian epoch");
  }
  const hyphen = rest.lastIndexOf("-");
  const upstream = hyphen === -1 ? rest : rest.slice(0, hyphen);
  const revision = hyphen === -1 ? "0" : rest.slice(hyphen + 1);
  if (!/^[0-9][A-Za-z0-9.+~\-]*$/.test(upstream) || !/^[A-Za-z0-9+.~]+$/.test(revision))
    throw new Error("Malformed or unsupported Debian version");
  return { epoch, upstream, revision };
}

function digit(c: string | undefined): boolean {
  return c !== undefined && c >= "0" && c <= "9";
}
function order(c: string | undefined): number {
  if (c === "~") return -1;
  if (c === undefined || digit(c)) return 0;
  return /[A-Za-z]/.test(c) ? c.charCodeAt(0) : c.charCodeAt(0) + 256;
}
function comparePart(a: string, b: string): Ordering {
  let i = 0, j = 0;
  while (i < a.length || j < b.length) {
    while ((i < a.length && !digit(a[i])) || (j < b.length && !digit(b[j]))) {
      const left = order(a[i]), right = order(b[j]);
      if (left !== right) return left < right ? -1 : 1;
      if (i < a.length) i++;
      if (j < b.length) j++;
    }
    const startA = i, startB = j;
    while (digit(a[i])) i++;
    while (digit(b[j])) j++;
    const n = numeric(a.slice(startA, i), b.slice(startB, j));
    if (n !== 0) return n;
  }
  return 0;
}

export function compareDebianVersions(a: string, b: string): Ordering {
  const left = parseVersion(a), right = parseVersion(b);
  return numeric(left.epoch, right.epoch) || comparePart(left.upstream, right.upstream) || comparePart(left.revision, right.revision);
}

// Fixed bounds exclude their version; last_affected includes it. Limits restrict the whole range.
export function matchesOsvRange(version: string, events: readonly OsvRangeEvent[]): boolean {
  parseVersion(version);
  if (!Array.isArray(events) || events.length === 0 || events.length > 1000)
    throw new Error("Malformed OSV event array");
  const allowed = ["introduced", "fixed", "last_affected", "limit"] as const;
  const timeline: Array<{kind: typeof allowed[number]; value: string}> = [];
  const limits: string[] = [];
  let hasIntroduced = false, hasFixed = false, hasLastAffected = false;
  for (const event of events) {
    if (!event || typeof event !== "object" || Array.isArray(event)) throw new Error("Malformed OSV event");
    const keys = Object.keys(event);
    if (keys.length !== 1 || !allowed.includes(keys[0] as typeof allowed[number]))
      throw new Error("OSV event must contain exactly one supported key");
    const kind = keys[0] as typeof allowed[number];
    const value = event[kind];
    if (typeof value !== "string") throw new Error("OSV event version must be a string");
    if (kind === "limit" && value === "*") { limits.push(value); continue; }
    parseVersion(value);
    if (kind === "limit") { limits.push(value); continue; }
    if (kind === "introduced") hasIntroduced = true;
    if (kind === "fixed") hasFixed = true;
    if (kind === "last_affected") hasLastAffected = true;
    timeline.push({ kind, value });
  }
  if (!hasIntroduced || (hasFixed && hasLastAffected))
    throw new Error("OSV range needs introduced and cannot mix fixed with last_affected");
  timeline.sort((a, b) => {
    if (a.kind === "introduced" && a.value === "0") return b.kind === "introduced" && b.value === "0" ? 0 : -1;
    if (b.kind === "introduced" && b.value === "0") return 1;
    return compareDebianVersions(a.value, b.value);
  });
  // Equivalent boundaries of opposite kinds cannot define an unambiguous transition order.
  for (let i = 1; i < timeline.length; i++) {
    const a = timeline[i - 1], b = timeline[i];
    if (a.kind !== b.kind && !(a.kind === "introduced" && a.value === "0") && compareDebianVersions(a.value, b.value) === 0)
      throw new Error("Ambiguous equal OSV boundaries");
  }
  if (limits.length && !limits.some(limit => limit === "*" || compareDebianVersions(version, limit) < 0)) return false;
  let affected = false;
  for (const event of timeline) {
    if (event.kind === "introduced" && event.value === "0") affected = true;
    else {
      const comparison = compareDebianVersions(version, event.value);
      if (event.kind === "introduced" && comparison >= 0) affected = true;
      if (event.kind === "fixed" && comparison >= 0) affected = false;
      if (event.kind === "last_affected" && comparison > 0) affected = false;
    }
  }
  return affected;
}
