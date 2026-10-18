/**
 * Shared subdomain grouping for the customer console. Imported subdomains are stored as
 * ordinary fqdn targets, which would otherwise crowd the Targets list and inflate the
 * target counts shown on the overview and other dashboards. A target is treated as a
 * subdomain child when another declared fqdn in the same target group is a strict hostname
 * ancestor of it (mirrors the target detail "Subdomains" tab: same group + containment).
 * Display-only: this does not change scoring or coverage math.
 */

type Rec = Record<string, unknown>;

function field(item: Rec, key: string): string {
  const value = item?.[key];
  return typeof value === 'string' ? value : '';
}

function hostOf(item: Rec): string {
  const kind = field(item, 'kind').trim().toLowerCase();
  if (kind !== 'fqdn') return '';
  const raw = field(item, 'value').trim().toLowerCase();
  if (!raw) return '';
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(raw)) {
    try {
      return new URL(raw).hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '');
    } catch {
      return '';
    }
  }
  return raw.replace(/\.$/, '');
}

export function isStrictSubdomainHost(host: string, parent: string): boolean {
  return !!host && !!parent && host !== parent && host.endsWith(`.${parent}`);
}

export interface SubdomainGrouping {
  /** Ids of targets that are subdomains of another declared target (hidden from top-level views). */
  hiddenIds: Set<string>;
  /** For each visible parent id, how many declared descendants are grouped under it. */
  childCount: Map<string, number>;
}

export function computeSubdomainGrouping(items: readonly Rec[]): SubdomainGrouping {
  const nodes = items
    .map((item) => ({ id: field(item, 'id'), group: field(item, 'target_group_id'), host: hostOf(item) }))
    .filter((node) => node.id && node.host);
  const hiddenIds = new Set<string>();
  for (const node of nodes) {
    if (nodes.some((other) => other.id !== node.id && other.group === node.group && isStrictSubdomainHost(node.host, other.host))) {
      hiddenIds.add(node.id);
    }
  }
  const childCount = new Map<string, number>();
  for (const parent of nodes) {
    if (hiddenIds.has(parent.id)) continue;
    const count = nodes.filter((node) => node.id !== parent.id && node.group === parent.group && isStrictSubdomainHost(node.host, parent.host)).length;
    if (count > 0) childCount.set(parent.id, count);
  }
  return { hiddenIds, childCount };
}

/** Nearest declared ancestor per subdomain target id (same group, longest strict parent host). */
export function subdomainParentMap(items: readonly Rec[]): Map<string, string> {
  const nodes = items
    .map((item) => ({ id: field(item, 'id'), group: field(item, 'target_group_id'), host: hostOf(item) }))
    .filter((node) => node.id && node.host);
  const parents = new Map<string, string>();
  for (const node of nodes) {
    let best: { id: string; host: string } | null = null;
    for (const other of nodes) {
      if (other.id === node.id || other.group !== node.group || !isStrictSubdomainHost(node.host, other.host)) continue;
      if (!best || other.host.length > best.host.length) best = other;
    }
    if (best) parents.set(node.id, best.id);
  }
  return parents;
}

/** Top-level ancestor id for a target, following the parent chain from subdomainParentMap. */
export function topLevelAncestor(id: string, parents: ReadonlyMap<string, string>): string {
  let current = id;
  const seen = new Set<string>();
  while (parents.has(current) && !seen.has(current)) {
    seen.add(current);
    current = parents.get(current)!;
  }
  return current;
}

/** The targets that are not subdomains of another declared target (top-level domains + standalone). */
export function topLevelTargets<T extends Rec>(items: readonly T[]): T[] {
  const { hiddenIds } = computeSubdomainGrouping(items);
  return items.filter((item) => !hiddenIds.has(field(item, 'id')));
}
