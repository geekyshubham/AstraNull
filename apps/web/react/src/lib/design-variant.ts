import { useCallback, useEffect, useState } from 'react';

/**
 * Per-page design variant. "classic" is the established console layout and the default;
 * "refined" is the alternate layout over the same records, actions, and permission gates.
 *
 * Not presentation-only for Findings: the variants group findings into different entities
 * (ADR-0009). Classic groups by "rule" (findingRuleKey in findings-helpers.ts: the displayed
 * outcome/title, merging checks); Refined groups by "alert" (findingGroupKey in
 * finding-groups.mjs: check id + issue identity). The same findings can be one Classic rule
 * and two Refined alerts, so group counts and drilldown membership differ between variants.
 */
export type DesignVariant = 'classic' | 'refined';

/** Pages that currently ship a Refined presentation. */
export type VariantPage = 'test-policies' | 'runs' | 'findings';

const STORAGE_PREFIX = 'astranull.design-variant.';
const HASH_PARAM = 'variant';

export function designVariantStorageKey(page: VariantPage) {
  return `${STORAGE_PREFIX}${page}`;
}

export function parseDesignVariant(value: unknown): DesignVariant | null {
  const normalized = String(value ?? '').trim().toLowerCase();
  return normalized === 'refined' || normalized === 'classic' ? normalized : null;
}

function splitHash(): { route: string; params: URLSearchParams | null } {
  if (typeof window === 'undefined') return { route: '', params: null };
  const hash = window.location.hash.replace(/^#\/?/, '');
  const index = hash.indexOf('?');
  return index >= 0
    ? { route: hash.slice(0, index), params: new URLSearchParams(hash.slice(index + 1)) }
    : { route: hash, params: null };
}

/**
 * `#<page>?variant=refined|classic` overrides the stored preference. The override only
 * applies to the page named by the hash route (VariantPage ids equal their RouteIds), so a
 * page that hosts several variant hooks never persists one route's override into another.
 */
export function readHashDesignVariant(page: VariantPage): DesignVariant | null {
  const { route, params } = splitHash();
  if (route !== page) return null;
  return parseDesignVariant(params?.get(HASH_PARAM));
}

function readStoredVariant(page: VariantPage): DesignVariant | null {
  try {
    return parseDesignVariant(window.localStorage.getItem(designVariantStorageKey(page)));
  } catch {
    return null;
  }
}

function writeStoredVariant(page: VariantPage, variant: DesignVariant) {
  try {
    window.localStorage.setItem(designVariantStorageKey(page), variant);
  } catch {
    // Best-effort preference persistence only; private windows may block storage.
  }
}

/**
 * Keep an explicit `variant` hash param in step with the user's choice so a reload does
 * not revert it. replaceState does not fire hashchange, so the route does not remount.
 */
function syncHashVariant(page: VariantPage, variant: DesignVariant) {
  try {
    const hash = window.location.hash.replace(/^#/, '');
    const index = hash.indexOf('?');
    if (index < 0 || hash.slice(0, index).replace(/^\//, '') !== page) return;
    const params = new URLSearchParams(hash.slice(index + 1));
    if (!params.has(HASH_PARAM) || params.get(HASH_PARAM) === variant) return;
    params.set(HASH_PARAM, variant);
    const nextHash = `#${hash.slice(0, index)}?${params.toString()}`;
    window.history.replaceState(window.history.state, '', `${window.location.pathname}${window.location.search}${nextHash}`);
  } catch {
    // History access can fail in sandboxed previews; the in-memory choice still applies.
  }
}

function resolveVariant(page: VariantPage): DesignVariant {
  if (typeof window === 'undefined') return 'classic';
  const fromHash = readHashDesignVariant(page);
  if (fromHash) {
    writeStoredVariant(page, fromHash);
    return fromHash;
  }
  return readStoredVariant(page) ?? 'classic';
}

export function useDesignVariant(page: VariantPage): [DesignVariant, (v: DesignVariant) => void] {
  const [variant, setVariantState] = useState<DesignVariant>(() => resolveVariant(page));

  useEffect(() => {
    setVariantState(resolveVariant(page));
    function onHashChange() {
      const fromHash = readHashDesignVariant(page);
      if (!fromHash) return;
      writeStoredVariant(page, fromHash);
      setVariantState(fromHash);
    }
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, [page]);

  const setVariant = useCallback((next: DesignVariant) => {
    setVariantState(next);
    writeStoredVariant(page, next);
    syncHashVariant(page, next);
  }, [page]);

  return [variant, setVariant];
}
