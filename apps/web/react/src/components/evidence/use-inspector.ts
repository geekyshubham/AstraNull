import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import {
  EVIDENCE_INSPECTOR_EVENT,
  inspectorRefKey,
  openEvidenceInspector,
  parseInspectorRef,
  replaceEvidenceInspector,
  type EvidenceInspectorRef,
} from '../../lib/evidence-inspector.mjs';
import { loadNavState, navScopeKey, saveNavState, type NavListState } from '../../lib/nav-state.mjs';
import { sessionIdentity } from '../../lib/api';
import { createActivityReaderKey } from '../../lib/recorded-activity.mjs';
import type { PortalConfig, Session } from '../../lib/types';

/** Same-principal credential rotation invalidates reads without exposing tokens in keys/URLs. */
export function useInspectorScopeKey(config: PortalConfig, session: Session) {
  const keyFor = useRef(createActivityReaderKey());
  return keyFor.current({ identity: sessionIdentity(session), authMode: config.authMode, session, id: 'inspector' });
}

/** The sanitized address, not mount-local state, owns the assessment's display selection. */
export function useScanDisplaySelection(reference: EvidenceInspectorRef) {
  const follow = reference.display_mode !== 'pinned';
  const select = useCallback((runId?: string) => {
    // Ignore a stale control if navigation selected a different execution in the meantime.
    const current = parseInspectorRef(window.location.hash);
    if (current?.entry !== 'validation_scan' || current.scan_id !== reference.scan_id || current.target_id !== reference.target_id) return;
    replaceEvidenceInspector({ entry: 'validation_scan', scan_id: current.scan_id, target_id: current.target_id,
      display_mode: runId ? 'pinned' : 'follow', ...(runId ? { pinned_run_id: runId } : {}) });
  }, [reference.scan_id, reference.target_id]);
  return { follow, pinnedChild: reference.pinned_run_id || '', select };
}

/** The ref currently open in the shared inspector, kept in sync with the address. */
export function useInspectorRef(): EvidenceInspectorRef | null {
  const [ref, setRef] = useState<EvidenceInspectorRef | null>(() => parseInspectorRef(window.location.hash));
  useEffect(() => {
    const sync = () => {
      const next = parseInspectorRef(window.location.hash);
      setRef((current) => (inspectorRefKey(current) === inspectorRefKey(next) ? current : next));
    };
    window.addEventListener('popstate', sync);
    window.addEventListener('hashchange', sync);
    window.addEventListener(EVIDENCE_INSPECTOR_EVENT, sync);
    return () => {
      window.removeEventListener('popstate', sync);
      window.removeEventListener('hashchange', sync);
      window.removeEventListener(EVIDENCE_INSPECTOR_EVENT, sync);
    };
  }, []);
  return ref;
}

/** Open the inspector and remember which row triggered it, so Close returns focus there. */
export function useOpenInspector() {
  return useCallback((ref: EvidenceInspectorRef, focusKey?: string) => openEvidenceInspector(ref, { focusKey }), []);
}

/**
 * Restore and persist allowlisted list state (filters, sort, page, selection, scroll) for one
 * route, scoped to tenant/user/role. `initial` is read once; `save` merges and stores.
 */
export function useListReturnState(session: Session, route: string) {
  const scope = navScopeKey(session);
  const initialRef = useRef<NavListState | null>(null);
  if (initialRef.current === null) initialRef.current = loadNavState(scope, route) ?? {};
  const latest = useRef<NavListState>(initialRef.current);

  const save = useCallback((patch: NavListState) => {
    latest.current = { ...latest.current, ...patch };
    saveNavState(scope, route, latest.current);
  }, [scope, route]);

  useEffect(() => {
    const persistScroll = () => saveNavState(scope, route, { ...latest.current, scrollTop: Math.round(window.scrollY) });
    window.addEventListener('pagehide', persistScroll);
    return () => {
      persistScroll();
      window.removeEventListener('pagehide', persistScroll);
    };
  }, [scope, route]);

  return { initial: initialRef.current, save };
}

/** Restore scroll and focus once, after the list has real rows. */
export function useRestoreListPosition(ready: boolean, state: NavListState) {
  const done = useRef(false);
  useLayoutEffect(() => {
    if (done.current || !ready) return;
    done.current = true;
    if (typeof state.scrollTop === 'number' && state.scrollTop > 0) window.scrollTo({ top: state.scrollTop });
    if (state.focusKey && !parseInspectorRef(window.location.hash)) {
      const node = document.querySelector<HTMLElement>(`[data-focus-key="${CSS.escape(state.focusKey)}"]`);
      node?.focus({ preventScroll: true });
    }
  }, [ready, state]);
}
