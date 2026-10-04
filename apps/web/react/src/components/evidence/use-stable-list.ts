import { useCallback, useMemo, useReducer, useRef, useState, type FocusEvent, type PointerEvent } from 'react';

const signatures = new WeakMap<object, string>();

/** Content identity of a list; a refetch that returns the same records is not an update. */
function signature<T>(items: T[]) {
  const cached = signatures.get(items);
  if (cached !== undefined) return cached;
  let value = '';
  try {
    value = JSON.stringify(items);
  } catch {
    value = String(Math.random());
  }
  signatures.set(items, value);
  return value;
}

export type StableListState<T> = {
  /** Rows currently displayed: the committed snapshot, never silently replaced while held. */
  items: T[];
  /** True when newer rows arrived for the same scope and are waiting for an explicit apply. */
  pending: boolean;
  added: number;
  removed: number;
  /** When the displayed snapshot was committed (ms since epoch). */
  committedAt: number;
  /** Show the newest rows now (an explicit user action). */
  apply: () => void;
};

/**
 * Hold a live list stable while the user is interacting with it. Newer rows for the same scope
 * do not move or remove the hovered, focused or inspected row; they wait behind an explicit
 * apply. A change of scope (tenant, user, role or route) replaces the snapshot immediately, so no
 * private rows from an earlier scope stay on screen.
 */
export function useStableList<T>(
  items: T[],
  { scope, idOf, hold }: { scope: string; idOf: (item: T) => string; hold: boolean },
): StableListState<T> {
  const committed = useRef<{ scope: string; items: T[]; at: number }>({ scope, items, at: Date.now() });
  const latest = useRef(items);
  latest.current = items;
  const [, rerender] = useReducer((count: number) => count + 1, 0);

  const held = useRef(false);
  if (committed.current.scope !== scope) {
    committed.current = { scope, items, at: Date.now() };
    held.current = false;
  } else if (items !== committed.current.items) {
    const sameContent = signature(items) === signature(committed.current.items);
    if (sameContent || committed.current.items.length === 0 || (!hold && !held.current)) {
      committed.current = { scope, items, at: Date.now() };
    } else {
      // Once an update has been held it stays behind the explicit apply, even after the pointer
      // leaves, so rows never jump out from under a returning pointer or a closing inspector.
      held.current = true;
    }
  }

  const shown = committed.current.items;
  const pending = shown !== items;
  const { added, removed } = useMemo(() => {
    if (!pending) return { added: 0, removed: 0 };
    const before = new Set(shown.map(idOf));
    const after = new Set(items.map(idOf));
    let addedCount = 0;
    let removedCount = 0;
    after.forEach((id) => { if (!before.has(id)) addedCount += 1; });
    before.forEach((id) => { if (!after.has(id)) removedCount += 1; });
    return { added: addedCount, removed: removedCount };
  }, [pending, shown, items, idOf]);

  const apply = useCallback(() => {
    held.current = false;
    if (committed.current.items === latest.current) return;
    committed.current = { scope: committed.current.scope, items: latest.current, at: Date.now() };
    rerender();
  }, []);

  return { items: shown, pending, added, removed, committedAt: committed.current.at, apply };
}

/**
 * Tracks whether the pointer is over, or keyboard focus is inside, a list region. Spread
 * `handlers` on the region's wrapper.
 */
export function useInteractionHold() {
  const [pointerInside, setPointerInside] = useState(false);
  const [focusInside, setFocusInside] = useState(false);
  const handlers = useMemo(() => ({
    onPointerEnter: (_event: PointerEvent<HTMLElement>) => setPointerInside(true),
    onPointerLeave: (_event: PointerEvent<HTMLElement>) => setPointerInside(false),
    onFocusCapture: (_event: FocusEvent<HTMLElement>) => setFocusInside(true),
    onBlurCapture: (event: FocusEvent<HTMLElement>) => {
      const next = event.relatedTarget as Node | null;
      if (!next || !event.currentTarget.contains(next)) setFocusInside(false);
    },
  }), []);
  return { holding: pointerInside || focusInside, handlers };
}
