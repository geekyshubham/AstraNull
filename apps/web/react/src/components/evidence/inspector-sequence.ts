import { useEffect, useSyncExternalStore } from 'react';
import { inspectorRefKey, type EvidenceInspectorRef } from '../../lib/evidence-inspector.mjs';

export type InspectorSequenceItem = { ref: EvidenceInspectorRef; label: string };
export type InspectorSequence = { owner: string; noun: string; items: InspectorSequenceItem[] };

let current: InspectorSequence | null = null;
const listeners = new Set<() => void>();

function emit() {
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function snapshot() {
  return current;
}

/**
 * A page publishes the ordered records the inspector may step through (for example the members
 * of one finding group under the active filter). Cleared when the page unmounts.
 */
export function usePublishInspectorSequence(sequence: InspectorSequence | null) {
  const signature = sequence ? `${sequence.owner}|${sequence.items.map((item) => inspectorRefKey(item.ref)).join(',')}` : '';
  useEffect(() => {
    current = sequence;
    emit();
    return () => {
      if (current && sequence && current.owner === sequence.owner) {
        current = null;
        emit();
      }
    };
    // signature captures the sequence identity and order.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [signature]);
}

export function useInspectorSequence() {
  return useSyncExternalStore(subscribe, snapshot, snapshot);
}

/** Position of `ref` in the sequence, with bounded neighbours (no wrap-around). */
export function sequencePosition(sequence: InspectorSequence | null, ref: EvidenceInspectorRef | null) {
  if (!sequence || !ref) return null;
  const key = inspectorRefKey(ref);
  const index = sequence.items.findIndex((item) => inspectorRefKey(item.ref) === key);
  if (index < 0) return null;
  return {
    index,
    total: sequence.items.length,
    previous: index > 0 ? sequence.items[index - 1] : null,
    next: index < sequence.items.length - 1 ? sequence.items[index + 1] : null,
    current: sequence.items[index],
    noun: sequence.noun,
  };
}
