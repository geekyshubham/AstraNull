import { useId, useMemo, useState } from 'react';
import { Search } from 'lucide-react';
import type { DataItem } from '../../lib/types';
import { subdomainParentMap } from '../../lib/subdomain-grouping';
import { Button } from '../ui/button';

const MAX_SELECTED = 500;

type Row = { target: DataItem; id: string; depth: number };

function orderedRows(targets: DataItem[]): Row[] {
  const parents = subdomainParentMap(targets);
  const byParent = new Map<string, DataItem[]>();
  const roots: DataItem[] = [];
  for (const target of targets) {
    const parent = parents.get(String(target.id));
    if (parent) byParent.set(parent, [...(byParent.get(parent) ?? []), target]);
    else roots.push(target);
  }
  const byName = (left: DataItem, right: DataItem) => String(left.value ?? '').localeCompare(String(right.value ?? ''));
  const rows: Row[] = [];
  const walk = (target: DataItem, depth: number) => {
    const id = String(target.id);
    rows.push({ target, id, depth });
    for (const child of [...(byParent.get(id) ?? [])].sort(byName)) walk(child, Math.min(depth + 1, 3));
  };
  roots.sort(byName).forEach((target) => walk(target, 0));
  return rows;
}

/** Explicit selection of declared domains/endpoints. Selection never starts a check. */
export function DomainPicker({ targets, selectedIds, onChange, disabled = false, loading = false, label = 'Domains', incompatibleReason }: {
  targets: DataItem[];
  selectedIds: string[];
  onChange: (ids: string[]) => void;
  disabled?: boolean;
  loading?: boolean;
  label?: string;
  /** Reason a domain cannot be bound (for example the chosen check does not support it); empty when it can. */
  incompatibleReason?: (target: DataItem) => string;
}) {
  const id = useId();
  const [query, setQuery] = useState('');
  const active = useMemo(() => targets.filter((target) => !target.deleted_at && !target.archived_at), [targets]);
  const rows = useMemo(() => orderedRows(active), [active]);
  const known = new Set(active.map((target) => String(target.id)));
  const selected = new Set(selectedIds);
  const missing = selectedIds.filter((value) => !known.has(value));
  const needle = query.trim().toLowerCase();
  const visible = needle
    ? rows.filter((row) => `${row.target.value ?? ''} ${row.target.kind ?? ''}`.toLowerCase().includes(needle)).map((row) => ({ ...row, depth: 0 }))
    : rows;
  const reasonFor = (target: DataItem) => incompatibleReason?.(target) ?? '';
  const selectable = visible.filter((row) => !reasonFor(row.target));
  const allVisibleSelected = selectable.length > 0 && selectable.every((row) => selected.has(row.id));
  const toggle = (value: string, checked: boolean) => onChange(checked ? [...selectedIds, value] : selectedIds.filter((candidate) => candidate !== value));
  const selectVisible = () => onChange([...new Set([...selectedIds, ...selectable.map((row) => row.id)])].slice(0, MAX_SELECTED));
  const clearVisible = () => {
    const shown = new Set(visible.map((row) => row.id));
    onChange(selectedIds.filter((value) => !shown.has(value)));
  };

  return (
    <div className="domain-picker full" role="group" aria-labelledby={`${id}-label`} aria-busy={loading || undefined}>
      <div className="domain-picker-head">
        <span className="domain-picker-label" id={`${id}-label`}>{label}</span>
        <span className="domain-picker-count" aria-live="polite">{selectedIds.length} selected</span>
      </div>
      <div className="domain-picker-tools">
        <label className="domain-picker-search" htmlFor={id}>
          <Search size={15} aria-hidden="true" />
          <span className="sr-only">Search declared domains</span>
          <input id={id} type="search" value={query} disabled={disabled} onChange={(event) => setQuery(event.target.value)} placeholder="Search domains or endpoints" autoComplete="off" />
        </label>
        {visible.length ? (
          <Button type="button" size="sm" variant="ghost" disabled={disabled || loading || (!allVisibleSelected && selectable.length === 0)} onClick={allVisibleSelected ? clearVisible : selectVisible}>
            {allVisibleSelected ? 'Clear' : needle ? 'Select matches' : incompatibleReason ? 'Select all compatible' : 'Select all'}
          </Button>
        ) : null}
      </div>
      {loading ? <p className="domain-picker-note" role="status">Loading declared domains…</p> : null}
      {!loading && active.length === 0 ? <p className="domain-picker-note">No domains have been declared. Add a target first.</p> : null}
      {!loading && active.length > 0 && visible.length === 0 ? <p className="domain-picker-note">No declared domains match this search.</p> : null}
      {visible.length ? (
        <ul className="domain-picker-options">
          {visible.map((row) => {
            const reason = reasonFor(row.target);
            const checked = selected.has(row.id);
            const blocked = disabled || loading || (!checked && (Boolean(reason) || selectedIds.length >= MAX_SELECTED));
            return (
              <li key={row.id}>
                <label className="domain-picker-option" data-depth={row.depth} data-incompatible={reason ? 'true' : undefined}>
                  <input type="checkbox" checked={checked} disabled={blocked} onChange={(event) => toggle(row.id, event.target.checked)} />
                  <span className="domain-picker-text">
                    <strong>{String(row.target.value ?? 'Declared endpoint')}</strong>
                    <small>{reason || String(row.target.kind ?? 'target').replaceAll('_', ' ')}</small>
                  </span>
                </label>
              </li>
            );
          })}
        </ul>
      ) : null}
      {missing.length ? (
        <p className="form-error domain-picker-note" role="alert">
          {missing.length} selected domain{missing.length === 1 ? ' is' : 's are'} no longer available.{' '}
          <Button size="sm" variant="secondary" onClick={() => onChange(selectedIds.filter((value) => known.has(value)))}>Remove unavailable selections</Button>
        </p>
      ) : null}
    </div>
  );
}
