import { useId, useMemo, useState } from 'react';
import type { DataItem } from '../../lib/types';
import { Button } from '../ui/button';

/** Explicit selection of declared domains/endpoints. Selection never starts a check. */
export function DomainPicker({ targets, selectedIds, onChange, disabled = false, loading = false, label = 'Select domains' }: {
  targets: DataItem[];
  selectedIds: string[];
  onChange: (ids: string[]) => void;
  disabled?: boolean;
  loading?: boolean;
  label?: string;
}) {
  const id = useId();
  const [query, setQuery] = useState('');
  const active = useMemo(() => targets.filter((target) => !target.deleted_at && !target.archived_at), [targets]);
  const known = new Set(active.map((target) => String(target.id)));
  const selected = new Set(selectedIds);
  const missing = selectedIds.filter((value) => !known.has(value));
  const visible = active.filter((target) => `${target.value ?? ''} ${target.kind ?? ''}`.toLowerCase().includes(query.trim().toLowerCase()));
  return <fieldset className="domain-picker full" disabled={disabled} aria-busy={loading || undefined}>
    <legend>{label}</legend>
    <label className="domain-picker-search" htmlFor={id}><span>Search declared domains</span><input id={id} type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search domains or endpoints" /></label>
    <p className="muted small">{selectedIds.length} selected. Only these declared domains will be assessed.</p>
    {loading ? <p role="status">Loading declared domains…</p> : null}
    {!loading && active.length === 0 ? <p>No domains have been declared. Add a target first.</p> : null}
    {!loading && active.length > 0 && visible.length === 0 ? <p>No declared domains match this search.</p> : null}
    <div className="domain-picker-options">{visible.map((target) => {
      const value = String(target.id);
      return <label className="domain-picker-option" key={value}>
        <input type="checkbox" checked={selected.has(value)} disabled={loading || (!selected.has(value) && selectedIds.length >= 500)} onChange={(event) => onChange(event.target.checked ? [...selectedIds, value] : selectedIds.filter((candidate) => candidate !== value))} />
        <span><strong>{String(target.value ?? 'Declared endpoint')}</strong><small>{String(target.kind ?? 'target').replaceAll('_', ' ')}</small></span>
      </label>;
    })}</div>
    {missing.length ? <p className="form-error" role="alert">{missing.length} selected domain{missing.length === 1 ? ' is' : 's are'} no longer available. <Button size="sm" variant="secondary" onClick={() => onChange(selectedIds.filter((value) => known.has(value)))}>Remove unavailable selections</Button></p> : null}
  </fieldset>;
}
