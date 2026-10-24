import { useId, useMemo, useState } from 'react';
import { Lock, Search } from 'lucide-react';
import { CheckClassChips } from '../checks/check-class-chips';
import { Button } from '../ui/button';
import { formatNumber } from '../../lib/utils';
import {
  SOC_GOVERNED_LABEL,
  filterScheduleCheckEntries,
  scheduleCheckCategoryCounts,
  type ScheduleCheckEntry,
} from '../../lib/schedule-checks.mjs';

/** Every catalog check, searchable and filterable; checks the server would refuse stay visible but disabled. */
export function ScheduleCheckPicker({ entries, value, onChange, disabled = false }: {
  entries: ScheduleCheckEntry[];
  value: string;
  onChange: (checkId: string) => void;
  disabled?: boolean;
}) {
  const id = useId();
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('');
  const [browsing, setBrowsing] = useState(!value);
  const selected = entries.find((entry) => entry.id === value) ?? null;
  const categories = useMemo(() => scheduleCheckCategoryCounts(entries), [entries]);
  const visible = useMemo(() => filterScheduleCheckEntries(entries, { query, category }), [entries, query, category]);
  const gatedCount = entries.filter((entry) => !entry.selectable).length;
  const filtering = Boolean(query.trim() || category);
  const countText = filtering
    ? `${formatNumber(visible.length)} of ${formatNumber(entries.length)} checks match`
    : `${formatNumber(entries.length)} checks${gatedCount ? ` · ${formatNumber(gatedCount)} need setup` : ''}`;

  if (selected && !browsing) {
    return (
      <div className="rf-check-summary full">
        <div className="rf-check-summary-copy">
          <span className="rf-check-summary-label">Check</span>
          <strong>{selected.name}</strong>
          <code>{selected.id}</code>
          <CheckClassChips check={selected.check} />
        </div>
        <Button type="button" size="sm" variant="secondary" disabled={disabled} onClick={() => setBrowsing(true)}>Change</Button>
      </div>
    );
  }

  return (
    <div className="rf-check-picker full">
      <div className="rf-check-picker-tools">
        <label className="rf-check-search" htmlFor={`${id}-search`}>
          <Search size={15} aria-hidden="true" />
          <span className="sr-only">Find a check</span>
          <input
            id={`${id}-search`}
            type="search"
            value={query}
            disabled={disabled}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search by name or check ID"
            autoComplete="off"
            aria-describedby={`${id}-count`}
          />
        </label>
        <span className="rf-check-count" id={`${id}-count`} aria-live="polite">{countText}</span>
      </div>
      {categories.length > 2 ? (
        <div className="rf-check-categories" role="group" aria-label="Check category">
          {categories.map((entry) => (
            <button key={entry.id || 'all'} type="button" aria-pressed={category === entry.id} disabled={disabled} onClick={() => setCategory(entry.id)}>
              {entry.label}<span className="tabular-nums">{formatNumber(entry.count)}</span>
            </button>
          ))}
        </div>
      ) : null}
      <div className="rf-check-options" role="radiogroup" aria-label="Check">
        {visible.length ? visible.map((entry) => (
          <label key={entry.id} className="rf-check-option" data-gated={entry.selectable ? undefined : 'true'} title={entry.reason || undefined}>
            <input
              type="radio"
              name={`${id}-check`}
              value={entry.id}
              checked={entry.id === value}
              disabled={disabled || !entry.selectable}
              onChange={() => { onChange(entry.id); setBrowsing(false); }}
            />
            <span className="rf-check-option-copy">
              <strong>{entry.name}</strong>
              <code>{entry.id}</code>
            </span>
            {entry.selectable ? null : <span className="rf-check-gated"><Lock size={12} aria-hidden="true" />{SOC_GOVERNED_LABEL}</span>}
          </label>
        )) : <p className="rf-check-empty">No checks match. Clear the search or pick another category.</p>}
      </div>
      {selected ? <Button type="button" size="sm" variant="ghost" className="rf-check-cancel" onClick={() => setBrowsing(false)}>Keep {selected.name}</Button> : null}
    </div>
  );
}
