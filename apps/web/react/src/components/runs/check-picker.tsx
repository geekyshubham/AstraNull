import { useEffect, useId, useMemo, useRef, useState } from 'react';
import { Search, ShieldOff } from 'lucide-react';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import type { DataItem } from '../../lib/types';
import {
  checkProbeSummary,
  checkTargetCoverage,
  filterChecks,
  groupChecksBySection,
  selectableChecks,
  type CheckSection,
} from '../../lib/check-picker.mjs';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function humanize(value: string) {
  return value.replaceAll('_', ' ').replace(/\b\w/g, (character) => character.toUpperCase());
}

export type CheckPickerProps = {
  checks: DataItem[];
  selectedIds: string[];
  onChange: (ids: string[]) => void;
  targets: DataItem[];
  scope: 'targets' | 'target';
  targetId?: string;
  disabled?: boolean;
  maxSelected: number;
};

type RowState = {
  check: DataItem;
  id: string;
  enabled: boolean;
  compatText: string;
};

function SectionSelectAll({
  section,
  rows,
  selected,
  disabled,
  onToggle
}: {
  section: CheckSection;
  rows: RowState[];
  selected: Set<string>;
  disabled: boolean;
  onToggle: (ids: string[], checked: boolean) => void;
}) {
  const ref = useRef<HTMLInputElement>(null);
  const enabledIds = rows.filter((row) => row.enabled).map((row) => row.id);
  const selectedCount = enabledIds.filter((id) => selected.has(id)).length;
  const allSelected = enabledIds.length > 0 && selectedCount === enabledIds.length;
  const partiallySelected = selectedCount > 0 && !allSelected;

  useEffect(() => {
    if (ref.current) ref.current.indeterminate = partiallySelected;
  }, [partiallySelected]);

  return (
    <label className="check-picker-select-all">
      <input
        ref={ref}
        type="checkbox"
        checked={allSelected}
        disabled={disabled || enabledIds.length === 0}
        onChange={(event) => onToggle(enabledIds, event.target.checked)}
        aria-label={`Select all ${enabledIds.length} applicable checks in ${section.label}`}
      />
      <span>Select all</span>
    </label>
  );
}

export function CheckPicker({
  checks,
  selectedIds,
  onChange,
  targets,
  scope,
  targetId = '',
  disabled = false,
  maxSelected
}: CheckPickerProps) {
  const baseId = useId();
  const [query, setQuery] = useState('');
  const selected = useMemo(() => new Set(selectedIds), [selectedIds]);
  const { checks: eligible, excluded } = useMemo(() => selectableChecks(checks), [checks]);
  const visible = useMemo(() => filterChecks(eligible, query), [eligible, query]);
  const sections = useMemo(() => groupChecksBySection(visible), [visible]);
  const scopedTargets = useMemo(
    () => (scope === 'target' && targetId ? targets.filter((target) => getString(target, ['id']) === targetId) : targets),
    [targets, scope, targetId]
  );
  const scopeReady = scope === 'targets' ? targets.length > 0 : Boolean(targetId);
  const limitReached = selectedIds.length >= maxSelected;

  function rowState(check: DataItem): RowState {
    const id = getString(check, ['check_id']);
    const coverage = checkTargetCoverage(check, scopedTargets);
    const supportedKinds = Array.isArray(check.supported_targets) ? check.supported_targets.map(String) : [];
    if (!scopeReady) {
      return { check, id, enabled: false, compatText: 'Choose an exact target first' };
    }
    if (scopedTargets.length === 0) {
      return { check, id, enabled: false, compatText: 'No active domains are selected' };
    }
    if (coverage.supported === 0) {
      return {
        check,
        id,
        enabled: false,
        compatText: scope === 'target'
          ? `Not applicable to this target kind (supports ${supportedKinds.join(', ') || 'no declared kind'})`
          : `Applies to 0 of ${coverage.total} targets`
      };
    }
    return {
      check,
      id,
      enabled: true,
      compatText: scope === 'target' ? 'Applies to the selected target' : `Applies to ${coverage.supported} of ${coverage.total} targets`
    };
  }

  function toggleMany(ids: string[], checked: boolean) {
    if (checked) {
      const next = [...selectedIds];
      for (const id of ids) {
        if (next.length >= maxSelected) break;
        if (!next.includes(id)) next.push(id);
      }
      onChange(next);
      return;
    }
    const remove = new Set(ids);
    onChange(selectedIds.filter((id) => !remove.has(id)));
  }

  const totalVisible = visible.length;

  return (
    <div className="check-picker" aria-busy={disabled || undefined}>
      <div className="check-picker-toolbar">
        <label className="check-picker-search">
          <span className="sr-only">Search checks</span>
          <Search size={15} aria-hidden="true" />
          <input
            type="search"
            value={query}
            disabled={disabled}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search by name, check id, section, or probe kind"
          />
        </label>
        <span className="check-picker-results muted" role="status">
          {totalVisible} of {eligible.length} selectable checks shown
        </span>
        <span className="check-picker-selected" aria-live="polite">
          {selectedIds.length} of {maxSelected} selected
        </span>
        <Button type="button" size="sm" variant="ghost" disabled={disabled || selectedIds.length === 0} onClick={() => onChange([])}>
          Clear selection
        </Button>
      </div>
      <p className="check-picker-note" role="note">
        <ShieldOff size={14} aria-hidden="true" />
        <span>
          SOC-gated and monitor-only checks cannot be started here.
          {excluded.total > 0 ? ` ${excluded.total} catalog ${excluded.total === 1 ? 'entry is' : 'entries are'} hidden for that reason.` : ''}
        </span>
      </p>
      {limitReached ? (
        <p className="form-banner neutral" role="status">Selection limit reached. Remove a check to add another.</p>
      ) : null}
      {sections.length === 0 ? (
        <p className="muted small check-picker-empty">No selectable checks match this search.</p>
      ) : null}
      {sections.map((section) => {
        const rows = section.checks.map(rowState);
        const selectedInSection = rows.filter((row) => selected.has(row.id)).length;
        return (
          <fieldset key={section.id} className="check-picker-section" disabled={disabled}>
            <legend>
              <span className="check-picker-section-label">{section.label}</span>
              <span className="muted small">{selectedInSection} of {rows.length} selected</span>
            </legend>
            <SectionSelectAll section={section} rows={rows} selected={selected} disabled={disabled} onToggle={toggleMany} />
            <ul className="check-picker-list">
              {rows.map((row) => {
                const checked = selected.has(row.id);
                const probe = checkProbeSummary(row.check);
                const reasonId = `${baseId}-${row.id.replace(/[^a-zA-Z0-9_-]/g, '-')}-reason`;
                const tier = getString(row.check, ['evidence_tier']);
                const rowDisabled = disabled || (!row.enabled && !checked) || (!checked && limitReached);
                return (
                  <li key={row.id} className={`check-picker-row${rowDisabled ? ' is-disabled' : ''}${checked ? ' is-checked' : ''}`}>
                    <label className="check-picker-row-main">
                      <input
                        type="checkbox"
                        checked={checked}
                        disabled={rowDisabled}
                        aria-describedby={reasonId}
                        onChange={(event) => toggleMany([row.id], event.target.checked)}
                      />
                      <span className="check-picker-row-copy">
                        <span className="check-picker-row-title">
                          <strong>{getString(row.check, ['name'], row.id)}</strong>
                          {tier ? <Badge tone="muted" mono>{tier}</Badge> : null}
                        </span>
                        <code className="check-picker-row-id">{row.id}</code>
                      </span>
                    </label>
                    <span className="check-picker-row-meta">
                      <span className="muted small">
                        {probe.kind ? humanize(probe.kind) : 'Probe kind not recorded'}
                        {probe.maxRequests !== null ? ` · max ${probe.maxRequests} request${probe.maxRequests === 1 ? '' : 's'}` : ' · request bound not recorded'}
                      </span>
                      <span id={reasonId} className={`small ${row.enabled ? 'muted' : 'check-picker-incompatible'}`}>{row.compatText}</span>
                    </span>
                  </li>
                );
              })}
            </ul>
          </fieldset>
        );
      })}
    </div>
  );
}
