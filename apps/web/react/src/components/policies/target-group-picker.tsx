import { useEffect, useId, useRef, useState } from 'react';
import { ChevronDown, X } from 'lucide-react';
import type { DataItem } from '../../lib/types';

function getString(item: DataItem, keys: string[], fallback = '') {
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function getNumber(item: DataItem, keys: string[], fallback: number | null = null) {
  for (const key of keys) {
    const value = item[key];
    if (typeof value === 'number' && Number.isFinite(value)) return value;
  }
  return fallback;
}

const POLICY_TARGET_KIND_ALIASES: Readonly<Record<string, string>> = {
  domain: 'fqdn',
  hostname: 'fqdn',
};

/** Mirror the policy API: persisted aliases are canonical FQDNs and HTTP(S) values are URLs. */
export function effectivePolicyTargetKind(target: DataItem) {
  const value = getString(target, ['value'], '');
  if (/^https?:\/\//i.test(value)) return 'url';
  const kind = getString(target, ['kind'], '').trim().toLowerCase();
  return POLICY_TARGET_KIND_ALIASES[kind] ?? kind;
}

export function policySupportedTargetKinds(check: DataItem | null | undefined) {
  return Array.isArray(check?.supported_targets)
    ? check.supported_targets.map((value) => String(value).trim()).filter(Boolean)
    : [];
}

export function isPolicyTargetCompatible(check: DataItem | null | undefined, target: DataItem) {
  const supportedTargets = policySupportedTargetKinds(check);
  return supportedTargets.length === 0 || supportedTargets.includes(effectivePolicyTargetKind(target));
}

function TargetGroupChip({
  id,
  name,
  disabled,
  unavailable = false,
  onRemove,
}: {
  id: string;
  name: string;
  disabled: boolean;
  unavailable?: boolean;
  onRemove: (id: string) => void;
}) {
  const displayName = unavailable ? `${name} (unavailable)` : name;
  return (
    <span className="tg-chip">
      <span>{displayName}</span>
      <button
        type="button"
        className="tg-chip-remove"
        aria-label={`Remove ${displayName}`}
        disabled={disabled}
        onClick={() => onRemove(id)}
      >
        <X size={12} aria-hidden="true" />
      </button>
    </span>
  );
}

function TargetGroupOption({
  group,
  checked,
  disabled,
  onToggle,
}: {
  group: DataItem;
  checked: boolean;
  disabled: boolean;
  onToggle: (id: string) => void;
}) {
  const id = getString(group, ['id']);
  const name = getString(group, ['name', 'id'], 'Unnamed target group');
  const criticality = getString(group, ['criticality']);
  const targetCount = getNumber(group, ['target_count', 'targets_count']);
  const metadata = [
    criticality || null,
    targetCount === null ? null : `${targetCount} target${targetCount === 1 ? '' : 's'}`,
  ].filter(Boolean).join(' · ') || 'Group metadata unavailable';

  return (
    <div
      className="tg-picker-row"
      role="option"
      aria-selected={checked}
      aria-disabled={disabled || undefined}
      tabIndex={disabled ? -1 : 0}
      onClick={() => {
        if (!disabled) onToggle(id);
      }}
      onKeyDown={(event) => {
        if (disabled) return;
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          onToggle(id);
        }
      }}
    >
      <input
        type="checkbox"
        tabIndex={-1}
        checked={checked}
        readOnly
        aria-hidden="true"
        disabled={disabled}
      />
      <span className="tg-check-box" aria-hidden="true" />
      <span className="tg-name">{name}</span>
      <span className="tg-meta">{metadata}</span>
    </div>
  );
}

export type TargetGroupPickerProps = {
  groups: DataItem[];
  selectedIds: string[];
  onChange: (ids: string[]) => void;
  disabled?: boolean;
  label?: string;
};

export function TargetGroupPicker({
  groups,
  selectedIds,
  onChange,
  disabled = false,
  label = 'Target groups'
}: TargetGroupPickerProps) {
  const labelId = useId();
  const summaryId = useId();
  const helpId = useId();
  const menuId = useId();
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    function onPointerDown(event: MouseEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    }
    document.addEventListener('mousedown', onPointerDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
    };
  }, []);

  useEffect(() => {
    if (disabled) setOpen(false);
  }, [disabled]);

  function focusMenuOption(position: 'first' | 'last' = 'first') {
    window.requestAnimationFrame(() => {
      const options = menuRef.current?.querySelectorAll<HTMLElement>('[role="option"]:not([aria-disabled="true"])');
      if (!options?.length) return;
      options[position === 'first' ? 0 : options.length - 1]?.focus({ preventScroll: true });
    });
  }

  function openMenu(position: 'first' | 'last' = 'first') {
    if (disabled || groups.length === 0) return;
    setOpen(true);
    focusMenuOption(position);
  }

  function moveOptionFocus(event: React.KeyboardEvent<HTMLDivElement>) {
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
    const options = Array.from(
      menuRef.current?.querySelectorAll<HTMLElement>('[role="option"]:not([aria-disabled="true"])') ?? []
    );
    if (options.length === 0) return;
    event.preventDefault();
    const currentIndex = options.indexOf(document.activeElement as HTMLElement);
    if (event.key === 'Home') options[0]?.focus();
    else if (event.key === 'End') options[options.length - 1]?.focus();
    else if (event.key === 'ArrowDown') options[(currentIndex + 1 + options.length) % options.length]?.focus();
    else options[(currentIndex - 1 + options.length) % options.length]?.focus();
  }

  function toggleGroup(id: string) {
    if (selectedIds.includes(id)) {
      onChange(selectedIds.filter((value) => value !== id));
      return;
    }
    onChange([...selectedIds, id]);
  }

  function removeGroup(id: string) {
    onChange(selectedIds.filter((value) => value !== id));
  }

  const selectedGroups = selectedIds.map((id) => ({
    id,
    group: groups.find((group) => getString(group, ['id']) === id) ?? null,
  }));
  const selectionSummary = selectedIds.length === 0
    ? 'No target groups selected'
    : `${selectedIds.length} target group${selectedIds.length === 1 ? '' : 's'} selected`;

  return (
    <div className="tg-picker-field">
      <span className="data-label" id={labelId}>{label}</span>
      <div
        className="tg-picker"
        data-tg-picker
        ref={rootRef}
        onKeyDownCapture={(event) => {
          if (!open || event.key !== 'Escape') return;
          event.preventDefault();
          event.stopPropagation();
          setOpen(false);
          triggerRef.current?.focus({ preventScroll: true });
        }}
      >
        <button
          ref={triggerRef}
          type="button"
          className="tg-picker-trigger input"
          aria-haspopup="listbox"
          aria-expanded={open}
          aria-controls={menuId}
          aria-labelledby={`${labelId} ${summaryId}`}
          aria-describedby={helpId}
          disabled={disabled || groups.length === 0}
          onClick={() => setOpen((value) => !value)}
          onKeyDown={(event) => {
            if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
              event.preventDefault();
              openMenu(event.key === 'ArrowUp' ? 'last' : 'first');
            }
          }}
        >
          <span className="tg-picker-values">
            <span
              className={selectedIds.length === 0 ? 'tg-picker-placeholder' : 'text-sm'}
              id={summaryId}
            >
              {selectionSummary}
            </span>
          </span>
          <ChevronDown className="tg-picker-chevron" size={12} aria-hidden="true" />
        </button>
        <div
          ref={menuRef}
          className="tg-picker-menu"
          id={menuId}
          role="listbox"
          aria-labelledby={labelId}
          aria-describedby={helpId}
          aria-multiselectable="true"
          hidden={!open}
          onKeyDown={moveOptionFocus}
        >
          {groups.length > 0 ? groups.map((group) => {
            const id = getString(group, ['id']);
            const checked = selectedIds.includes(id);
            return (
              <TargetGroupOption
                key={id}
                group={group}
                checked={checked}
                disabled={disabled}
                onToggle={toggleGroup}
              />
            );
          }) : (
            <p className="muted small">No active target groups are available.</p>
          )}
        </div>
      </div>

      {selectedGroups.length > 0 ? (
        <div className="tg-picker-values" aria-label="Selected target groups">
          {selectedGroups.map(({ id, group }) => (
            <TargetGroupChip
              key={id}
              id={id}
              name={getString(group ?? {}, ['name', 'id'], id)}
              unavailable={!group}
              disabled={disabled}
              onRemove={removeGroup}
            />
          ))}
        </div>
      ) : null}

      <p className="muted small" id={helpId}>
        Select declared groups, then bind one exact compatible active target per group. AstraNull never assigns a target automatically.
      </p>
    </div>
  );
}
