import { useEffect, useId, useMemo, useState, type FormEvent } from 'react';
import { CalendarClock } from 'lucide-react';
import { requestJson } from '../../lib/api';
import { ConfirmModal, FormModal } from '../../lib/crud-ui';
import { apiErrorMessage } from '../../lib/error-messages';
import type { DataItem, PortalConfig, Session } from '../../lib/types';
import { formatDate } from '../../lib/utils';
import { selectableChecks, summarizeSelection } from '../../lib/check-picker.mjs';
import {
  MAX_SCAN_CHECKS,
  SCAN_RECURRENCE_CADENCES,
  buildScanPatch,
  buildScanPayload,
  emptyScanForm,
  localDatetimeToIso,
  minScheduleLocalValue,
  recurrenceLabel,
  scanErrorMessage,
  scanFormFromScan,
  validateScanForm,
  type ScanForm,
} from '../../lib/validation-scan.mjs';
import { Select, type SelectOption } from '../ui/select';
import { Button } from '../ui/button';
import { CheckPicker } from './check-picker';
import { DomainPicker } from '../targets/domain-picker';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function itemArray(value: unknown) {
  return Array.isArray(value) ? value as DataItem[] : [];
}

function humanize(value: string) {
  return value.replaceAll('_', ' ').replace(/\b\w/g, (character) => character.toUpperCase());
}

function activeTargets(items: DataItem[]) {
  return items.filter((target) => target.deleted_at == null && target.archived_at == null);
}

function targetLabel(target: DataItem) {
  const value = getString(target, ['value', 'hostname', 'id'], 'Unnamed target');
  return `${value} · ${humanize(getString(target, ['kind'], 'target'))}`;
}

export type ScanLauncherMode = 'create' | 'edit' | 'reschedule';

export type ValidationScanLauncherProps = {
  open: boolean;
  mode: ScanLauncherMode;
  scan?: DataItem | null;
  config: PortalConfig;
  session: Session;
  checks: DataItem[];
  targets?: DataItem[];
  initialTargets?: DataItem[];
  onClose: () => void;
  onScheduled: (scan: DataItem, mode: ScanLauncherMode) => void;
  onStarted?: (scan: DataItem) => void;
};

function initialForm(mode: ScanLauncherMode, scan: DataItem | null | undefined): ScanForm {
  if ((mode === 'edit' || mode === 'reschedule') && scan) return scanFormFromScan(scan, mode);
  return emptyScanForm();
}

export function ValidationScanLauncher({
  open,
  mode,
  scan = null,
  config,
  session,
  checks,
  targets: declaredTargets,
  initialTargets,
  onClose,
  onScheduled,
  onStarted
}: ValidationScanLauncherProps) {
  const [form, setForm] = useState<ScanForm>(() => initialForm(mode, scan));
  const [targets, setTargets] = useState<DataItem[]>(initialTargets ? activeTargets(initialTargets) : []);
  const [targetsLoading, setTargetsLoading] = useState(false);
  const [targetsError, setTargetsError] = useState('');
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState('');
  const [reviewing, setReviewing] = useState(false);
  const [busy, setBusy] = useState(false);
  const ids = {
    name: useId(),
    scheduledFor: useId(),
    timezone: useId(),
    scopeHelp: useId(),
    scheduleHelp: useId()
  };

  useEffect(() => {
    if (!open) return;
    setForm(initialForm(mode, scan));
    setFieldErrors({});
    setError('');
    setReviewing(false);
    setBusy(false);
  }, [open, mode, scan]);

  useEffect(() => {
    if (!open) return undefined;
    if (initialTargets || declaredTargets) {
      setTargets(activeTargets(initialTargets ?? declaredTargets ?? [])); setTargetsError(''); setTargetsLoading(false);
      return undefined;
    }
    let cancelled = false;
    setTargetsLoading(true); setTargetsError('');
    void requestJson(config, session, '/v1/targets').then((payload) => {
      if (!cancelled) setTargets(activeTargets(itemArray((payload as DataItem).items)));
    }).catch((err) => { if (!cancelled) setTargetsError(apiErrorMessage(err, 'Declared domains could not be loaded.')); })
      .finally(() => { if (!cancelled) setTargetsLoading(false); });
    return () => { cancelled = true; };
  }, [open, config, session, declaredTargets, initialTargets]);

  const recurrenceOptions: SelectOption[] = [
    { value: 'none', label: 'Does not repeat' },
    ...SCAN_RECURRENCE_CADENCES.map((cadence) => ({ value: cadence, label: humanize(cadence) }))
  ];
  const eligibleChecks = useMemo(() => selectableChecks(checks).checks, [checks]);
  const selectedTargets = useMemo(() => targets.filter((target) => form.targetIds.includes(getString(target, ['id']))), [targets, form.targetIds]);
  const summary = useMemo(() => summarizeSelection({
    checks: eligibleChecks,
    selectedIds: form.checkIds,
    targets: selectedTargets,
  }), [eligibleChecks, form.checkIds, selectedTargets]);
  const selectedChecks = eligibleChecks.filter((check) => form.checkIds.includes(getString(check, ['check_id'])));
  const editing = mode === 'edit';
  const title = editing ? 'Edit scheduled scan' : mode === 'reschedule' ? 'Schedule this scan again' : 'Start validation scan';
  const scheduleLocked = editing || mode === 'reschedule';

  function update(patch: Partial<ScanForm>) {
    setForm((current) => ({ ...current, ...patch }));
    setFieldErrors({});
    setError('');
  }

  function review(event: FormEvent) {
    event.preventDefault();
    const nextForm = form;
    const validation = validateScanForm(nextForm);
    if (!validation.ok) {
      setFieldErrors(validation.errors);
      return;
    }
    if (selectedTargets.length !== form.targetIds.length) { setFieldErrors({ target_ids: 'Remove unavailable domains before reviewing this assessment.' }); return; }
    if (summary.stepCount === 0) {
      setFieldErrors({ check_ids: 'None of the selected checks apply to the targets in this scope.' });
      return;
    }
    setForm(nextForm);
    setReviewing(true);
  }

  async function submit() {
    setBusy(true);
    setError('');
    try {
      let result: DataItem;
      if (editing && scan) {
        const patch = buildScanPatch(scan, form);
        if (Object.keys(patch).length === 0) {
          setReviewing(false);
          onClose();
          return;
        }
        result = await requestJson(config, session, `/v1/validation-scans/${encodeURIComponent(getString(scan, ['id']))}`, {
          method: 'PATCH',
          body: patch
        }) as DataItem;
        setReviewing(false);
        onScheduled(result, mode);
        return;
      }
      result = await requestJson(config, session, '/v1/validation-scans', { method: 'POST', body: buildScanPayload(form) }) as DataItem;
      setReviewing(false);
      if (getString(result, ['status']) === 'scheduled') {
        onScheduled(result, mode);
        return;
      }
      if (onStarted) onStarted(result);
      else window.location.hash = `#scan-detail?id=${encodeURIComponent(getString(result, ['id']))}`;
    } catch (err) {
      const payload = (err as { payload?: unknown }).payload;
      setReviewing(false);
      setError(scanErrorMessage(payload, apiErrorMessage(err, 'The scan could not be submitted.')));
    } finally {
      setBusy(false);
    }
  }

  const scheduledIso = form.schedule === 'later' ? localDatetimeToIso(form.scheduledForLocal) : '';
  const firstNames = selectedChecks.slice(0, 5).map((check) => getString(check, ['name', 'check_id']));
  const moreCount = Math.max(0, selectedChecks.length - firstNames.length);

  return (
    <>
      <FormModal
        open={open}
        title={title}
        description="Choose the scope, select bounded checks, and optionally schedule. Every step is a bounded child run under the same safety gates as a single run."
        onClose={onClose}
        wide
      >
        <form className="product-form scan-launcher" onSubmit={review} aria-busy={busy || undefined}>
          {error ? <div className="form-banner error full" role="alert">{error}</div> : null}
          <DomainPicker targets={targets} selectedIds={form.targetIds} onChange={(targetIds) => update({ targetIds })} disabled={busy} loading={targetsLoading} />
          <p id={ids.scopeHelp} className="muted small full">Choose one or more declared domains directly. Only selected domains are planned; incompatible check/target pairs are recorded and excluded.</p>
          {fieldErrors.target_ids ? <p className="form-error full" role="alert">{fieldErrors.target_ids}</p> : null}
          {targetsError ? <p className="form-error full" role="alert">{targetsError}</p> : null}
          <fieldset className="scan-launcher-checks">
            <legend>Checks</legend>
            <div className="full">
              <CheckPicker
                checks={checks}
                selectedIds={form.checkIds}
                onChange={(next) => update({ checkIds: next })}
                targets={selectedTargets}
                scope="targets"
                disabled={busy || !form.targetIds.length}
                maxSelected={MAX_SCAN_CHECKS}
              />
            </div>
            {fieldErrors.check_ids ? <p className="form-error full" role="alert">{fieldErrors.check_ids}</p> : null}
            <p className="scan-launcher-summary full" role="status" aria-live="polite">
              {summary.selectedCount} check{summary.selectedCount === 1 ? '' : 's'} selected · {summary.stepCount} planned step{summary.stepCount === 1 ? '' : 's'}
              {summary.requestUpperBound !== null ? ` · at most ${summary.requestUpperBound} probe request${summary.requestUpperBound === 1 ? '' : 's'}` : ' · request bound not recorded for every check'}
              {summary.incompatible.length > 0 ? ` · ${summary.incompatible.length} selected check${summary.incompatible.length === 1 ? '' : 's'} will be recorded as incompatible` : ''}
            </p>
          </fieldset>

          <fieldset className="scan-launcher-schedule">
            <legend>Name and schedule</legend>
            <label>
              <span>Scan name (optional)</span>
              <input id={ids.name} value={form.name} disabled={busy} onChange={(event) => update({ name: event.target.value })} placeholder="Defaults to the scan id" autoComplete="off" />
            </label>
            {fieldErrors.name ? <p className="form-error full" role="alert">{fieldErrors.name}</p> : null}
            <div className="scan-launcher-radios full" role="radiogroup" aria-label="When to run" aria-describedby={ids.scheduleHelp}>
              <label className="check-row">
                <input type="radio" name="scan-schedule" value="now" checked={form.schedule === 'now'} disabled={busy || scheduleLocked} onChange={() => update({ schedule: 'now', recurrence: 'none' })} />
                <span>Run now</span>
              </label>
              <label className="check-row">
                <input type="radio" name="scan-schedule" value="later" checked={form.schedule === 'later'} disabled={busy} onChange={() => update({ schedule: 'later' })} />
                <span>Schedule for later</span>
              </label>
            </div>
            <p id={ids.scheduleHelp} className="muted small full">Scheduled scans dispatch at the chosen time and still pass ownership, safe-window, concurrency, and kill-switch gates at dispatch.</p>
            {form.schedule === 'later' ? (
              <>
                <label>
                  <span>Scheduled for</span>
                  <input
                    id={ids.scheduledFor}
                    type="datetime-local"
                    value={form.scheduledForLocal}
                    min={minScheduleLocalValue()}
                    disabled={busy}
                    required
                    onChange={(event) => update({ scheduledForLocal: event.target.value })}
                  />
                </label>
                <Select label="Repeat" value={form.recurrence} options={recurrenceOptions} disabled={busy} onChange={(value) => update({ recurrence: value })} />
                {form.recurrence !== 'none' ? (
                  <label>
                    <span>Recurrence timezone (IANA, optional)</span>
                    <input id={ids.timezone} value={form.timezone} disabled={busy} onChange={(event) => update({ timezone: event.target.value })} placeholder="Server default when empty" autoComplete="off" spellCheck={false} />
                  </label>
                ) : null}
              </>
            ) : null}
            {fieldErrors.scheduled_for ? <p className="form-error full" role="alert">{fieldErrors.scheduled_for}</p> : null}
            {fieldErrors.recurrence ? <p className="form-error full" role="alert">{fieldErrors.recurrence}</p> : null}
          </fieldset>

          <div className="form-actions full">
            <Button type="button" variant="ghost" disabled={busy} onClick={onClose}>Cancel</Button>
            <Button type="submit" disabled={busy || !form.targetIds.length || form.checkIds.length === 0}>Review scan</Button>
          </div>
        </form>
      </FormModal>

      <ConfirmModal
        open={open && reviewing}
        title={editing ? 'Save these schedule changes?' : form.schedule === 'later' ? 'Schedule this validation scan?' : 'Start this validation scan now?'}
        description={(
          <div className="stack-tight scan-review">
            <p><strong>Domains:</strong> {selectedTargets.map(targetLabel).join(', ')}</p>
            <p>
              <strong>Checks:</strong> {summary.selectedCount} selected{firstNames.length ? ` (${firstNames.join(', ')}${moreCount > 0 ? `, and ${moreCount} more` : ''})` : ''}
            </p>
            <p><strong>Planned steps:</strong> {summary.stepCount}{summary.incompatible.length > 0 ? ` · ${summary.incompatible.length} incompatible pair${summary.incompatible.length === 1 ? '' : 's'} recorded` : ''}</p>
            <p><strong>Request upper bound:</strong> {summary.requestUpperBound !== null ? `${summary.requestUpperBound} probe request${summary.requestUpperBound === 1 ? '' : 's'} across all steps` : 'Not recorded for every selected check'}</p>
            <p><strong>Schedule:</strong> {form.schedule === 'later' ? `${formatDate(scheduledIso)} · ${recurrenceLabel(form.recurrence === 'none' ? null : { cadence: form.recurrence, timezone: form.timezone })}` : 'Runs immediately, one step at a time'}</p>
            {form.name.trim() ? <p><strong>Name:</strong> {form.name.trim()}</p> : null}
            <p className="muted small"><CalendarClock size={14} aria-hidden="true" /> Ownership, eligibility, safe windows, concurrency, and the tenant kill switch are checked again for every step.</p>
          </div>
        )}
        confirmLabel={editing ? 'Save changes' : form.schedule === 'later' ? 'Schedule scan' : 'Start scan'}
        confirmTone="default"
        busy={busy}
        onCancel={() => setReviewing(false)}
        onConfirm={() => void submit()}
      />
    </>
  );
}
