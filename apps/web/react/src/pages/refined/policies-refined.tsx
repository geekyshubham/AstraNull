import { useEffect, useId, useMemo, useRef, useState, type FormEvent, type HTMLAttributes, type ReactNode } from 'react';
import {
  Archive,
  CalendarClock,
  CircleCheck,
  CircleDashed,
  ListFilter,
  Lock,
  Pause,
  Plus,
  ShieldCheck
} from 'lucide-react';
import {
  effectivePolicyTargetKind,
  isPolicyTargetCompatible,
  policySupportedTargetKinds,
  TargetGroupPicker
} from '../../components/policies/target-group-picker';
import { Badge } from '../../components/ui/badge';
import { Button } from '../../components/ui/button';
import { EmptyState } from '../../components/ui/empty-state';
import { Select, type SelectOption } from '../../components/ui/select';
import { DataTable, type TableColumn } from '../../components/ui/table';
import { VariantSwitch } from '../../components/ui/variant-switch';
import type { DesignVariant } from '../../lib/design-variant';
import type { DataItem, PortalConfig, PortalData, Session } from '../../lib/types';
import { formatDate, formatNumber } from '../../lib/utils';
import './policies-refined.css';

/** Mirrors PolicyPage's per-group exact-target binding state. */
export type RefinedPolicyTargetBinding = {
  targets: DataItem[];
  selectedTargetId: string;
  loading: boolean;
  error: string;
};

/**
 * The create-schedule form state and handlers, owned by PolicyPage. Refined renders the
 * form inline (progressive disclosure) instead of in a modal, but every value, validation
 * rule, and write path is the parent's.
 */
export interface PolicyCreateFormModel {
  /** Already gated on test_policy:write by the parent. */
  open: boolean;
  onClose: () => void;
  /** PolicyPage.handleCreatePolicy: validates, writes one policy per group, keeps failures for retry. */
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  /** Active (not archived, not deleted) target groups. */
  targetGroups: DataItem[];
  selectedGroupIds: string[];
  onTargetGroupsChange: (ids: string[]) => void;
  bindings: Record<string, RefinedPolicyTargetBinding>;
  onSelectTarget: (targetGroupId: string, targetId: string) => void;
  onRetryTargets: (targetGroupId: string) => void;
  bindingsReady: boolean;
  selectedCheck: DataItem | null;
  checkId: string;
  checkOptions: SelectOption[];
  onCheckChange: (checkId: string) => void;
  cadence: string;
  cadenceOptions: SelectOption[];
  onCadenceChange: (cadence: string) => void;
  expectedVerdict: string;
  verdictOptions: SelectOption[];
  onExpectedVerdictChange: (verdict: string) => void;
}

/**
 * Everything the Refined test-policies view needs. State, mutations, permission gates,
 * and modals stay owned by PolicyPage; this view only re-presents them.
 */
export interface PoliciesRefinedProps {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
  variant: DesignVariant;
  onVariantChange: (next: DesignVariant) => void;
  /** PolicyPage busy key: '' when idle, else e.g. 'create-test-policy' or `patch-policy-<id>`. */
  busy: string;
  message: string;
  error: string;
  /** test_policy:write. Gates Create schedule and the per-row actions inside policyColumns. */
  canWritePolicies: boolean;
  /** Same columns as classic, including the gated Actions column. Refined reuses their cell renders. */
  policyColumns: TableColumn<DataItem>[];
  activePolicies: DataItem[];
  safeChecks: DataItem[];
  socGatedChecks: DataItem[];
  socScheduledCount: number;
  boundPolicyCount: number;
  /** ISO timestamps of upcoming non-SOC runs, ascending. */
  upcomingRuns: string[];
  nextRunLabel: string;
  /** Row navigation to policy-detail plus aria-busy while that row mutates. */
  getPolicyRowProps: (item: DataItem) => Omit<HTMLAttributes<HTMLTableRowElement>, 'key'>;
  /** Same next-run derivation the classic Next run column uses. */
  getPolicyNextRun: (item: DataItem) => { label: string; iso: string | null; socGated: boolean };
  policyEmptyState: ReactNode;
  onCreateSchedule: () => void;
  /** Archive ConfirmModal, already wired to PolicyPage state. */
  modals: ReactNode;
  createForm: PolicyCreateFormModel;
}

type StateFilter = 'all' | 'active' | 'paused' | 'archived';

const STATE_FILTERS: Array<{ id: StateFilter; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'active', label: 'Active' },
  { id: 'paused', label: 'Paused' },
  { id: 'archived', label: 'Archived' }
];

function str(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function nested(item: DataItem, key: string): DataItem {
  const value = item[key];
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as DataItem) : {};
}

function rowId(item: DataItem) {
  return str(item, ['id', 'policy_id']);
}

/** Same buckets as PolicyPage.activePolicies: anything not paused, archived, or deleted is active. */
function policyStateBucket(item: DataItem): Exclude<StateFilter, 'all'> {
  const state = str(item, ['state'], 'active');
  if (state === 'paused') return 'paused';
  if (state === 'archived' || state === 'deleted') return 'archived';
  return 'active';
}

function policyGroupId(item: DataItem) {
  return str(item, ['target_group_id'], str(nested(item, 'target_group'), ['id']));
}

function optionLabel(options: SelectOption[], value: string) {
  return options.find((option) => option.value === value)?.label ?? value.replace(/_/g, ' ');
}

function formatSafeWindow(item: DataItem) {
  const windows = item.safe_windows;
  const first = Array.isArray(windows) ? windows[0] : null;
  if (!first || typeof first !== 'object') return '';
  const windowItem = first as DataItem;
  const day = str(windowItem, ['day']);
  const start = str(windowItem, ['start']);
  const end = str(windowItem, ['end']);
  const timezone = str(windowItem, ['timezone']);
  if (!start && !end) return '';
  const range = start && end ? `${start}–${end}` : start || end;
  return [day, range, timezone].filter(Boolean).join(' ');
}

function PolicyStateBadge({ item }: { item: DataItem }) {
  const raw = str(item, ['state'], 'active');
  const bucket = policyStateBucket(item);
  if (bucket === 'paused') {
    return <Badge tone="warn"><Pause size={12} aria-hidden="true" />Paused</Badge>;
  }
  if (bucket === 'archived') {
    return <Badge tone="muted"><Archive size={12} aria-hidden="true" />{raw === 'deleted' ? 'Deleted' : 'Archived'}</Badge>;
  }
  if (raw !== 'active') {
    return <Badge tone="info"><CircleDashed size={12} aria-hidden="true" />{raw.replace(/_/g, ' ')}</Badge>;
  }
  return <Badge tone="success"><CircleCheck size={12} aria-hidden="true" />Active</Badge>;
}

function Stat({ label, value, hint }: { label: string; value: ReactNode; hint: ReactNode }) {
  return (
    <div className="rf-stat">
      <span className="rf-stat-label">{label}</span>
      <span className="rf-stat-value">{value}</span>
      <span className="rf-stat-hint">{hint}</span>
    </div>
  );
}

function FeedbackBanner({ message, error }: { message: string; error: string }) {
  if (!message && !error) return null;
  return (
    <div className={error ? 'form-banner error' : 'form-banner neutral'} role={error ? 'alert' : 'status'}>
      {error || message}
    </div>
  );
}

function TargetBindingRow({
  targetGroupId,
  form,
  busy
}: {
  targetGroupId: string;
  form: PolicyCreateFormModel;
  busy: string;
}) {
  const group = form.targetGroups.find((candidate) => str(candidate, ['id']) === targetGroupId);
  const groupName = str(group, ['name'], targetGroupId);
  const binding = form.bindings[targetGroupId];
  const targets = binding?.targets ?? [];
  const check = form.selectedCheck;
  const compatibleTargets = check ? targets.filter((target) => isPolicyTargetCompatible(check, target)) : [];
  const selectedTarget = compatibleTargets.find((target) => str(target, ['id']) === binding?.selectedTargetId);
  const supportedKinds = policySupportedTargetKinds(check);
  const checkName = str(check, ['name', 'check_id'], 'selected check');
  const noCompatibleTargets = Boolean(
    check && !binding?.loading && !binding?.error && targets.length > 0 && compatibleTargets.length === 0
  );
  const options: SelectOption[] = [
    {
      value: '',
      label: binding?.loading
        ? 'Loading active targets…'
        : targets.length === 0
          ? 'No active targets available'
          : noCompatibleTargets
            ? 'No compatible targets'
            : 'Select exact target'
    },
    ...compatibleTargets.map((target) => {
      const targetId = str(target, ['id']);
      return {
        value: targetId,
        label: str(target, ['value'], targetId),
        description: `${effectivePolicyTargetKind(target).replace(/_/g, ' ')} · ${targetId}`
      };
    })
  ];

  return (
    <li className="rf-binding" aria-busy={binding?.loading || undefined}>
      <Select
        label={`${groupName} exact target`}
        value={binding?.selectedTargetId ?? ''}
        options={options}
        disabled={!check || !binding || binding.loading || Boolean(binding.error) || compatibleTargets.length === 0 || busy !== ''}
        onChange={(targetId) => form.onSelectTarget(targetGroupId, targetId)}
      />
      {binding?.error ? (
        <div className="form-banner error rf-binding-error" role="alert">
          <span>{groupName}: {binding.error}</span>
          <Button type="button" size="sm" variant="secondary" disabled={busy !== ''} onClick={() => form.onRetryTargets(targetGroupId)}>
            Retry targets
          </Button>
        </div>
      ) : selectedTarget ? (
        <p className="rf-binding-note">
          <CircleCheck size={14} aria-hidden="true" />
          <span>
            Bound identity <strong className="rf-mono">{str(selectedTarget, ['value'], binding.selectedTargetId)}</strong>
            {' '}<span className="rf-mono">{binding.selectedTargetId}</span>
          </span>
        </p>
      ) : noCompatibleTargets ? (
        <p className="form-banner neutral" role="status">
          {groupName} has no exact target compatible with {checkName}. This check supports {supportedKinds.join(', ') || 'any declared target kind'}. Choose another check or target group.
        </p>
      ) : !binding?.loading && targets.length === 0 ? (
        <p className="form-banner error" role="alert">{groupName} has no active target to schedule.</p>
      ) : null}
    </li>
  );
}

function CreateSchedulePanel({
  form,
  busy,
  message,
  error,
  safeCheckCount,
  panelId
}: {
  form: PolicyCreateFormModel;
  busy: string;
  message: string;
  error: string;
  safeCheckCount: number;
  panelId: string;
}) {
  const headingId = useId();
  const statusId = useId();
  const checkSectionId = useId();
  const scopeSectionId = useId();
  const cadenceSectionId = useId();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const noGroups = form.targetGroups.length === 0;
  const noChecks = safeCheckCount === 0;
  const selectedCount = form.selectedGroupIds.length;

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  const readiness = noGroups
    ? 'Declare an active target group before creating a schedule.'
    : noChecks
      ? 'No customer-runnable checks are available to schedule.'
      : !form.checkId
        ? 'Select a check to continue.'
        : selectedCount === 0
          ? 'Select at least one target group.'
          : !form.bindingsReady
            ? 'Select one exact active target for every selected group.'
            : `Ready to create ${selectedCount} ${selectedCount === 1 ? 'schedule' : 'schedules'}, one per target group.`;
  const submitDisabled = noGroups || noChecks || !form.checkId || !form.bindingsReady || busy !== '';

  return (
    <section id={panelId} className="rf-panel rf-create" aria-labelledby={headingId}>
      <div className="rf-create-head">
        <div className="rf-create-heading">
          <h2 id={headingId} ref={headingRef} tabIndex={-1}>New validation schedule</h2>
          <p>
            Bind a customer-runnable check to one exact active target in each selected group. Groups are written one at a time, and failed bindings stay selected for retry. SOC-gated checks remain request-only.
          </p>
        </div>
        <Button type="button" size="sm" variant="ghost" disabled={busy !== ''} onClick={form.onClose}>Cancel</Button>
      </div>

      <form className="product-form rf-policy-form" onSubmit={form.onSubmit} aria-busy={busy === 'create-test-policy' || undefined}>
        <input type="hidden" name="check_id" value={form.checkId} />
        <input type="hidden" name="cadence" value={form.cadence} />
        <input type="hidden" name="expected_verdict" value={form.expectedVerdict} />

        <div className="rf-form-section">
          <div className="rf-form-intro">
            <h3 id={checkSectionId}><span className="rf-step" aria-hidden="true">1</span>Check</h3>
            <p>Only customer-runnable checks can be scheduled. The check decides which target kinds can be bound.</p>
          </div>
          <fieldset className="rf-form-fields" aria-labelledby={checkSectionId}>
            <Select
              label="Check"
              value={form.checkId}
              options={form.checkOptions}
              disabled={noChecks}
              onChange={form.onCheckChange}
            />
            <Select
              label="Expected verdict"
              value={form.expectedVerdict}
              options={form.verdictOptions}
              onChange={form.onExpectedVerdictChange}
            />
            <p className="rf-help full">
              The expected verdict is a declaration. It is compared against external probe evidence once a run records it.
              {noChecks ? <> <a href="#checks">Review the check catalog</a>.</> : null}
            </p>
          </fieldset>
        </div>

        <div className="rf-form-section">
          <div className="rf-form-intro">
            <h3 id={scopeSectionId}><span className="rf-step" aria-hidden="true">2</span>Scope</h3>
            <p>Choose declared target groups, then one exact target in each. Targets are never assigned automatically, and the bound identity cannot change after creation.</p>
          </div>
          <fieldset className="rf-form-fields" aria-labelledby={scopeSectionId}>
            <div className="full">
              <TargetGroupPicker
                groups={form.targetGroups}
                selectedIds={form.selectedGroupIds}
                onChange={form.onTargetGroupsChange}
                disabled={noGroups || busy !== ''}
              />
            </div>
            {noGroups ? (
              <p className="rf-help full">
                No active target groups are declared. <a href="#target-groups">Declare a target group</a> first.
              </p>
            ) : null}
            {selectedCount > 0 ? (
              <ul className="rf-binding-list full" aria-live="polite" aria-label="Exact target per group">
                {form.selectedGroupIds.map((targetGroupId) => (
                  <TargetBindingRow key={targetGroupId} targetGroupId={targetGroupId} form={form} busy={busy} />
                ))}
              </ul>
            ) : null}
          </fieldset>
        </div>

        <div className="rf-form-section">
          <div className="rf-form-intro">
            <h3 id={cadenceSectionId}><span className="rf-step" aria-hidden="true">3</span>Cadence</h3>
            <p>How often the check runs. A safe window limits when scheduled runs may start.</p>
          </div>
          <fieldset className="rf-form-fields" aria-labelledby={cadenceSectionId}>
            <Select
              label="Cadence"
              value={form.cadence}
              options={form.cadenceOptions}
              onChange={form.onCadenceChange}
            />
            <details className="rf-disclosure full">
              <summary>Safe window (optional)</summary>
              <div className="rf-disclosure-body">
                <p className="rf-help full">Leave every field blank for no safe window, or complete all four.</p>
                <label>
                  <span>Safe window day</span>
                  <input name="safe_window_day" placeholder="Mon" autoComplete="off" />
                </label>
                <label>
                  <span>Window timezone</span>
                  <input name="safe_window_timezone" placeholder="UTC" autoComplete="off" spellCheck={false} />
                </label>
                <label>
                  <span>Window start</span>
                  <input name="safe_window_start" type="time" />
                </label>
                <label>
                  <span>Window end</span>
                  <input name="safe_window_end" type="time" />
                </label>
              </div>
            </details>
          </fieldset>
        </div>

        <FeedbackBanner message={message} error={error} />

        <div className="rf-form-footer">
          <p id={statusId} className="rf-readiness" aria-live="polite">
            {submitDisabled && busy === '' ? <CircleDashed size={14} aria-hidden="true" /> : <CircleCheck size={14} aria-hidden="true" />}
            <span>{readiness}</span>
          </p>
          <div className="form-actions">
            <Button type="button" variant="ghost" disabled={busy !== ''} onClick={form.onClose}>Cancel</Button>
            <Button
              type="submit"
              loading={busy === 'create-test-policy'}
              disabled={submitDisabled}
              aria-describedby={statusId}
            >
              Create schedule
            </Button>
          </div>
        </div>
      </form>
    </section>
  );
}

export function PoliciesRefined(props: PoliciesRefinedProps) {
  const { data, busy, message, error, canWritePolicies, createForm } = props;
  const [stateFilter, setStateFilter] = useState<StateFilter>('all');
  const panelId = useId();
  const tableHeadingId = useId();
  const createButtonRef = useRef<HTMLButtonElement>(null);
  const policiesUnavailable = Boolean(data.loadErrors.testPolicies);
  const socUnavailable = policiesUnavailable || Boolean(data.loadErrors.checks);
  const formOpen = canWritePolicies && createForm.open;
  const wasFormOpen = useRef(formOpen);

  useEffect(() => {
    if (wasFormOpen.current && !formOpen) {
      window.requestAnimationFrame(() => createButtonRef.current?.focus());
    }
    wasFormOpen.current = formOpen;
  }, [formOpen]);

  const counts = useMemo(() => {
    const result: Record<StateFilter, number> = { all: data.testPolicies.length, active: 0, paused: 0, archived: 0 };
    for (const policy of data.testPolicies) result[policyStateBucket(policy)] += 1;
    return result;
  }, [data.testPolicies]);

  const coveredGroupCount = useMemo(() => {
    const covered = new Set(props.activePolicies.map(policyGroupId).filter(Boolean));
    if (createForm.targetGroups.length === 0) return covered.size;
    const activeGroupIds = new Set(createForm.targetGroups.map((group) => str(group, ['id'])));
    return [...covered].filter((id) => activeGroupIds.has(id)).length;
  }, [props.activePolicies, createForm.targetGroups]);

  const visiblePolicies = stateFilter === 'all'
    ? data.testPolicies
    : data.testPolicies.filter((policy) => policyStateBucket(policy) === stateFilter);

  const classicRender = useMemo(() => {
    const byKey = new Map(props.policyColumns.map((column) => [column.key, column.render]));
    return (key: string, item: DataItem) => byKey.get(key)?.(item) ?? null;
  }, [props.policyColumns]);

  const columns: TableColumn<DataItem>[] = [
    {
      key: 'schedule',
      label: 'Schedule',
      render: (item) => {
        const id = rowId(item);
        return (
          <div className="rf-cell">
            <span className="rf-cell-title">{str(item, ['name', 'title'], 'Scheduled policy')}</span>
            {id ? <span className="rf-mono rf-cell-meta">{id}</span> : null}
            <span className="rf-cell-meta">Updated {formatDate(item.updated_at ?? item.created_at)}</span>
          </div>
        );
      }
    },
    {
      key: 'scope',
      label: 'Scope',
      render: (item) => (
        <div className="rf-cell">
          <div className="rf-cell-link">{classicRender('target', item)}</div>
          <div className="rf-cell-link">{classicRender('exact_target', item)}</div>
        </div>
      )
    },
    {
      key: 'check',
      label: 'Check',
      render: (item) => {
        const verdict = str(item, ['expected_verdict']);
        return (
          <div className="rf-cell">
            <div className="rf-cell-link">{classicRender('check', item)}</div>
            {verdict ? (
              <span className="rf-cell-meta" title="Declared expectation, not observed evidence">
                Expects {optionLabel(createForm.verdictOptions, verdict).toLowerCase()}
              </span>
            ) : null}
          </div>
        );
      }
    },
    {
      key: 'cadence',
      label: 'Cadence',
      render: (item) => {
        const next = props.getPolicyNextRun(item);
        const window = formatSafeWindow(item);
        // Classic uses a dash placeholder for an unknown next run; any label without letters or digits counts as missing.
        const nextLabel = /[\p{L}\p{N}]/u.test(next.label) ? next.label : 'Not scheduled';
        return (
          <div className="rf-cell">
            <span className="rf-cell-title">{optionLabel(createForm.cadenceOptions, str(item, ['cadence'], 'manual'))}</span>
            {next.socGated ? (
              <Badge tone="warn" title="High-scale schedules run only when SOC schedules them.">
                <ShieldCheck size={12} aria-hidden="true" />Awaiting SOC
              </Badge>
            ) : (
              <span className="rf-cell-meta">
                <CalendarClock size={12} aria-hidden="true" />
                <span>Next <span className="rf-mono">{nextLabel}</span></span>
              </span>
            )}
            <span className="rf-cell-meta">{window ? <>Window <span className="rf-mono">{window}</span></> : 'No safe window'}</span>
          </div>
        );
      }
    },
    { key: 'status', label: 'Status', render: (item) => <PolicyStateBadge item={item} /> },
    // Row actions keep the classic render, so the write gate, busy keys, and confirms are unchanged.
    ...(canWritePolicies ? [{ key: 'actions', label: 'Actions', render: (item: DataItem) => classicRender('actions', item) }] : [])
  ];

  const filterLabel = STATE_FILTERS.find((option) => option.id === stateFilter)?.label ?? 'All';
  const emptyState = stateFilter !== 'all' && data.testPolicies.length > 0 ? (
    <EmptyState
      icon={ListFilter}
      title={`No ${filterLabel.toLowerCase()} schedules.`}
      body="Choose another state to see the remaining schedules."
      actionLabel="Show all schedules"
      onAction={() => setStateFilter('all')}
    />
  ) : props.policyEmptyState;

  const nextRunValue = policiesUnavailable ? 'Unavailable' : props.upcomingRuns.length > 0 ? props.nextRunLabel : 'None';
  const groupsTotal = createForm.targetGroups.length;

  function openCreate() {
    if (formOpen) {
      document.getElementById(panelId)?.querySelector<HTMLElement>('h2')?.focus();
      return;
    }
    props.onCreateSchedule();
  }

  return (
    <div className="content refined rf-policies">
      <header className="rf-header">
        <div className="rf-header-copy">
          <p className="rf-eyebrow">Declared scope, bounded execution</p>
          <h1>Test policies</h1>
          <p className="rf-header-description">
            Scheduled validation cadences, exact target bindings, and safe windows. Expected verdicts stay declarations until external probe evidence is recorded. High-scale scenarios stay SOC-scheduled.
          </p>
        </div>
        <div className="rf-header-actions">
          <VariantSwitch value={props.variant} onChange={props.onVariantChange} />
          {canWritePolicies ? (
            <Button
              ref={createButtonRef}
              variant="default"
              size="sm"
              disabled={busy !== ''}
              aria-expanded={formOpen}
              aria-controls={formOpen ? panelId : undefined}
              onClick={openCreate}
            >
              <Plus size={14} aria-hidden="true" />
              Create schedule
            </Button>
          ) : null}
        </div>
      </header>

      <section className="rf-summary-strip" aria-label="Schedule summary">
        <Stat
          label="Active"
          value={policiesUnavailable ? 'Unavailable' : formatNumber(counts.active)}
          hint={policiesUnavailable ? 'Policy data unavailable' : `${formatNumber(counts.paused)} paused, ${formatNumber(counts.archived)} archived`}
        />
        <Stat
          label="Next run"
          value={<span className="rf-stat-date">{nextRunValue}</span>}
          hint={policiesUnavailable ? 'Policy data unavailable' : props.upcomingRuns.length > 0 ? `${props.upcomingRuns.length} upcoming` : 'No cadence scheduled'}
        />
        <Stat
          label="Groups covered"
          value={policiesUnavailable ? 'Unavailable' : (
            <>{formatNumber(coveredGroupCount)}{groupsTotal > 0 ? <span className="rf-stat-of"> of {formatNumber(groupsTotal)}</span> : null}</>
          )}
          hint={data.loadErrors.targetGroups ? 'Target group data unavailable' : 'Active groups with a schedule'}
        />
        <Stat
          label="Checks bound"
          value={policiesUnavailable ? 'Unavailable' : formatNumber(props.boundPolicyCount)}
          hint={data.loadErrors.checks ? 'Check catalog unavailable' : `${props.safeChecks.length} checks bindable`}
        />
        <Stat
          label="SOC-scheduled"
          value={socUnavailable ? 'Unavailable' : formatNumber(props.socScheduledCount)}
          hint={socUnavailable ? 'SOC schedule data unavailable' : props.socScheduledCount > 0 ? 'Awaiting SOC' : 'None gated'}
        />
      </section>

      {formOpen ? (
        <CreateSchedulePanel
          form={createForm}
          busy={busy}
          message={message}
          error={error}
          safeCheckCount={props.safeChecks.length}
          panelId={panelId}
        />
      ) : (
        <FeedbackBanner message={message} error={error} />
      )}

      <section className="rf-section" aria-labelledby={tableHeadingId}>
        <div className="rf-section-head">
          <div className="rf-section-copy">
            <h2 id={tableHeadingId}>Validation schedules</h2>
            <p>Bindings between declared target groups and customer-runnable checks. Select a row to open its detail.</p>
          </div>
          <div className="rf-toolbar">
            <div className="rf-segmented" role="group" aria-label="Filter schedules by state">
              {STATE_FILTERS.map((option) => (
                <button
                  key={option.id}
                  type="button"
                  aria-pressed={stateFilter === option.id}
                  onClick={() => setStateFilter(option.id)}
                >
                  {option.label}
                  <span className="rf-segmented-count">{formatNumber(counts[option.id])}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
        <div className="rf-panel rf-panel-flush">
          <DataTable
            columns={columns}
            items={visiblePolicies}
            loadError={data.loadErrors.testPolicies}
            onRetry={() => void props.onRefresh()}
            getRowId={rowId}
            getRowProps={props.getPolicyRowProps}
            empty={emptyState}
          />
        </div>
        <div className="rf-footnotes">
          <p className="rf-footnote">
            <ShieldCheck size={14} aria-hidden="true" />
            <span>
              {props.socGatedChecks.length > 0
                ? `${props.socGatedChecks.length} SOC-gated ${props.socGatedChecks.length === 1 ? 'check' : 'checks'} in the catalog. High-scale schedules run only when SOC schedules them.`
                : 'High-scale schedules run only when SOC schedules them.'}
            </span>
          </p>
          {!canWritePolicies ? (
            <p className="rf-footnote">
              <Lock size={14} aria-hidden="true" />
              <span>Read only. Changing schedules requires the test_policy:write permission.</span>
            </p>
          ) : null}
        </div>
      </section>

      {props.modals}
    </div>
  );
}
