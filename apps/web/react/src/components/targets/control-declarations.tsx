import { useEffect, useId, useMemo, useRef, useState, type MouseEvent, type ReactNode } from 'react';
import {
  CircleCheck, CircleDashed, CircleDot, Copy, FileText, GitCompareArrows, Link2, Link2Off, Lock, Plus, RotateCcw, Save, Trash2, TriangleAlert,
} from 'lucide-react';
import { requestJson } from '../../lib/api';
import { apiErrorMessage } from '../../lib/error-messages';
import { formatDate } from '../../lib/utils';
import type { DataItem, PortalConfig, Session } from '../../lib/types';
import {
  DECLARATION_KEYS,
  DECLARATION_SECTION_GROUPS,
  EXPECTED_WAF_ACTIONS,
  RATE_LIMIT_EXPECTED_ACTIONS,
  MAX_CONNECTION_LIMITS,
  MAX_HEADER_VALUE,
  MAX_MARKER_PATHS,
  MAX_NETWORK_RULES,
  controlsHref,
  declarationSectionStates,
  declarationSummary,
  declarationsDraftDiff,
  declarationsDraftSignature,
  declarationsEtag,
  declarationsFromDraft,
  declarationsSaveConflict,
  draftFromDeclarations,
  emptyConnectionLimit,
  emptyNetworkRule,
  serverFieldErrors,
  validateDeclarationsDraft,
  type DeclarationSectionState,
  type DeclarationsDiffRow,
  type DeclarationsDraft,
} from '../../lib/control-declarations.mjs';
import { TERM_HELP } from '../../lib/probe-evidence.mjs';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import './control-declarations.css';

export type OriginRelationSummary = { state: 'loading' | 'ready' | 'unavailable'; active: number };

export type ProbePerspective = { id: string; label: string; region: string; egressIps: string[] };

export function normalizePerspectives(payload: unknown): ProbePerspective[] {
  const items = payload && typeof payload === 'object' && Array.isArray((payload as DataItem).items) ? (payload as { items: unknown[] }).items : [];
  return items.flatMap((raw) => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return [];
    const item = raw as DataItem;
    const id = typeof item.id === 'string' ? item.id.trim() : '';
    if (!id) return [];
    return [{
      id,
      label: typeof item.label === 'string' && item.label.trim() ? item.label.trim() : id,
      region: typeof item.region === 'string' ? item.region.trim() : '',
      egressIps: Array.isArray(item.egress_ips) ? item.egress_ips.filter((ip): ip is string => typeof ip === 'string' && ip.trim() !== '') : [],
    }];
  });
}

function fieldId(field: string) {
  return `cd-${field.replace(/[^a-zA-Z0-9]+/g, '-')}`;
}

const FIELD_LABELS: Array<[RegExp, string]> = [
  [/^network_policy\[(\d+)\]\.port$/, 'Network rule $1: port'],
  [/^network_policy\[(\d+)\]\.note$/, 'Network rule $1: note'],
  [/^network_policy\[(\d+)\]/, 'Network rule $1'],
  [/^network_policy$/, 'Network policy'],
  [/^waf\.block_signature\.header_name$/, 'Block signature: header name'],
  [/^waf\.block_signature\.header_value$/, 'Block signature: header value'],
  [/^waf\.block_signature\.status_codes/, 'Block signature: status codes'],
  [/^waf\.expected_action$/, 'Expected WAF action'],
  [/^waf\.rate_limit_canary\.path$/, 'Rate-limit canary: path'],
  [/^waf\.rate_limit_canary\.threshold$/, 'Rate-limit canary: threshold'],
  [/^waf\.rate_limit_canary\.window_seconds$/, 'Rate-limit canary: window'],
  [/^waf\.rate_limit_canary\.expected_action$/, 'Rate-limit canary: action at the limit'],
  [/^waf\.marker_paths\[(\d+)\]$/, 'Extra marker path $1'],
  [/^waf\.marker_paths$/, 'Extra marker paths'],
  [/^canary_sink\.url$/, 'Canary sink URL'],
  [/^connection_limits\[(\d+)\]\.port$/, 'Connection limit $1: port'],
  [/^connection_limits\[(\d+)\]\.max_connections_per_source$/, 'Connection limit $1: connections per source'],
  [/^connection_limits/, 'Connection limits'],
  [/^perspectives\./, 'Probe perspectives'],
];

function fieldLabel(field: string) {
  for (const [pattern, label] of FIELD_LABELS) {
    const match = field.match(pattern);
    if (match) return label.replace('$1', match[1] ? String(Number(match[1]) + 1) : '');
  }
  return 'Control declarations';
}

/** Where a server field error should land when it names a whole row or section. */
function focusTargetFor(field: string) {
  if (/^network_policy\[\d+\]$/.test(field)) return `${field}.port`;
  if (/^connection_limits\[\d+\]$/.test(field)) return `${field}.port`;
  if (field.startsWith('waf.block_signature.status_codes')) return 'waf.block_signature.status_codes';
  return field;
}

function prefersReducedMotion() {
  return typeof window !== 'undefined' && typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

/** Whether the second half of the origin-lockdown prerequisite (one active origin relation) is in place. */
function OriginRelationStatus({ relations, href, lockdown }: { relations?: OriginRelationSummary; href: string; lockdown: boolean }) {
  if (!relations || relations.state === 'loading') return <p className="cd-origin-relation" data-state="loading" role="status">Checking origin relations…</p>;
  const link = href ? <a className="detail-entity-link" href={href}>Open Origin relations</a> : null;
  if (relations.state === 'unavailable') {
    return <p className="cd-origin-relation" data-state="unknown"><Link2 size={15} aria-hidden="true" /><span>Origin relations could not be read here. Confirm one active relation names your origin address. {link}</span></p>;
  }
  if (relations.active === 1) {
    return <p className="cd-origin-relation" data-state="ok"><Link2 size={15} aria-hidden="true" /><span><b>Origin relation: 1 active.</b> {lockdown ? 'The check sends its one request to that origin address.' : 'Declare lockdown above to let the check use it.'} {link}</span></p>;
  }
  const many = relations.active > 1;
  return (
    <p className="cd-origin-relation" data-state={lockdown ? 'gap' : 'idle'}>
      <Link2Off size={15} aria-hidden="true" />
      <span>
        <b>{many ? `Origin relations: ${relations.active} active.` : 'No active origin relation.'}</b>{' '}
        {many ? 'The check refuses to guess which origin to probe; archive the extras so exactly one remains.' : 'Without one, the origin-lockdown check cannot run even with lockdown declared.'} {link}
      </span>
    </p>
  );
}

function SectionStateIcon({ state }: { state: DeclarationSectionState }) {
  if (state.edited) return <CircleDot size={16} aria-hidden="true" className="cd-nav-icon" data-state="edited" />;
  if (state.declared) return <CircleCheck size={16} aria-hidden="true" className="cd-nav-icon" data-state="declared" />;
  return <CircleDashed size={16} aria-hidden="true" className="cd-nav-icon" data-state="empty" />;
}

type Props = {
  config: PortalConfig;
  session: Session;
  target: DataItem;
  canWrite: boolean;
  declarations: DataItem | null;
  loadState: 'loading' | 'ready' | 'error';
  loadError: string;
  perspectives: ProbePerspective[];
  perspectivesError: string;
  focusSection?: string;
  /** Active origin relations naming this target; the origin-lockdown check needs exactly one. */
  originRelations?: OriginRelationSummary;
  originRelationsHref?: string;
  onReload: () => void;
  onSaved: (next: DataItem) => void;
  /** Replaces the stored document after a conflict, without treating it as this user's save. */
  onLatest?: (latest: DataItem) => void;
  onDirtyChange?: (dirty: boolean) => void;
};

type Conflict = {
  kind: 'conflict' | 'precondition';
  status: 'idle' | 'loading' | 'ready' | 'error';
  latest: DataItem | null;
  diff: DeclarationsDiffRow[];
  error: string;
};

const PAGE_PURPOSE = 'Tell AstraNull how your controls are meant to behave. A declaration is an input to a check, never proof on its own: a check still has to observe the behaviour from outside. Every save is audited.';

export function ControlDeclarations({
  config, session, target, canWrite, declarations, loadState, loadError, perspectives, perspectivesError,
  focusSection = '', originRelations, originRelationsHref = '', onReload, onSaved, onLatest, onDirtyChange,
}: Props) {
  const baseId = useId();
  const initial = useMemo(() => draftFromDeclarations(declarations), [declarations]);
  const [draft, setDraft] = useState<DeclarationsDraft>(initial);
  const [touched, setTouched] = useState<Set<string>>(() => new Set());
  const [submitted, setSubmitted] = useState(false);
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({});
  const [saveError, setSaveError] = useState('');
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState('');
  const [conflict, setConflict] = useState<Conflict | null>(null);
  const summaryRef = useRef<HTMLDivElement>(null);
  const conflictRef = useRef<HTMLDivElement>(null);
  const dirty = declarationsDraftSignature(draft) !== declarationsDraftSignature(initial);
  const perspectiveIds = useMemo(() => perspectives.map((item) => item.id), [perspectives]);
  const clientErrors = useMemo(() => validateDeclarationsDraft(draft, { target, perspectiveIds: perspectivesError ? null : perspectiveIds }), [draft, target, perspectiveIds, perspectivesError]);
  const sectionStates = useMemo(() => declarationSectionStates(declarations, draft), [declarations, draft]);
  const summary = declarationSummary(declarations);
  const readOnly = !canWrite;

  const baselineRef = useRef(initial);
  useEffect(() => {
    // Follow a new stored document only while the draft still equals the one it was built from.
    if (declarationsDraftSignature(draft) === declarationsDraftSignature(baselineRef.current)) setDraft(initial);
    baselineRef.current = initial;
  }, [initial]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { onDirtyChange?.(dirty); }, [dirty, onDirtyChange]);
  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange]);
  useEffect(() => {
    if (!dirty) return undefined;
    const guard = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ''; };
    window.addEventListener('beforeunload', guard);
    return () => window.removeEventListener('beforeunload', guard);
  }, [dirty]);
  useEffect(() => {
    if (!focusSection || loadState !== 'ready') return;
    const section = document.getElementById(`cd-section-${focusSection}`);
    if (!section) return;
    section.scrollIntoView({ block: 'start' });
    section.querySelector<HTMLElement>('input:not([disabled]), select:not([disabled]), button:not([disabled])')?.focus({ preventScroll: true });
  }, [focusSection, loadState]);

  const visibleErrors: Record<string, string> = {};
  for (const [field, message] of Object.entries(clientErrors)) {
    if (submitted || touched.has(field)) visibleErrors[field] = message;
  }
  for (const [field, message] of Object.entries(serverErrors)) visibleErrors[focusTargetFor(field)] = message;

  function update(patch: Partial<DeclarationsDraft>, fields: string[] = []) {
    setDraft((current) => ({ ...current, ...patch }));
    setNotice('');
    if (fields.length) {
      setServerErrors((current) => Object.fromEntries(Object.entries(current).filter(([key]) => !fields.some((field) => key === field || key.startsWith(`${field}.`) || key.startsWith(`${field}[`)))));
    }
  }

  function touch(field: string) {
    setTouched((current) => (current.has(field) ? current : new Set(current).add(field)));
  }

  function errorProps(field: string, hintId?: string) {
    const message = visibleErrors[field];
    const errorId = `${fieldId(field)}-error`;
    return {
      id: fieldId(field),
      'aria-invalid': message ? true : undefined,
      'aria-describedby': [message ? errorId : '', hintId ?? ''].filter(Boolean).join(' ') || undefined,
      onBlur: () => touch(field),
    } as const;
  }

  function fieldError(field: string) {
    const message = visibleErrors[field];
    return message ? <span className="cd-error" id={`${fieldId(field)}-error`}><TriangleAlert size={13} aria-hidden="true" />{message}</span> : null;
  }

  function discard() {
    if (!window.confirm('Discard your unsaved changes to the control declarations?')) return;
    setDraft(initial);
    setTouched(new Set());
    setSubmitted(false);
    setServerErrors({});
    setSaveError('');
  }

  async function save() {
    setSubmitted(true);
    setSaveError('');
    setNotice('');
    if (Object.keys(clientErrors).length) {
      window.requestAnimationFrame(() => summaryRef.current?.focus());
      return;
    }
    setSaving(true);
    try {
      const saved = await requestJson(config, session, `/v1/targets/${encodeURIComponent(String(target.id ?? ''))}/control-declarations`, {
        method: 'PUT',
        body: declarationsFromDraft(draft),
        headers: { 'If-Match': declarationsEtag(declarations) },
      }) as DataItem;
      setServerErrors({});
      setTouched(new Set());
      setSubmitted(false);
      setConflict(null);
      setNotice('Declarations saved and recorded in the audit log.');
      onSaved(saved);
    } catch (error) {
      const fields = serverFieldErrors((error as { payload?: unknown }).payload);
      const clash = declarationsSaveConflict(error);
      if (clash) {
        setConflict({ kind: clash.kind, status: 'idle', latest: null, diff: [], error: '' });
        window.requestAnimationFrame(() => conflictRef.current?.focus());
      } else if (Object.keys(fields).length) {
        setServerErrors(fields);
        window.requestAnimationFrame(() => summaryRef.current?.focus());
      } else {
        setSaveError(apiErrorMessage(error, 'Declarations could not be saved. Nothing was changed.'));
      }
    } finally {
      setSaving(false);
    }
  }

  async function loadLatest() {
    setConflict((current) => (current ? { ...current, status: 'loading', error: '' } : current));
    try {
      const latest = await requestJson(config, session, `/v1/targets/${encodeURIComponent(String(target.id ?? ''))}/control-declarations`) as DataItem;
      setConflict((current) => (current ? { ...current, status: 'ready', latest, diff: declarationsDraftDiff(latest, draft) } : current));
    } catch (error) {
      setConflict((current) => (current ? { ...current, status: 'error', error: apiErrorMessage(error, 'The latest declarations could not load. Your draft is still here.') } : current));
    }
  }

  function keepDraftOnLatest() {
    if (!conflict?.latest) return;
    onLatest?.(conflict.latest);
    setConflict(null);
    setNotice('Their version is now the saved baseline. Your draft is unchanged: review it, then save to apply your changes on top.');
  }

  function useTheirVersion() {
    if (!conflict?.latest) return;
    if (!window.confirm('Replace your draft with their saved version? Your unsaved changes will be lost.')) return;
    const latest = conflict.latest;
    setDraft(draftFromDeclarations(latest));
    setTouched(new Set());
    setSubmitted(false);
    setServerErrors({});
    onLatest?.(latest);
    setConflict(null);
    setNotice('Loaded their saved version. Your unsaved changes were discarded.');
  }

  async function copyIps(perspective: ProbePerspective) {
    try {
      await navigator.clipboard.writeText(perspective.egressIps.join('\n'));
      setNotice(`Copied ${perspective.egressIps.length} egress ${perspective.egressIps.length === 1 ? 'address' : 'addresses'} for ${perspective.label}.`);
    } catch {
      setNotice(`Copy failed. Select the addresses for ${perspective.label} and copy them manually.`);
    }
  }

  function jumpToSection(event: MouseEvent<HTMLAnchorElement>, id: string) {
    const section = document.getElementById(`cd-section-${id}`);
    if (!section) return;
    event.preventDefault();
    section.scrollIntoView({ block: 'start', behavior: prefersReducedMotion() ? 'auto' : 'smooth' });
    section.focus({ preventScroll: true });
  }

  const head = (state: ReactNode = null) => (
    <header className="cd-head">
      <div className="cd-head-copy">
        <h2 id={`${baseId}-title`}>Control declarations</h2>
        <p>{PAGE_PURPOSE}</p>
      </div>
      {state}
    </header>
  );

  if (loadState === 'loading') {
    return (
      <section className="cd" aria-labelledby={`${baseId}-title`} aria-busy="true">
        {head()}
        <p className="sr-only" role="status">Loading control declarations…</p>
        <div className="cd-layout" aria-hidden="true">
          <div className="cd-overview cd-skeleton-card">
            <div className="skeleton skeleton-text" />
            <div className="skeleton skeleton-row" />
            <div className="skeleton skeleton-row" />
          </div>
          <div className="cd-main">
            <div className="cd-skeleton-card"><div className="skeleton skeleton-text" /><div className="skeleton skeleton-row" /><div className="skeleton skeleton-row" /></div>
            <div className="cd-skeleton-card"><div className="skeleton skeleton-text" /><div className="skeleton skeleton-row" /></div>
          </div>
        </div>
      </section>
    );
  }
  if (loadState === 'error') {
    return (
      <section className="cd" aria-labelledby={`${baseId}-title`}>
        {head()}
        <div className="cd-callout" data-tone="danger" role="alert">
          <TriangleAlert size={18} aria-hidden="true" className="cd-callout-icon" />
          <div className="cd-callout-body">
            <strong>Control declarations could not load</strong>
            <p>{loadError || 'Control declarations could not load.'} Nothing is shown in their place, and checks that need a declaration stay out of run-all.</p>
            <div className="cd-row-actions">
              <Button size="sm" variant="secondary" onClick={onReload}><RotateCcw size={14} aria-hidden="true" />Retry</Button>
            </div>
          </div>
        </div>
      </section>
    );
  }

  const errorEntries = Object.entries(visibleErrors);
  const allowSet = new Set(draft.allowlisted_perspective_ids);
  const denySet = new Set(draft.denied_perspective_ids);
  const stateById = new Map(sectionStates.map((state) => [state.id, state] as const));
  const declaredCount = sectionStates.filter((state) => state.declared).length;
  const editedCount = sectionStates.filter((state) => state.edited).length;
  const showErrorSummary = Boolean(errorEntries.length && (submitted || Object.keys(serverErrors).length));
  const targetId = String(target.id ?? '');

  const saveStateBadge = readOnly
    ? <Badge tone="muted"><Lock size={12} />Read only</Badge>
    : dirty
      ? <Badge tone="warn"><CircleDot size={12} />Unsaved changes</Badge>
      : summary.updatedAt
        ? <Badge tone="success"><CircleCheck size={12} />Saved</Badge>
        : <Badge tone="muted"><CircleDashed size={12} />Not saved yet</Badge>;

  let barState: 'saving' | 'conflict' | 'invalid' | 'dirty' | 'clean' = 'clean';
  if (saving) barState = 'saving';
  else if (conflict) barState = 'conflict';
  else if (showErrorSummary) barState = 'invalid';
  else if (dirty) barState = 'dirty';
  const barCopy = {
    saving: 'Saving declarations…',
    conflict: 'Review the latest version before saving',
    invalid: errorEntries.length === 1 ? 'One value needs fixing before saving' : `${errorEntries.length} values need fixing before saving`,
    dirty: editedCount === 1 ? 'Unsaved changes in 1 section' : editedCount > 1 ? `Unsaved changes in ${editedCount} sections` : 'Unsaved changes',
    clean: summary.updatedAt ? 'All changes saved' : 'No unsaved changes',
  }[barState];
  const barIcon = {
    saving: <Save size={15} aria-hidden="true" />,
    conflict: <GitCompareArrows size={15} aria-hidden="true" />,
    invalid: <TriangleAlert size={15} aria-hidden="true" />,
    dirty: <CircleDot size={15} aria-hidden="true" />,
    clean: <CircleCheck size={15} aria-hidden="true" />,
  }[barState];
  const status = <p className="cd-status" role="status" aria-live="polite">{notice}</p>;

  function section(id: string, title: string, hint: ReactNode, body: ReactNode, options: { lock?: boolean; more?: { summary: string; body: ReactNode } } = {}) {
    const { lock = true, more } = options;
    const hintId = `cd-section-${id}-hint`;
    const state = stateById.get(id as DeclarationSectionState['id']);
    return (
      <fieldset className="cd-section" id={`cd-section-${id}`} aria-describedby={hintId} disabled={lock && (readOnly || saving)} tabIndex={-1} data-edited={state?.edited || undefined}>
        <legend className="cd-section-title">{title}</legend>
        {state ? (
          <div className="cd-section-state">
            {state.edited ? <Badge tone="warn"><CircleDot size={12} />Unsaved</Badge> : null}
            <Badge tone={state.declared ? 'info' : 'muted'}>{state.declared ? <CircleCheck size={12} /> : <CircleDashed size={12} />}{state.declared ? state.detail : 'Not declared'}</Badge>
          </div>
        ) : null}
        <div className="cd-section-intro">
          <p className="cd-hint" id={hintId}>{hint}</p>
          {more ? (
            <details className="cd-more">
              <summary>{more.summary}</summary>
              <div className="cd-more-body">{more.body}</div>
            </details>
          ) : null}
        </div>
        <div className="cd-section-body">{body}</div>
      </fieldset>
    );
  }

  const sections: Record<string, ReactNode> = {
    network: section('network', 'Network policy', (
      <>Which ports should be open or closed from the internet. <b>Deny</b> means the port should not answer. {DECLARATION_KEYS.network_policy.unlocks}</>
    ), (
      <>
        {draft.network_policy.length ? (
          <div className="cd-table-wrap" role="region" aria-label="Network policy rules" tabIndex={0}>
            <table className="data-table cd-table cd-table-stack">
              <caption className="sr-only">Declared network policy rules. Each row is one protocol, port and address family.</caption>
              <thead>
                <tr><th scope="col">Protocol</th><th scope="col">Port</th><th scope="col">Action</th><th scope="col">Address family</th><th scope="col">Note</th><th scope="col"><span className="sr-only">Remove</span></th></tr>
              </thead>
              <tbody>
                {draft.network_policy.map((rule, index) => {
                  const prefix = `network_policy[${index}]`;
                  const rowLabel = `rule ${index + 1}`;
                  const patchRule = (patch: Partial<typeof rule>, field: string) => update({ network_policy: draft.network_policy.map((entry, position) => position === index ? { ...entry, ...patch } : entry) }, [`${prefix}.${field}`, prefix]);
                  return (
                    <tr key={rule.key}>
                      <td data-label="Protocol"><select aria-label={`Protocol for ${rowLabel}`} value={rule.protocol} onChange={(event) => patchRule({ protocol: event.target.value }, 'protocol')}><option value="tcp">TCP</option><option value="udp">UDP</option></select></td>
                      <td data-label="Port">
                        <input type="text" inputMode="numeric" autoComplete="off" className="cd-port" aria-label={`Port for ${rowLabel}`} value={rule.port} placeholder="22" {...errorProps(`${prefix}.port`)} onChange={(event) => patchRule({ port: event.target.value.trim() }, 'port')} />
                        {fieldError(`${prefix}.port`)}
                      </td>
                      <td data-label="Action"><select aria-label={`Action for ${rowLabel}`} value={rule.action} onChange={(event) => patchRule({ action: event.target.value }, 'action')}><option value="deny">Deny</option><option value="allow">Allow</option></select></td>
                      <td data-label="Address family"><select aria-label={`Address family for ${rowLabel}`} value={rule.address_family} onChange={(event) => patchRule({ address_family: event.target.value }, 'address_family')}><option value="any">IPv4 and IPv6</option><option value="ipv4">IPv4 only</option><option value="ipv6">IPv6 only</option></select></td>
                      <td data-label="Note" className="cd-cell-wide">
                        <input type="text" autoComplete="off" aria-label={`Note for ${rowLabel}`} value={rule.note} maxLength={200} placeholder="Optional, e.g. SSH via bastion only" {...errorProps(`${prefix}.note`)} onChange={(event) => patchRule({ note: event.target.value }, 'note')} />
                        {fieldError(`${prefix}.note`)}
                      </td>
                      <td className="cd-cell-action">
                        <Button size="sm" variant="ghost" aria-label={`Remove ${rowLabel}`} onClick={() => update({ network_policy: draft.network_policy.filter((_, position) => position !== index) }, ['network_policy'])}>
                          <Trash2 size={14} aria-hidden="true" />
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : <p className="cd-none">No rules yet. Declare denied ports to let AstraNull report firewall exposures.</p>}
        {fieldError('network_policy')}
        <div className="cd-row-actions">
          <Button size="sm" variant="secondary" disabled={draft.network_policy.length >= MAX_NETWORK_RULES} onClick={() => update({ network_policy: [...draft.network_policy, emptyNetworkRule()] })}>
            <Plus size={14} aria-hidden="true" />Add rule
          </Button>
          <span className="cd-count tabular-nums">{draft.network_policy.length} of {MAX_NETWORK_RULES} rules</span>
          <span className="cd-help">Ports 1 to 65535. Each protocol, port and address family can appear once.</span>
        </div>
      </>
    ), {
      more: {
        summary: 'How exposures are reported',
        body: <p>AstraNull reports an exposure only when a denied port answers from outside your CDN. A closed port is never shown as protected, because silence from outside does not prove a firewall rule.</p>,
      },
    }),

    connection_limits: section('connection_limits', 'Connection limits', `${DECLARATION_KEYS.connection_limits.unlocks} TCP only.`, (
      <>
        {draft.connection_limits.length ? (
          <div className="cd-table-wrap" role="region" aria-label="Connection limits" tabIndex={0}>
            <table className="data-table cd-table cd-table-compact cd-table-stack">
              <caption className="sr-only">Declared per-source TCP connection limits by port.</caption>
              <thead><tr><th scope="col">Port</th><th scope="col">Connections per source</th><th scope="col"><span className="sr-only">Remove</span></th></tr></thead>
              <tbody>
                {draft.connection_limits.map((row, index) => {
                  const prefix = `connection_limits[${index}]`;
                  const patchRow = (patch: Partial<typeof row>, field: string) => update({ connection_limits: draft.connection_limits.map((entry, position) => position === index ? { ...entry, ...patch } : entry) }, [`${prefix}.${field}`, prefix]);
                  return (
                    <tr key={row.key}>
                      <td data-label="Port">
                        <input type="text" inputMode="numeric" autoComplete="off" className="cd-port" aria-label={`Port for connection limit ${index + 1}`} value={row.port} placeholder="443" {...errorProps(`${prefix}.port`)} onChange={(event) => patchRow({ port: event.target.value.trim() }, 'port')} />
                        {fieldError(`${prefix}.port`)}
                      </td>
                      <td data-label="Connections per source">
                        <input type="text" inputMode="numeric" autoComplete="off" className="cd-port" aria-label={`Connections per source for limit ${index + 1}`} value={row.max} placeholder="4" {...errorProps(`${prefix}.max_connections_per_source`)} onChange={(event) => patchRow({ max: event.target.value.trim() }, 'max_connections_per_source')} />
                        {fieldError(`${prefix}.max_connections_per_source`)}
                      </td>
                      <td className="cd-cell-action"><Button size="sm" variant="ghost" aria-label={`Remove connection limit ${index + 1}`} onClick={() => update({ connection_limits: draft.connection_limits.filter((_, position) => position !== index) }, ['connection_limits'])}><Trash2 size={14} aria-hidden="true" /></Button></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : <p className="cd-none">No connection limits declared.</p>}
        {fieldError('connection_limits')}
        <div className="cd-row-actions">
          <Button size="sm" variant="secondary" disabled={draft.connection_limits.length >= MAX_CONNECTION_LIMITS} onClick={() => update({ connection_limits: [...draft.connection_limits, emptyConnectionLimit()] })}><Plus size={14} aria-hidden="true" />Add limit</Button>
          <span className="cd-help">One limit per port, 1 to 10 connections per source.</span>
        </div>
      </>
    )),

    perspectives: section('perspectives', 'Probe perspectives', (
      <>{TERM_HELP.perspective} Mark the ones your firewall allows or denies so allowlists can be tested. Copy the egress addresses into your allowlist only if you intend AstraNull to reach the target from there.</>
    ), (
      <>
        {perspectivesError ? <p className="form-banner error" role="alert">{perspectivesError}</p> : null}
        {perspectives.length ? (
          <div className="cd-table-wrap" role="region" aria-label="Probe perspectives" tabIndex={0}>
            <table className="data-table cd-table cd-table-stack">
              <caption className="sr-only">Registered probe perspectives with their egress addresses and your declared allow or deny choice.</caption>
              <thead><tr><th scope="col">Perspective</th><th scope="col">Egress addresses</th><th scope="col">Allowed</th><th scope="col">Denied</th></tr></thead>
              <tbody>
                {perspectives.map((perspective) => (
                  <tr key={perspective.id}>
                    <th scope="row"><span className="cd-perspective"><b>{perspective.label}</b><small className="mono">{perspective.id}{perspective.region ? ` · ${perspective.region}` : ''}</small></span></th>
                    <td data-label="Egress addresses" className="cd-cell-wide">
                      {perspective.egressIps.length ? (
                        <span className="cd-ips">
                          <code>{perspective.egressIps.join(', ')}</code>
                          <Button size="sm" variant="ghost" aria-label={`Copy egress addresses for ${perspective.label}`} onClick={() => void copyIps(perspective)}><Copy size={14} aria-hidden="true" />Copy</Button>
                        </span>
                      ) : <span className="cd-none">Not published by your operator</span>}
                    </td>
                    <td data-label="Allowed" className="cd-cell-check"><input type="checkbox" disabled={readOnly || saving} aria-label={`${perspective.label} is allowed`} checked={allowSet.has(perspective.id)} onChange={(event) => update({ allowlisted_perspective_ids: event.target.checked ? [...draft.allowlisted_perspective_ids, perspective.id] : draft.allowlisted_perspective_ids.filter((id) => id !== perspective.id), denied_perspective_ids: event.target.checked ? draft.denied_perspective_ids.filter((id) => id !== perspective.id) : draft.denied_perspective_ids }, ['perspectives'])} /></td>
                    <td data-label="Denied" className="cd-cell-check"><input type="checkbox" disabled={readOnly || saving} aria-label={`${perspective.label} is denied`} checked={denySet.has(perspective.id)} onChange={(event) => update({ denied_perspective_ids: event.target.checked ? [...draft.denied_perspective_ids, perspective.id] : draft.denied_perspective_ids.filter((id) => id !== perspective.id), allowlisted_perspective_ids: event.target.checked ? draft.allowlisted_perspective_ids.filter((id) => id !== perspective.id) : draft.allowlisted_perspective_ids }, ['perspectives'])} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : !perspectivesError ? <p className="cd-none">No probe perspectives are registered for this workspace.</p> : null}
        {fieldError('perspectives.allowlisted_perspective_ids')}
        {fieldError('perspectives.denied_perspective_ids')}
        {perspectives.length < 2 && !perspectivesError ? <p className="cd-help">Testing an allowlist needs at least two perspectives; only {perspectives.length} {perspectives.length === 1 ? 'is' : 'are'} registered, so the multi-perspective check stays unavailable.</p> : null}
      </>
    ), { lock: false }),

    waf_signature: section('waf_signature', 'WAF block signature', (
      <>A response header your WAF adds only when it blocks, so those responses count as blocks instead of inconclusive. The value is stored but never shown in audit logs.</>
    ), (
      <div className="cd-grid">
        <div className="cd-field">
          <label htmlFor={fieldId('waf.block_signature.header_name')}>Header name</label>
          <input type="text" autoComplete="off" spellCheck={false} value={draft.block_header_name} placeholder="x-blocked-by" {...errorProps('waf.block_signature.header_name', `${baseId}-header-name-hint`)} onChange={(event) => update({ block_header_name: event.target.value }, ['waf.block_signature.header_name'])} />
          <small className="cd-help" id={`${baseId}-header-name-hint`}>Letters, digits and - only.</small>
          {fieldError('waf.block_signature.header_name')}
        </div>
        <div className="cd-field">
          <label htmlFor={fieldId('waf.block_signature.header_value')}>Header value</label>
          <input type="text" autoComplete="off" spellCheck={false} value={draft.block_header_value} placeholder="edge-waf" {...errorProps('waf.block_signature.header_value', `${baseId}-header-value-hint`)} onChange={(event) => update({ block_header_value: event.target.value }, ['waf.block_signature.header_value'])} />
          <small className="cd-help" id={`${baseId}-header-value-hint`}>Printable ASCII, up to {MAX_HEADER_VALUE} characters.</small>
          {fieldError('waf.block_signature.header_value')}
        </div>
        <div className="cd-field">
          <label htmlFor={fieldId('waf.block_signature.status_codes')}>Status codes <small>optional</small></label>
          <input type="text" autoComplete="off" inputMode="numeric" value={draft.block_status_codes} placeholder="403, 429" {...errorProps('waf.block_signature.status_codes', `${baseId}-codes-hint`)} onChange={(event) => update({ block_status_codes: event.target.value }, ['waf.block_signature.status_codes'])} />
          <small className="cd-help" id={`${baseId}-codes-hint`}>Comma-separated, 400–599. Leave empty to accept any error status with the header.</small>
          {fieldError('waf.block_signature.status_codes')}
        </div>
      </div>
    ), {
      more: {
        summary: 'Which WAFs need this',
        body: <p>Several WAFs answer a block with a page AstraNull cannot tell apart from an ordinary error: AWS ALB and API Gateway (a plain 403), Google Cloud Armor, Azure Front Door, Fastly, and any custom block page. Add a header on block in your WAF, then declare it here.</p>,
      },
    }),

    waf_action: section('waf_action', 'Expected WAF action', 'What your WAF should do with a request it decides to stop. A challenge (CAPTCHA or JavaScript check) can be solved by an attacker, so it never satisfies "Block".', (
      <div className="cd-choices cd-choices-grid" role="radiogroup" aria-label="Expected WAF action">
        {[{ value: '', label: 'Not declared', hint: 'Checks use their catalog default.' }, ...EXPECTED_WAF_ACTIONS].map((option) => (
          <label key={option.value || 'none'} className="cd-choice">
            <input type="radio" name={`${baseId}-action`} value={option.value} checked={draft.expected_action === option.value} onChange={() => update({ expected_action: option.value }, ['waf.expected_action'])} />
            <span><b>{option.label}</b><small>{option.hint}</small></span>
          </label>
        ))}
      </div>
    )),

    rate_limit: section('rate_limit', 'Rate-limit canary route', (
      <>{DECLARATION_KEYS['waf.rate_limit_canary'].unlocks} Configure a deliberately low limit on a route that does nothing; AstraNull sends at most 8 bounded GET or HEAD requests to it.</>
    ), (
      <>
        <div className="cd-toggle-row">
          <label className="cd-toggle">
            <input type="checkbox" checked={draft.rate_limit_enabled} aria-describedby={`${baseId}-rate-toggle-hint`} onChange={(event) => update({ rate_limit_enabled: event.target.checked }, ['waf.rate_limit_canary'])} />
            Declare a rate-limit canary route
          </label>
          <small className="cd-help" id={`${baseId}-rate-toggle-hint`}>{draft.rate_limit_enabled ? 'Clear this to remove the route on save.' : 'Turn on to describe the route and its limit.'}</small>
        </div>
        {draft.rate_limit_enabled ? (
          <div className="cd-reveal">
            <div className="cd-grid">
              <div className="cd-field">
                <label htmlFor={fieldId('waf.rate_limit_canary.path')}>Path</label>
                <input type="text" autoComplete="off" spellCheck={false} value={draft.rate_path} placeholder="/rl-canary" {...errorProps('waf.rate_limit_canary.path', `${baseId}-rate-path-hint`)} onChange={(event) => update({ rate_path: event.target.value.trim() }, ['waf.rate_limit_canary.path'])} />
                <small className="cd-help" id={`${baseId}-rate-path-hint`}>Starts with /, no query string.</small>
                {fieldError('waf.rate_limit_canary.path')}
              </div>
              <div className="cd-field">
                <label htmlFor={`${baseId}-rate-method`}>Method</label>
                <select id={`${baseId}-rate-method`} value={draft.rate_method} onChange={(event) => update({ rate_method: event.target.value }, ['waf.rate_limit_canary.method'])}><option value="GET">GET</option><option value="HEAD">HEAD</option></select>
              </div>
              <div className="cd-field">
                <label htmlFor={fieldId('waf.rate_limit_canary.threshold')}>Threshold (requests)</label>
                <input type="text" inputMode="numeric" autoComplete="off" value={draft.rate_threshold} placeholder="5" {...errorProps('waf.rate_limit_canary.threshold', `${baseId}-rate-threshold-hint`)} onChange={(event) => update({ rate_threshold: event.target.value.trim() }, ['waf.rate_limit_canary.threshold'])} />
                <small className="cd-help" id={`${baseId}-rate-threshold-hint`}>1 to 10 requests.</small>
                {fieldError('waf.rate_limit_canary.threshold')}
              </div>
              <div className="cd-field">
                <label htmlFor={fieldId('waf.rate_limit_canary.window_seconds')}>Window (seconds)</label>
                <input type="text" inputMode="numeric" autoComplete="off" value={draft.rate_window} placeholder="10" {...errorProps('waf.rate_limit_canary.window_seconds', `${baseId}-rate-window-hint`)} onChange={(event) => update({ rate_window: event.target.value.trim() }, ['waf.rate_limit_canary.window_seconds'])} />
                <small className="cd-help" id={`${baseId}-rate-window-hint`}>1 to 60 seconds.</small>
                {fieldError('waf.rate_limit_canary.window_seconds')}
              </div>
            </div>
            <fieldset className="cd-subset">
              <legend>When the limit is reached, the WAF should:</legend>
              <div className="cd-choices cd-choices-grid">
                {RATE_LIMIT_EXPECTED_ACTIONS.map((option) => {
                  const selected = (draft.rate_expected_action || 'block') === option.value;
                  return (
                    <label key={option.value} className="cd-choice">
                      <input type="radio" name={`${baseId}-rate-action`} value={option.value} checked={selected} {...(selected ? errorProps('waf.rate_limit_canary.expected_action') : {})} onChange={() => update({ rate_expected_action: option.value }, ['waf.rate_limit_canary.expected_action'])} />
                      <span><b>{option.label}</b><small>{option.hint}</small></span>
                    </label>
                  );
                })}
              </div>
              {fieldError('waf.rate_limit_canary.expected_action')}
            </fieldset>
          </div>
        ) : null}
      </>
    )),

    marker_paths: section('marker_paths', 'Extra marker paths', 'By default harmless WAF markers go to the root path. Add up to five other paths on this same host whose rules you want tested too, for example an API or login route.', (
      <>
        {draft.marker_paths.length ? (
          <ul className="cd-path-list">
            {draft.marker_paths.map((path, index) => (
              <li key={`path-${index}`}>
                <div className="cd-field">
                  <label className="sr-only" htmlFor={fieldId(`waf.marker_paths[${index}]`)}>Extra marker path {index + 1}</label>
                  <input type="text" autoComplete="off" spellCheck={false} value={path} placeholder="/api/search" {...errorProps(`waf.marker_paths[${index}]`)} onChange={(event) => update({ marker_paths: draft.marker_paths.map((entry, position) => position === index ? event.target.value.trim() : entry) }, [`waf.marker_paths[${index}]`])} />
                  {fieldError(`waf.marker_paths[${index}]`)}
                </div>
                <Button size="sm" variant="ghost" aria-label={`Remove extra marker path ${index + 1}`} onClick={() => update({ marker_paths: draft.marker_paths.filter((_, position) => position !== index) }, ['waf.marker_paths'])}><Trash2 size={14} aria-hidden="true" /></Button>
              </li>
            ))}
          </ul>
        ) : <p className="cd-none">Only the root path is tested.</p>}
        <div className="cd-row-actions">
          <Button size="sm" variant="secondary" disabled={draft.marker_paths.length >= MAX_MARKER_PATHS} onClick={() => update({ marker_paths: [...draft.marker_paths, ''] })}><Plus size={14} aria-hidden="true" />Add path</Button>
          <span className="cd-count tabular-nums">{draft.marker_paths.length} of {MAX_MARKER_PATHS} paths</span>
        </div>
      </>
    )),

    origin: section('origin', 'Origin lockdown', (
      <>Say your origin should only accept traffic from your CDN, so a direct answer is reported as an exposure. The origin-lockdown check needs <b>both</b> this declaration and one active origin relation that names the origin address; the relation lives under Origin relations on the Overview tab.</>
    ), (
      <>
        <div className="cd-choices cd-choices-grid" role="radiogroup" aria-label="Origin lockdown">
          {[
            { value: '', label: 'Not declared', hint: 'The origin-lockdown check waits for a declaration.' },
            { value: 'expected', label: 'Origin accepts only CDN traffic', hint: 'A direct answer from outside your CDN is reported as an exposure.' },
            { value: 'not_expected', label: 'Origin is reachable directly by design', hint: 'Direct answers are recorded, not reported.' },
          ].map((option) => (
            <label key={option.value || 'none'} className="cd-choice">
              <input type="radio" name={`${baseId}-origin`} value={option.value} checked={draft.origin_lockdown === option.value} onChange={() => update({ origin_lockdown: option.value as DeclarationsDraft['origin_lockdown'] }, ['origin'])} />
              <span><b>{option.label}</b><small>{option.hint}</small></span>
            </label>
          ))}
        </div>
        <OriginRelationStatus relations={originRelations} href={originRelationsHref} lockdown={draft.origin_lockdown === 'expected'} />
      </>
    )),

    canary_sink: section('canary_sink', 'Canary sink URL', (
      <>{DECLARATION_KEYS.canary_sink.unlocks} Only AstraNull SOC sends request bodies, only after approval, and only to this URL.</>
    ), (
      <div className="cd-field cd-field-wide">
        <label htmlFor={fieldId('canary_sink.url')}>URL</label>
        <input type="url" autoComplete="off" spellCheck={false} value={draft.canary_sink_url} placeholder="https://canary.example.com/astranull-sink" {...errorProps('canary_sink.url', `${baseId}-sink-hint`)} onChange={(event) => update({ canary_sink_url: event.target.value.trim() }, ['canary_sink.url'])} />
        <small className="cd-help" id={`${baseId}-sink-hint`}>Must be https and on {String(target.value ?? 'this target')} or one of its subdomains.</small>
        {fieldError('canary_sink.url')}
      </div>
    )),
  };

  return (
    <section className="cd" aria-labelledby={`${baseId}-title`} data-dirty={dirty || undefined}>
      {head(
        <div className="cd-head-state">
          {saveStateBadge}
          <p className="cd-meta">
            {summary.updatedAt ? <>Last saved <time dateTime={summary.updatedAt}>{formatDate(summary.updatedAt)}</time>{summary.updatedBy ? <> by <span className="mono">{summary.updatedBy}</span></> : null}</> : 'Never saved for this target.'}
          </p>
        </div>,
      )}

      {readOnly ? (
        <div className="cd-callout" data-tone="neutral" role="note">
          <Lock size={18} aria-hidden="true" className="cd-callout-icon" />
          <div className="cd-callout-body">
            <strong>Read-only access</strong>
            <p>Your role can read these declarations but cannot change them. You can still copy probe egress addresses.</p>
          </div>
        </div>
      ) : null}

      <div className="cd-layout">
        <div className="cd-overview">
          <div className="cd-progress-head">
            <h3 id={`${baseId}-overview`}>Declared so far</h3>
            <p className="cd-progress-label" id={`${baseId}-progress`}>
              <b className="tabular-nums">{declaredCount}</b> of <span className="tabular-nums">{sectionStates.length}</span> sections declared
            </p>
          </div>
          <div className="cd-progress" aria-hidden="true">
            {sectionStates.map((state) => <span key={state.id} className="cd-progress-seg" data-declared={state.declared || undefined} data-edited={state.edited || undefined} />)}
          </div>
          <p className="cd-help">Each declaration is optional. Declare only what matches controls you actually run; checks still need outside evidence.</p>
          <nav className="cd-nav" aria-labelledby={`${baseId}-overview`}>
            {DECLARATION_SECTION_GROUPS.map((group) => (
              <div key={group.id} className="cd-nav-group">
                <p className="cd-nav-group-label" id={`${baseId}-nav-${group.id}`}>{group.label}</p>
                <ul aria-labelledby={`${baseId}-nav-${group.id}`}>
                  {group.sections.map((id) => {
                    const state = stateById.get(id);
                    if (!state) return null;
                    return (
                      <li key={id}>
                        <a className="cd-nav-link" href={controlsHref(targetId, id)} aria-current={focusSection === id ? 'location' : undefined} onClick={(event) => jumpToSection(event, id)}>
                          <SectionStateIcon state={state} />
                          <span className="cd-nav-text">
                            <span className="cd-nav-label">{state.label}</span>
                            <small className="cd-nav-detail">
                              <span className="sr-only">{state.declared ? 'Declared: ' : 'Not declared: '}</span>
                              {state.detail}{state.edited ? ' · unsaved changes' : ''}
                            </small>
                          </span>
                        </a>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ))}
          </nav>
        </div>

        <div className="cd-main">
          {summary.empty ? (
            <div className="cd-callout" data-tone="neutral" role="note">
              <FileText size={18} aria-hidden="true" className="cd-callout-icon" />
              <div className="cd-callout-body">
                <strong>Nothing declared yet</strong>
                <p>Each declaration unlocks checks that cannot conclude without it:</p>
                <ul className="cd-unlocks">
                  <li><b>Network policy:</b> {DECLARATION_KEYS.network_policy.unlocks}</li>
                  <li><b>WAF block signature:</b> lets AstraNull recognise your block page, so blocks are graded as blocks instead of inconclusive.</li>
                  <li><b>Rate-limit canary:</b> {DECLARATION_KEYS['waf.rate_limit_canary'].unlocks}</li>
                  <li><b>Origin lockdown:</b> {DECLARATION_KEYS['origin.lockdown_expected'].unlocks}</li>
                  <li><b>Connection limits:</b> {DECLARATION_KEYS.connection_limits.unlocks}</li>
                  <li><b>Probe perspectives:</b> {DECLARATION_KEYS.perspectives.unlocks}</li>
                  <li><b>Canary sink:</b> {DECLARATION_KEYS.canary_sink.unlocks}</li>
                </ul>
              </div>
            </div>
          ) : null}

          {conflict ? (
            <div className="cd-conflict" role="alert" tabIndex={-1} ref={conflictRef} aria-labelledby={`${baseId}-conflict`}>
              <strong id={`${baseId}-conflict`}><GitCompareArrows size={16} aria-hidden="true" />{conflict.kind === 'conflict' ? 'Someone else saved these controls' : 'This save could not confirm which version you edited'}</strong>
              <p>
                {conflict.kind === 'conflict'
                  ? 'Review their version, then re-apply your changes. Your draft is kept here and nothing was overwritten.'
                  : 'Load the latest saved version, review it against your draft, then save again. Your draft is kept here and nothing was overwritten.'}
              </p>
              {conflict.status === 'ready' && conflict.latest ? (
                <div className="cd-conflict-review">
                  <p className="cd-meta">
                    Their version{declarationSummary(conflict.latest).updatedAt ? <> was saved <time dateTime={declarationSummary(conflict.latest).updatedAt}>{formatDate(declarationSummary(conflict.latest).updatedAt)}</time></> : null}
                    {declarationSummary(conflict.latest).updatedBy ? <> by <span className="mono">{declarationSummary(conflict.latest).updatedBy}</span></> : null}.
                  </p>
                  {conflict.diff.length ? (
                    <div className="cd-table-wrap" role="region" aria-label="Their saved version compared with your draft" tabIndex={0}>
                      <table className="data-table cd-table cd-diff">
                        <caption className="sr-only">Sections where their saved version and your draft differ.</caption>
                        <thead><tr><th scope="col">Section</th><th scope="col">Their saved version</th><th scope="col">Your draft</th></tr></thead>
                        <tbody>
                          {conflict.diff.map((row) => (
                            <tr key={row.section}><th scope="row">{row.label}</th><td data-label="Their saved version">{row.theirs}</td><td data-label="Your draft">{row.yours}</td></tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : <p className="cd-none">No section summary differs. Values such as a header value may still differ; review the form before saving.</p>}
                  <div className="cd-row-actions">
                    <Button size="sm" variant="secondary" onClick={keepDraftOnLatest}>Keep my draft and review</Button>
                    <Button size="sm" variant="ghost" onClick={useTheirVersion}>Use their version</Button>
                  </div>
                </div>
              ) : (
                <div className="cd-row-actions">
                  <Button size="sm" variant="secondary" loading={conflict.status === 'loading'} loadingText="Loading latest…" onClick={() => void loadLatest()}>Load latest</Button>
                  {conflict.status === 'error' ? <span className="cd-error" role="status">{conflict.error}</span> : null}
                </div>
              )}
            </div>
          ) : null}

          {showErrorSummary ? (
            <div className="cd-error-summary" role="alert" tabIndex={-1} ref={summaryRef} aria-labelledby={`${baseId}-errors`}>
              <strong id={`${baseId}-errors`}><TriangleAlert size={16} aria-hidden="true" />{errorEntries.length === 1 ? 'One value needs fixing before saving' : `${errorEntries.length} values need fixing before saving`}</strong>
              <ul>
                {errorEntries.map(([field, message]) => (
                  <li key={field}>
                    <a href={`#${fieldId(field)}`} onClick={(event) => { event.preventDefault(); document.getElementById(fieldId(field))?.focus(); }}>{fieldLabel(field)}</a>: {message}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}

          <form className="cd-form" noValidate onSubmit={(event) => { event.preventDefault(); void save(); }}>
            {DECLARATION_SECTION_GROUPS.map((group) => (
              <div key={group.id} className="cd-group" role="group" aria-labelledby={`${baseId}-group-${group.id}`}>
                <h3 className="cd-group-title" id={`${baseId}-group-${group.id}`}>{group.label}</h3>
                {group.sections.map((id) => <div key={id} className="cd-group-item">{sections[id]}</div>)}
              </div>
            ))}

            {saveError ? (
              <div className="cd-callout" data-tone="danger" role="alert">
                <TriangleAlert size={18} aria-hidden="true" className="cd-callout-icon" />
                <div className="cd-callout-body"><strong>Save failed</strong><p>{saveError}</p></div>
              </div>
            ) : null}
            {canWrite ? (
              <div className="cd-savebar" data-dirty={dirty || undefined} data-state={barState}>
                <div className="cd-savebar-copy">
                  <span className="cd-savebar-state">{barIcon}{barCopy}</span>
                  {status}
                </div>
                <div className="cd-savebar-actions">
                  <Button type="button" variant="ghost" disabled={!dirty || saving} onClick={discard}><RotateCcw size={14} aria-hidden="true" />Discard</Button>
                  <Button type="submit" loading={saving} loadingText="Saving…" disabled={!dirty || saving || Boolean(conflict)}>Save declarations</Button>
                </div>
              </div>
            ) : status}
          </form>
        </div>
      </div>
    </section>
  );
}
